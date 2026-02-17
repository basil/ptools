use nix::fcntl::{open, OFlag};
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};
use nix::sys::eventfd::{EfdFlags, EventFd};
use nix::sys::stat::Mode;
use nix::unistd::pipe2;
use std::env;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsFd, RawFd};
use std::os::unix::fs::{symlink, FileTypeExt};
use std::thread;
use std::time::Duration;

fn open_signalfd() -> RawFd {
    unsafe {
        let mut mask = std::mem::zeroed::<nix::libc::sigset_t>();
        if nix::libc::sigemptyset(&mut mask) != 0 {
            panic!("sigemptyset failed: {}", std::io::Error::last_os_error());
        }
        if nix::libc::sigaddset(&mut mask, nix::libc::SIGUSR1) != 0 {
            panic!("sigaddset failed: {}", std::io::Error::last_os_error());
        }
        if nix::libc::sigprocmask(nix::libc::SIG_BLOCK, &mask, std::ptr::null_mut()) != 0 {
            panic!("sigprocmask failed: {}", std::io::Error::last_os_error());
        }

        let fd = nix::libc::signalfd(-1, &mask, nix::libc::SFD_CLOEXEC | nix::libc::SFD_NONBLOCK);
        if fd < 0 {
            panic!("signalfd failed: {}", std::io::Error::last_os_error());
        }
        fd
    }
}

fn open_timerfd() -> RawFd {
    unsafe {
        let fd = nix::libc::timerfd_create(
            nix::libc::CLOCK_MONOTONIC,
            nix::libc::TFD_CLOEXEC | nix::libc::TFD_NONBLOCK,
        );
        if fd < 0 {
            panic!("timerfd_create failed: {}", std::io::Error::last_os_error());
        }

        let mut spec = std::mem::zeroed::<nix::libc::itimerspec>();
        spec.it_value.tv_sec = 5;
        if nix::libc::timerfd_settime(fd, 0, &spec, std::ptr::null_mut()) != 0 {
            panic!(
                "timerfd_settime failed: {}",
                std::io::Error::last_os_error()
            );
        }

        fd
    }
}

fn open_inotify() -> RawFd {
    unsafe {
        let fd = nix::libc::inotify_init1(nix::libc::IN_CLOEXEC | nix::libc::IN_NONBLOCK);
        if fd < 0 {
            panic!("inotify_init1 failed: {}", std::io::Error::last_os_error());
        }
        fd
    }
}

fn find_block_device_path() -> Option<String> {
    fs::read_dir("/dev").ok()?.flatten().find_map(|entry| {
        let path = entry.path();
        let metadata = fs::metadata(&path).ok()?;
        if metadata.file_type().is_block_device() {
            Some(path.to_string_lossy().to_string())
        } else {
            None
        }
    })
}

#[cfg(target_os = "linux")]
fn allow_ptrace_for_tests() {
    unsafe {
        nix::libc::prctl(
            nix::libc::PR_SET_PTRACER,
            nix::libc::PR_SET_PTRACER_ANY,
            0,
            0,
            0,
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn allow_ptrace_for_tests() {}

fn main() {
    allow_ptrace_for_tests();

    let signal_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");
    let tmp_file_path =
        env::var("PTOOLS_MATRIX_FILE_PATH").expect("PTOOLS_MATRIX_FILE_PATH must be set");
    let symlink_path =
        env::var("PTOOLS_MATRIX_LINK_PATH").expect("PTOOLS_MATRIX_LINK_PATH must be set");
    let mut tmp_file = File::create(&tmp_file_path).unwrap();
    writeln!(tmp_file, "ptools").unwrap();
    tmp_file.seek(SeekFrom::Start(3)).unwrap();

    let _ = fs::remove_file(&symlink_path);
    symlink(&tmp_file_path, &symlink_path).unwrap();
    let symlink_fd = open(
        &*symlink_path,
        OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .unwrap();

    let block_device = find_block_device_path().and_then(|path| {
        open(&*path, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())
            .ok()
            .map(|fd| (fd, path))
    });

    let dirfd = open(".", OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty()).unwrap();
    let (pipe_read, pipe_write) = pipe2(OFlag::O_CLOEXEC).unwrap();

    let epoll = Epoll::new(EpollCreateFlags::empty()).unwrap();
    let eventfd = EventFd::from_value_and_flags(0, EfdFlags::EFD_NONBLOCK).unwrap();
    let event = EpollEvent::new(EpollFlags::EPOLLIN, 0);
    epoll.add(eventfd.as_fd(), event).unwrap();
    let signalfd = open_signalfd();
    let timerfd = open_timerfd();
    let inotify_fd = open_inotify();
    unsafe {
        let watch_path = CString::new("/tmp").unwrap();
        if nix::libc::inotify_add_watch(inotify_fd, watch_path.as_ptr(), nix::libc::IN_CREATE) < 0 {
            panic!(
                "inotify_add_watch failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    let unix_socket_path = format!("{}.sock", tmp_file_path);
    let _ = std::fs::remove_file(&unix_socket_path);
    let unix_listener = std::os::unix::net::UnixListener::bind(&unix_socket_path).unwrap();
    let _unix_client = std::os::unix::net::UnixStream::connect(&unix_socket_path).unwrap();
    let (_unix_server_conn, _unix_addr) = unix_listener.accept().unwrap();

    let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    let _tcp_client = TcpStream::connect(tcp_addr).unwrap();
    let (_tcp_server_conn, _peer) = tcp_listener.accept().unwrap();

    let tcp6_listener = TcpListener::bind("[::1]:0").unwrap();
    let tcp6_addr = tcp6_listener.local_addr().unwrap();
    let _tcp6_client = TcpStream::connect(tcp6_addr).unwrap();
    let (_tcp6_server_conn, _peer6) = tcp6_listener.accept().unwrap();

    let _udp_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let _udp6_socket = UdpSocket::bind("[::1]:0").unwrap();

    // Signal parent process (the test process) that this process is ready to be observed by the
    // ptool being tested.
    File::create(signal_path).unwrap();

    // Keep all descriptors alive until killed by test harness.
    let _keep_alive = (
        tmp_file,
        symlink_fd,
        block_device,
        dirfd,
        pipe_read,
        pipe_write,
        epoll,
        eventfd,
        signalfd,
        timerfd,
        inotify_fd,
        unix_listener,
        tcp_listener,
        tcp6_listener,
    );

    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
