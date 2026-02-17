use nix::fcntl::{open, OFlag};
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};
use nix::sys::eventfd::{EfdFlags, EventFd};
use nix::sys::stat::Mode;
use nix::unistd::pipe2;
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsFd;
use std::os::unix::fs::{symlink, FileTypeExt};
use std::thread;
use std::time::Duration;

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

fn main() {
    let tmp_file_path = "/tmp/ptools-pfiles-matrix-file";
    let mut tmp_file = File::create(tmp_file_path).unwrap();
    writeln!(tmp_file, "ptools").unwrap();
    tmp_file.seek(SeekFrom::Start(3)).unwrap();

    let symlink_path = "/tmp/ptools-pfiles-matrix-link";
    let _ = fs::remove_file(symlink_path);
    symlink(tmp_file_path, symlink_path).unwrap();
    let symlink_fd = open(
        symlink_path,
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

    let _ = std::fs::remove_file("/tmp/ptools-pfiles-matrix.sock");
    let unix_listener =
        std::os::unix::net::UnixListener::bind("/tmp/ptools-pfiles-matrix.sock").unwrap();
    let _unix_client =
        std::os::unix::net::UnixStream::connect("/tmp/ptools-pfiles-matrix.sock").unwrap();
    let (_unix_server_conn, _unix_addr) = unix_listener.accept().unwrap();

    let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    let _tcp_client = TcpStream::connect(tcp_addr).unwrap();
    let (_tcp_server_conn, _peer) = tcp_listener.accept().unwrap();

    let _udp_socket = UdpSocket::bind("127.0.0.1:0").unwrap();

    // Signal parent process (the test process) that this process is ready to be observed by the
    // ptool being tested.
    File::create("/tmp/ptools-test-ready").unwrap();

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
        unix_listener,
        tcp_listener,
    );

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
