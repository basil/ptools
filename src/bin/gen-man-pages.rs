use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "pargs.rs"]
mod pargs;
#[allow(dead_code)]
#[path = "penv.rs"]
mod penv;
#[allow(dead_code)]
#[path = "pfiles.rs"]
mod pfiles;
#[allow(dead_code)]
#[path = "ptree.rs"]
mod ptree;

fn render_man_page(cmd: clap::Command, out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let name = cmd.get_name().to_string();
    let path = out_dir.join(format!("{name}.1"));
    let mut file = fs::File::create(&path)?;
    clap_mangen::Man::new(cmd).render(&mut file)?;
    println!("wrote {}", path.display());
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/man"));

    fs::create_dir_all(&out_dir)?;
    for entry in fs::read_dir(&out_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "1") {
            fs::remove_file(path)?;
        }
    }

    render_man_page(pargs::build_cli(), &out_dir)?;
    render_man_page(penv::build_cli(), &out_dir)?;
    render_man_page(pfiles::build_cli(), &out_dir)?;
    render_man_page(ptree::build_cli(), &out_dir)?;

    Ok(())
}
