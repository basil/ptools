use std::fs;
use std::path::Path;

mod cli {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cli.rs"));
}

fn render_man_page(cmd: clap::Command, out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let name = cmd.get_name().to_string();
    let path = out_dir.join(format!("{name}.1"));
    let mut file = fs::File::create(&path)?;
    clap_mangen::Man::new(cmd).render(&mut file)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use clap::CommandFactory;

    let out_dir = Path::new("target/man");

    fs::create_dir_all(out_dir)?;

    render_man_page(cli::PargsCli::command(), out_dir)?;
    render_man_page(cli::PenvCli::command(), out_dir)?;
    render_man_page(cli::PfilesCli::command(), out_dir)?;
    render_man_page(cli::PflagsCli::command(), out_dir)?;
    render_man_page(cli::PsigCli::command(), out_dir)?;
    render_man_page(cli::PtreeCli::command(), out_dir)?;

    println!("cargo:rerun-if-changed=src/cli.rs");

    Ok(())
}
