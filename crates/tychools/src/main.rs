mod allocator;
mod debug;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use debug::{print_elf_segments, print_page_tables};
use simple_logger;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    PrintELFSegments(FileArg),
    BuildPageTables(FileArg),
}

#[derive(Args)]
struct FileArg {
    #[arg(short, long, value_name = "FILE")]
    path: PathBuf,
}

fn main() {
    simple_logger::init().unwrap();
    let cli = Cli::parse();
    match &cli.command {
        Commands::PrintELFSegments(args) => {
            print_elf_segments(&args.path);
        }
        Commands::BuildPageTables(args) => {
            print_page_tables(&args.path);
        }
    }
}
