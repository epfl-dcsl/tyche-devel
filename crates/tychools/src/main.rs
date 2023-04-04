mod allocator;
mod debug;
mod instrument;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use debug::{print_elf_segments, print_page_tables};
use instrument::dump_page_tables;
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
    DumpPageTables(DumpPageTablesArgs),
    PrintPageTables(FileArg),
}

#[derive(Args)]
struct FileArg {
    #[arg(short, long, value_name = "FILE")]
    path: PathBuf,
}

#[derive(Args)]
struct DumpPageTablesArgs {
    #[arg(short, long, value_name = "SRC")]
    src: PathBuf,
    #[arg(short, long, value_name = "DST")]
    dst: PathBuf,
}

fn main() {
    simple_logger::init().unwrap();
    let cli = Cli::parse();
    match &cli.command {
        Commands::PrintELFSegments(args) => {
            print_elf_segments(&args.path);
        }
        Commands::DumpPageTables(args) => {
            dump_page_tables(&args.src, &args.dst);
        }
        Commands::PrintPageTables(args) => {
            print_page_tables(&args.path);
        }
    }
}
