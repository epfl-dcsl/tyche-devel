mod allocator;
mod debug;
mod instrument;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use debug::print_elf_segments;
use instrument::instrument;
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
    Instrument(InstrumentArgs),
}

#[derive(Args)]
struct FileArg {
    #[arg(short, long, value_name = "FILE")]
    path: PathBuf,
}

#[derive(Args)]
struct InstrumentArgs {
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
        Commands::Instrument(args) => {
            instrument(&args.src, &args.dst);
        }
    }
}
