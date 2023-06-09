mod allocator;
mod elf_modifier;
mod instrument;
mod loader;
mod page_table_mapper;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use instrument::{instrument_with_manifest, modify_binary, print_enum};
use page_table_mapper::print_page_tables;
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
    TychefyBinary(SrcDestArgs),
    Instrument(FilePath),
    PrintPts(FilePath),
    PrintEnum,
}

#[derive(Args)]
struct SrcDestArgs {
    #[arg(short, long, value_name = "SRC")]
    src: PathBuf,
    #[arg(short, long, value_name = "DST")]
    dst: PathBuf,
}

#[derive(Args)]
struct FilePath {
    #[arg(short, long, value_name = "SRC")]
    src: PathBuf,
}

fn main() {
    simple_logger::init().unwrap();
    let cli = Cli::parse();
    match &cli.command {
        Commands::TychefyBinary(args) => {
            modify_binary(&args.src, &args.dst);
        }
        Commands::Instrument(manifest) => {
            instrument_with_manifest(&manifest.src);
        }
        Commands::PrintPts(args) => {
            print_page_tables(&args.src);
        }
        Commands::PrintEnum => {
            print_enum();
        }
    }
}
