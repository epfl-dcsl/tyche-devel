mod allocator;
mod attestation;
mod elf_modifier;
mod instrument;
mod loader;
mod page_table_mapper;
mod tychools_const;

use std::path::PathBuf;

use attestation::{attest, attestation_check};
use clap::{Args, Parser, Subcommand};
use clap_num::maybe_hex;
use instrument::{instrument_with_manifest, modify_binary, print_enum};
use loader::{extract_bin, parse_and_run};
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
    Run(FilePath),
    PrintEnum,
    Hash(FileAndOffset),
    Extract(SrcDestArgs),
    Attestation(AttestationArgs),
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

#[derive(Args)]
struct FileAndOffset {
    #[arg(short, long, value_name = "SRC")]
    src: PathBuf,
    #[arg(short, long, value_name = "OFFSET", value_parser=maybe_hex::<u64>)]
    offset: u64,
}

#[derive(Args)]
struct AttestationArgs {
    #[arg(short, long, value_name = "ATT_SRC")]
    att_src: PathBuf,
    #[arg(short, long, value_name = "SRC_BIN")]
    src_bin: PathBuf,
    #[arg(short, long, value_name = "OFFSET", value_parser=maybe_hex::<u64>)]
    offset: u64,
    #[arg(short, long, value_name = "NONCE", value_parser=maybe_hex::<u64>)]
    nonce: u64,
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
        Commands::Run(args) => {
            parse_and_run(&args.src);
        }
        Commands::PrintEnum => {
            print_enum();
        }
        Commands::Hash(args) => {
            attest(&args.src, args.offset);
        }
        Commands::Extract(args) => {
            extract_bin(&args.src, &args.dst);
        }
        Commands::Attestation(args) => {
            attestation_check(&args.src_bin, &args.att_src, args.offset, args.nonce);
        }
    }
}
