use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::Duration;

// ————————————————————————————— QEMU Arguments ————————————————————————————— //

#[rustfmt::skip]
const RUN_ARGS: &[&str] = &[
    "--no-reboot",
    "-nographic",
    "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
    "-device", "intel-iommu,intremap=on,aw-bits=48",
    "-cpu", "host,+kvm",
    "-machine", "q35",
    "-accel", "kvm,kernel-irqchip=split",
    "-m", "14G",
   "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22",
   "-device", "e1000,netdev=net0",

];
const TEST_ARGS: &[&str] = &[
    "--no-reboot",
    "-device",
    "isa-debug-exit,iobase=0xf4,iosize=0x04",
    "-serial",
    "stdio",
    "-display",
    "none",
    "-cpu",
    "host,+kvm",
    "-enable-kvm",
];
const TEST_TIMEOUT_SECS: u64 = 10;
const QCOW2_CANDIDATES: &[&'static str] = &["nested.raw", "ubuntu.qcow2"];

// —————————————————————————————— CLI Parsing ——————————————————————————————— //

struct Args {
    no_boot: bool,
    uefi: bool,
    stop: bool,
    smp: usize,
    dbg: Option<String>,
    tpm: Option<String>,
    kernel_binary_path: PathBuf,
}

fn parse_args(args: &mut Vec<String>) -> Args {
    // Default values
    let mut no_boot = false;
    let mut uefi = false;
    let mut stop = false;
    let mut smp = 1;
    let mut tpm = None;
    let mut dbg = None;

    // Parse arguments
    let kernel_binary_path = PathBuf::from(args.remove(0)).canonicalize().unwrap();
    if flax_exists("--no-run", args) {
        no_boot = true;
    }
    if flax_exists("--uefi", args) {
        uefi = true;
    }
    if flax_exists("--stop", args) {
        stop = true;
    }
    if let Some(idx) = args.iter().position(|arg| arg.starts_with("--smp=")) {
        let value = args[idx]
            .strip_prefix("--smp=")
            .expect("Error parsing 'smp'")
            .parse::<usize>()
            .unwrap();
        args.remove(idx);
        smp = value;
    };
    if let Some(idx) = args.iter().position(|arg| arg.starts_with("--tpm=")) {
        let value = args[idx]
            .strip_prefix("--tpm=")
            .expect("Error parsing 'tpm'")
            .to_string();
        args.remove(idx);
        tpm = Some(value);
    };
    if let Some(idx) = args.iter().position(|arg| arg.starts_with("--dbg_path=")) {
        let mut value: String = args[idx]
            .strip_prefix("--dbg_path=")
            .expect("Error parsing 'dbg_path'")
            .to_string();
        args.remove(idx);
        if value.len() == 0 {
            value = String::from("/tmp/dbg0");
        }
        dbg = Some(value);
    };

    Args {
        no_boot,
        uefi,
        stop,
        smp,
        dbg,
        tpm,
        kernel_binary_path,
    }
}

/// Returns true if the flag exists in the command line. The flag is then removed if present.
fn flax_exists(flag: &str, args: &mut Vec<String>) -> bool {
    if let Some(idx) = args.iter().position(|arg| arg == flag) {
        args.remove(idx);
        true
    } else {
        false
    }
}

// —————————————————————————————— Entry Point ——————————————————————————————— //

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect(); // skip executable name
    let config = parse_args(&mut args);

    let image = create_disk_images(&config.kernel_binary_path, config.uefi);

    if config.no_boot {
        println!("Created disk image at `{}`", image.display());
        return;
    }

    let mut run_cmd = Command::new("qemu-system-x86_64");
    run_cmd.arg("-smp").arg(format!("{}", config.smp));

    run_cmd
        .arg("-drive")
        .arg(format!("format=raw,file={}", image.display()));

    if config.uefi {
        run_cmd.arg("-bios").arg("OVMF-pure-efi.fd");
    }

    if config.stop {
        run_cmd.arg("-S");
    }

    let binary_kind = runner_utils::binary_kind(&config.kernel_binary_path);
    if binary_kind.is_test() {
        run_cmd.args(TEST_ARGS);

        let exit_status = run_test_command(run_cmd);
        match exit_status.code() {
            Some(33) => (), // success
            other => panic!("Test failed (exit code: {:?})", other),
        }
    } else {
        run_cmd.args(RUN_ARGS);
        run_cmd.args(&args);

        // GDB path
        if let Some(dbg) = config.dbg {
            run_cmd
                .arg("-chardev")
                .arg(format!("socket,path={},server=on,wait=off,id=dbg0", dbg))
                .arg("-gdb")
                .arg("chardev:dbg0");
        }

        // TPM device
        if let Some(tpm) = config.tpm {
            run_cmd.args([
                "-device",
                "tpm-tis,tpmdev=tpm0",
                "-tpmdev",
                "emulator,id=tpm0,chardev=tpm-chardev",
                "-chardev",
            ]);
            run_cmd.arg(&format!("socket,id=tpm-chardev,path={}/sock", tpm));
        }

        // Disk image
        if let Some(qcow2) = find_qcow2() {
            run_cmd
                .arg("-drive")
                .arg(format!("file={},format=qcow2,media=disk", qcow2));
        }
        println!(
            "Running:\n{} {}",
            run_cmd.get_program().to_str().unwrap(),
            run_cmd
                .get_args()
                .map(|cmd| cmd.to_str().unwrap().to_owned())
                .fold(String::new(), |mut acc, cmd| {
                    acc.push_str(" ");
                    acc.push_str(&cmd);
                    acc
                })
        );

        let exit_status = run_cmd.status().unwrap();
        if !exit_status.success() {
            std::process::exit(exit_status.code().unwrap_or(1));
        }
    }
}

fn run_test_command(mut cmd: Command) -> ExitStatus {
    runner_utils::run_with_timeout(&mut cmd, Duration::from_secs(TEST_TIMEOUT_SECS)).unwrap()
}

fn create_disk_images(kernel_binary_path: &Path, uefi: bool) -> PathBuf {
    let bootloader_manifest_path = bootloader_locator::locate_bootloader("bootloader").unwrap();
    let kernel_manifest_path = locate_cargo_manifest::locate_manifest().unwrap();

    let mut build_cmd = Command::new(env!("CARGO"));
    build_cmd.current_dir(bootloader_manifest_path.parent().unwrap());
    build_cmd.arg("builder");
    build_cmd
        .arg("--kernel-manifest")
        .arg(&kernel_manifest_path);
    build_cmd.arg("--kernel-binary").arg(&kernel_binary_path);
    build_cmd
        .arg("--target-dir")
        .arg(kernel_manifest_path.parent().unwrap().join("target"));
    build_cmd
        .arg("--out-dir")
        .arg(kernel_binary_path.parent().unwrap());
    build_cmd.arg("--quiet");

    if !build_cmd.status().unwrap().success() {
        panic!("build failed");
    }

    let kernel_binary_name = kernel_binary_path.file_name().unwrap().to_str().unwrap();
    let disk_image = kernel_binary_path.parent().unwrap().join(format!(
        "boot-{}-{}.img",
        if uefi { "uefi" } else { "bios" },
        kernel_binary_name
    ));
    if !disk_image.exists() {
        panic!(
            "Disk image does not exist at {} after bootloader build",
            disk_image.display()
        );
    }
    disk_image
}

fn find_qcow2() -> Option<&'static str> {
    for candidate in QCOW2_CANDIDATES {
        if Path::new(candidate).exists() {
            return Some(candidate);
        }
    }
    return None;
}
