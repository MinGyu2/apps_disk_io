use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=ebpf/file_io.bpf.c");

    let out_file =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set")).join("file_io.bpf.o");
    let source = "ebpf/file_io.bpf.c";
    let target = if env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() == Ok("big") {
        "bpfeb"
    } else {
        "bpfel"
    };

    let mut command = Command::new("clang");
    command.args([
        "-O2", "-g", "-target", target, "-Wall", "-Werror", "-c", source, "-o",
    ]);
    command.arg(&out_file);

    for include_dir in candidate_multiarch_include_dirs() {
        add_include_dir_if_exists(&mut command, include_dir);
    }

    match command.status() {
        Ok(status) if status.success() => {}
        Ok(status) => {
            println!(
                "cargo:warning=eBPF object compilation failed with {status}; --detail will use fallback mode"
            );
            fs::write(&out_file, []).expect("write empty fallback eBPF object");
        }
        Err(error) => {
            println!(
                "cargo:warning=clang is unavailable ({error}); --detail will use fallback mode"
            );
            fs::write(&out_file, []).expect("write empty fallback eBPF object");
        }
    }
}

fn candidate_multiarch_include_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Ok(host) = env::var("HOST") {
        dirs.push(PathBuf::from(format!("/usr/include/{host}")));
    }

    if let Some(triple) = linux_gnu_include_triple() {
        dirs.push(PathBuf::from(format!("/usr/include/{triple}")));
    }

    dirs
}

fn linux_gnu_include_triple() -> Option<&'static str> {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").ok()?;

    match arch.as_str() {
        "x86_64" => Some("x86_64-linux-gnu"),
        "aarch64" => Some("aarch64-linux-gnu"),
        "arm" => Some("arm-linux-gnueabihf"),
        "riscv64" => Some("riscv64-linux-gnu"),
        "s390x" => Some("s390x-linux-gnu"),
        "powerpc64" => {
            if env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() == Ok("little") {
                Some("powerpc64le-linux-gnu")
            } else {
                Some("powerpc64-linux-gnu")
            }
        }
        _ => None,
    }
}

fn add_include_dir_if_exists(command: &mut Command, path: impl AsRef<Path>) {
    let path = path.as_ref();

    if path.is_dir() {
        command.arg(format!("-I{}", path.display()));
    }
}
