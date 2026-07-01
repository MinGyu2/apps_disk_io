use std::env;
use std::fs;
use std::path::PathBuf;
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

    if let Ok(host) = env::var("HOST") {
        let multiarch_include = PathBuf::from(format!("/usr/include/{host}"));
        if multiarch_include.is_dir() {
            command.arg(format!("-I{}", multiarch_include.display()));
        }
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
