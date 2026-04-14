fn main() {
    // If the SP1 ELF env var is already set (e.g. by sp1_build), use it.
    if std::env::var("SP1_ELF_zkdcap-sp1-guest").is_ok() {
        return;
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    // 1. Check for freshly-built ELF (from `cargo prove build`)
    let built_path = format!(
        "{manifest_dir}/../sp1-guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zkdcap-sp1-guest"
    );

    // 2. Check for checked-in ELF
    let checked_in_path = format!("{manifest_dir}/../elf/zkdcap-sp1-guest");

    let elf_path = if std::path::Path::new(&built_path).exists() {
        built_path
    } else if std::path::Path::new(&checked_in_path).exists() {
        checked_in_path
    } else {
        panic!(
            "SP1 guest ELF not found.\n\
             Looked in:\n  {built_path}\n  {checked_in_path}\n\
             Build it: cd sp1-guest && cargo prove build"
        );
    };

    println!("cargo:rustc-env=SP1_ELF_zkdcap-sp1-guest={elf_path}");
}
