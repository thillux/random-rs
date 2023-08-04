// Example custom build script.
fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed=src/random.c");

    println!("cargo:rustc-link-lib=dylib=jitterentropy");

    // native library dependencies
    pkg_config::Config::new().probe("libp11").unwrap();
    pkg_config::Config::new().probe("libcrypto").unwrap();
    pkg_config::Config::new().probe("gpgme").unwrap();

    // Use the `cc` crate to build a C file and statically link it.
    cc::Build::new().file("src/random.c").compile("random");
}
