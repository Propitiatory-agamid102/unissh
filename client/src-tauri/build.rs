fn main() {
    tauri_build::build();

    // `native_keychain`: a real OS keychain backend is available on every target
    // except Android (which has no `keyring` v3 backend yet). Desktop
    // (macOS/Windows/Linux) and iOS use the `keyring` crate; Android falls back to
    // the no-op stubs until a Keystore-backed plugin lands. Gating on this alias
    // (instead of `desktop`) is what brings iOS onto the keychain path.
    println!("cargo::rustc-check-cfg=cfg(native_keychain)");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if matches!(target_os.as_str(), "macos" | "windows" | "linux" | "ios") {
        println!("cargo::rustc-cfg=native_keychain");
    }
}
