fn main() {
    println!("cargo:rerun-if-changed=windows/tunbridge-setup.rc");
    println!("cargo:rerun-if-changed=windows/tunbridge-setup.manifest");

    #[cfg(windows)]
    embed_resource::compile("windows/tunbridge-setup.rc", embed_resource::NONE)
        .manifest_required()
        .unwrap();
}
