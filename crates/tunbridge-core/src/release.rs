//! Where TunBridge releases are published. The updater and the core-update
//! fetchers accept GitHub paths only under this repository; moving the
//! repository again means changing this file and the release scripts.

/// GitHub `owner/name` of the public repository.
pub const RELEASE_REPOSITORY: &str = "jacksonlin-infra/tunbridge";
/// Every release asset path on github.com starts with this prefix.
pub const RELEASE_ASSET_PATH_PREFIX: &str = "/jacksonlin-infra/tunbridge/releases/";
/// Path of the update manifest attached to the latest release.
pub const UPDATE_MANIFEST_PATH: &str =
    "/jacksonlin-infra/tunbridge/releases/latest/download/tunbridge-update.json";
/// Page opened when the user asks to see the latest release.
pub const RELEASES_URL: &str = "https://github.com/jacksonlin-infra/tunbridge/releases/latest";
/// Prefix every package URL in the update manifest must use.
pub const RELEASE_DOWNLOAD_PREFIX: &str =
    "https://github.com/jacksonlin-infra/tunbridge/releases/download/";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_locations_share_one_repository() {
        let prefix = format!("/{RELEASE_REPOSITORY}/releases/");
        assert_eq!(RELEASE_ASSET_PATH_PREFIX, prefix);
        assert!(UPDATE_MANIFEST_PATH.starts_with(&prefix));
        assert_eq!(RELEASES_URL, format!("https://github.com{prefix}latest"));
        assert_eq!(
            RELEASE_DOWNLOAD_PREFIX,
            format!("https://github.com{prefix}download/")
        );
    }
}
