use std::env;
use std::path::{Path, PathBuf};

const APPLICATION_SUPPORT_DIRECTORY: &str = "Library/Application Support";
const PRODUCT_DIRECTORY: &str = "com.tunbridge.desktop";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    MissingHome,
    RelativeHome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosUserPaths {
    application_support_root: PathBuf,
}

impl MacosUserPaths {
    pub fn from_environment() -> Result<Self, PathError> {
        Self::resolve(env::var_os("HOME").as_deref().map(Path::new))
    }

    pub fn resolve(home: Option<&Path>) -> Result<Self, PathError> {
        let home = home.ok_or(PathError::MissingHome)?;
        if !home.is_absolute() {
            return Err(PathError::RelativeHome);
        }
        Ok(Self {
            application_support_root: home
                .join(APPLICATION_SUPPORT_DIRECTORY)
                .join(PRODUCT_DIRECTORY),
        })
    }

    pub fn application_support_root(&self) -> &Path {
        &self.application_support_root
    }

    pub fn profile_root(&self) -> PathBuf {
        self.application_support_root.join("desktop")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_application_support_profile_root() {
        let paths = MacosUserPaths::resolve(Some(Path::new("/Users/alice"))).unwrap();
        assert_eq!(
            paths.application_support_root(),
            Path::new("/Users/alice/Library/Application Support/com.tunbridge.desktop")
        );
        assert_eq!(
            paths.profile_root(),
            Path::new("/Users/alice/Library/Application Support/com.tunbridge.desktop/desktop")
        );
    }

    #[test]
    fn missing_or_relative_home_fails_closed() {
        assert_eq!(MacosUserPaths::resolve(None), Err(PathError::MissingHome));
        assert_eq!(
            MacosUserPaths::resolve(Some(Path::new("Users/alice"))),
            Err(PathError::RelativeHome)
        );
    }
}
