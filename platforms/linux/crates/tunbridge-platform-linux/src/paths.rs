use std::env;
use std::path::{Path, PathBuf};

const PRODUCT_DIRECTORY: &str = "tunbridge";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    MissingHome,
    RelativeHome,
    RelativeXdgDirectory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxUserPaths {
    data_root: PathBuf,
    config_root: PathBuf,
    cache_root: PathBuf,
}

impl LinuxUserPaths {
    pub fn from_environment() -> Result<Self, PathError> {
        Self::resolve(
            env::var_os("HOME").as_deref().map(Path::new),
            env::var_os("XDG_DATA_HOME").as_deref().map(Path::new),
            env::var_os("XDG_CONFIG_HOME").as_deref().map(Path::new),
            env::var_os("XDG_CACHE_HOME").as_deref().map(Path::new),
        )
    }

    pub fn resolve(
        home: Option<&Path>,
        data_home: Option<&Path>,
        config_home: Option<&Path>,
        cache_home: Option<&Path>,
    ) -> Result<Self, PathError> {
        let home = home.ok_or(PathError::MissingHome)?;
        if !home.is_absolute() {
            return Err(PathError::RelativeHome);
        }

        Ok(Self {
            data_root: xdg_root(home, data_home, ".local/share")?.join(PRODUCT_DIRECTORY),
            config_root: xdg_root(home, config_home, ".config")?.join(PRODUCT_DIRECTORY),
            cache_root: xdg_root(home, cache_home, ".cache")?.join(PRODUCT_DIRECTORY),
        })
    }

    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    pub fn config_root(&self) -> &Path {
        &self.config_root
    }

    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    pub fn profile_root(&self) -> PathBuf {
        self.data_root.join("desktop")
    }
}

fn xdg_root(home: &Path, configured: Option<&Path>, fallback: &str) -> Result<PathBuf, PathError> {
    match configured {
        Some(path) if path.is_absolute() => Ok(path.to_owned()),
        Some(_) => Err(PathError::RelativeXdgDirectory),
        None => Ok(home.join(fallback)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_xdg_directories_are_used_verbatim() {
        let paths = LinuxUserPaths::resolve(
            Some(Path::new("/home/alice")),
            Some(Path::new("/srv/alice/data")),
            Some(Path::new("/srv/alice/config")),
            Some(Path::new("/srv/alice/cache")),
        )
        .unwrap();

        assert_eq!(paths.data_root(), Path::new("/srv/alice/data/tunbridge"));
        assert_eq!(
            paths.config_root(),
            Path::new("/srv/alice/config/tunbridge")
        );
        assert_eq!(paths.cache_root(), Path::new("/srv/alice/cache/tunbridge"));
        assert_eq!(
            paths.profile_root(),
            Path::new("/srv/alice/data/tunbridge/desktop")
        );
    }

    #[test]
    fn missing_xdg_directories_use_spec_fallbacks() {
        let paths =
            LinuxUserPaths::resolve(Some(Path::new("/home/alice")), None, None, None).unwrap();

        assert_eq!(
            paths.data_root(),
            Path::new("/home/alice/.local/share/tunbridge")
        );
        assert_eq!(
            paths.config_root(),
            Path::new("/home/alice/.config/tunbridge")
        );
        assert_eq!(
            paths.cache_root(),
            Path::new("/home/alice/.cache/tunbridge")
        );
    }

    #[test]
    fn relative_home_and_xdg_values_fail_closed() {
        assert_eq!(
            LinuxUserPaths::resolve(Some(Path::new("home/alice")), None, None, None),
            Err(PathError::RelativeHome)
        );
        assert_eq!(
            LinuxUserPaths::resolve(
                Some(Path::new("/home/alice")),
                Some(Path::new("data")),
                None,
                None
            ),
            Err(PathError::RelativeXdgDirectory)
        );
    }
}
