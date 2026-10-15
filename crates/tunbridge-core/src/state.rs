use crate::platform::model::NetSnapshot;
use crate::{CoreError, Result};
use std::path::PathBuf;

pub struct StatePaths {
    pub root: PathBuf,
}

impl StatePaths {
    pub fn resolve() -> Self {
        let root = std::env::var("LOCALAPPDATA")
            .map(|p| PathBuf::from(p).join("TunBridge").join("run"))
            .unwrap_or_else(|_| PathBuf::from(".tunbridge-run"));
        StatePaths { root }
    }

    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root).map_err(|e| CoreError::Io(e.to_string()))
    }

    pub fn pid_file(&self) -> PathBuf {
        self.root.join("mihomo.pid")
    }
    pub fn active_config(&self) -> PathBuf {
        self.root.join("active-config.yaml")
    }
    pub fn baseline_file(&self) -> PathBuf {
        self.root.join("baseline.json")
    }
    pub fn secret_file(&self) -> PathBuf {
        self.root.join("secret.txt")
    }
    pub fn profile_file(&self) -> PathBuf {
        self.root.join("profile.json")
    }
    pub fn engine_path_file(&self) -> PathBuf {
        self.root.join("engine-path.txt")
    }

    pub fn save_pid(&self, pid: u32) -> Result<()> {
        std::fs::write(self.pid_file(), pid.to_string()).map_err(|e| CoreError::Io(e.to_string()))
    }

    pub fn read_pid(&self) -> Option<u32> {
        std::fs::read_to_string(self.pid_file())
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    pub fn save_engine_path(&self, path: &std::path::Path) -> Result<()> {
        std::fs::write(self.engine_path_file(), path.to_string_lossy().as_bytes())
            .map_err(|e| CoreError::Io(e.to_string()))
    }

    pub fn read_engine_path(&self) -> Option<PathBuf> {
        let raw = std::fs::read_to_string(self.engine_path_file()).ok()?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed))
        }
    }

    pub fn clear(&self) -> Result<()> {
        for f in [
            self.pid_file(),
            self.active_config(),
            self.engine_path_file(),
        ] {
            let _ = std::fs::remove_file(f);
        }
        Ok(())
    }

    pub fn save_baseline(&self, snap: &NetSnapshot) -> Result<()> {
        let json = serde_json::to_string(snap).map_err(|e| CoreError::Io(e.to_string()))?;
        std::fs::write(self.baseline_file(), json).map_err(|e| CoreError::Io(e.to_string()))
    }

    pub fn read_baseline(&self) -> Result<NetSnapshot> {
        let raw = std::fs::read_to_string(self.baseline_file())
            .map_err(|e| CoreError::Io(e.to_string()))?;
        serde_json::from_str(&raw).map_err(|e| CoreError::Io(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::model::NetSnapshot;

    #[test]
    fn pid_roundtrip_and_clear() {
        let dir = std::env::temp_dir().join(format!("tb-state-{}", std::process::id()));
        let sp = StatePaths { root: dir.clone() };
        sp.ensure().unwrap();
        sp.save_pid(4321).unwrap();
        sp.save_engine_path(std::path::Path::new(r"C:\Tools\mihomo.exe"))
            .unwrap();
        assert_eq!(sp.read_pid(), Some(4321));
        assert_eq!(
            sp.read_engine_path(),
            Some(PathBuf::from(r"C:\Tools\mihomo.exe"))
        );
        sp.clear().unwrap();
        assert_eq!(sp.read_pid(), None);
        assert_eq!(sp.read_engine_path(), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn baseline_roundtrip() {
        let dir = std::env::temp_dir().join(format!("tb-base-{}", std::process::id()));
        let sp = StatePaths { root: dir.clone() };
        sp.ensure().unwrap();
        let snap = NetSnapshot {
            routes: vec!["a".into()],
            adapters: vec!["Ethernet".into()],
        };
        sp.save_baseline(&snap).unwrap();
        assert_eq!(sp.read_baseline().unwrap(), snap);
        let _ = std::fs::remove_dir_all(dir);
    }
}
