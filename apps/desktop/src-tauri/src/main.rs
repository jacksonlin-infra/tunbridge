#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(all(target_os = "linux", feature = "omarchy-package"))]
fn configure_omarchy_webkit_renderer() {
    // WebKitGTK's DMA-BUF renderer currently sends an invalid wl_surface.attach
    // request on the VMware graphics stack shipped with Omarchy 4. Keep this
    // package-specific and set it before GTK/WebKit creates any threads.
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }
}

#[cfg(windows)]
mod windows_single_instance {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr::null};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE},
        System::Threading::{CreateMutexW, ReleaseMutex},
        UI::WindowsAndMessaging::{
            FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW,
        },
    };

    const MUTEX_NAME: &str = "Local\\com.tunbridge.desktop.single-instance";
    const WINDOW_TITLE: &str = "TunBridge";

    pub struct Guard {
        handle: HANDLE,
    }

    impl Guard {
        pub fn acquire() -> Option<Self> {
            let name = wide(MUTEX_NAME);
            let handle = unsafe { CreateMutexW(null(), 1, name.as_ptr()) };
            if handle.is_null() {
                // A failure to establish the process boundary must fail closed.
                return None;
            }
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                unsafe {
                    CloseHandle(handle);
                }
                activate_existing_window();
                return None;
            }
            Some(Self { handle })
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                ReleaseMutex(self.handle);
                CloseHandle(self.handle);
            }
        }
    }

    fn activate_existing_window() {
        let title = wide(WINDOW_TITLE);
        let window = unsafe { FindWindowW(null(), title.as_ptr()) };
        if !window.is_null() {
            unsafe {
                ShowWindow(window, SW_SHOW);
                ShowWindow(window, SW_RESTORE);
                SetForegroundWindow(window);
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

#[cfg(target_os = "linux")]
mod linux_single_instance {
    use std::{
        fs::{self, File, OpenOptions},
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawFd,
        },
        path::Path,
    };

    pub struct Guard(File);

    impl Guard {
        pub fn acquire() -> Option<Self> {
            let runtime = std::env::var_os("XDG_RUNTIME_DIR")?;
            Self::acquire_at(Path::new(&runtime).join("tunbridge-desktop.lock"))
        }

        fn acquire_at(path: impl AsRef<Path>) -> Option<Self> {
            let path = path.as_ref();
            let runtime = path.parent()?;
            let runtime_metadata = fs::symlink_metadata(runtime).ok()?;
            let uid = unsafe { libc::geteuid() };
            if !runtime_metadata.is_dir()
                || runtime_metadata.uid() != uid
                || runtime_metadata.mode() & 0o777 != 0o700
            {
                return None;
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
                .ok()?;
            let metadata = file.metadata().ok()?;
            if !metadata.is_file()
                || metadata.uid() != uid
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
            {
                return None;
            }
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return None;
            }
            Some(Self(file))
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{os::unix::fs::PermissionsExt, path::PathBuf};

        fn private_runtime(name: &str) -> PathBuf {
            let path = std::env::temp_dir().join(format!(
                "tunbridge-single-instance-{}-{name}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        }

        #[test]
        fn lock_rejects_a_second_process_slot_until_release() {
            let runtime = private_runtime("exclusive");
            let lock = runtime.join("desktop.lock");
            let first = Guard::acquire_at(&lock).unwrap();
            assert!(Guard::acquire_at(&lock).is_none());
            drop(first);
            assert!(Guard::acquire_at(&lock).is_some());
            fs::remove_file(lock).unwrap();
            fs::remove_dir(runtime).unwrap();
        }
    }
}

fn main() {
    #[cfg(all(target_os = "linux", feature = "omarchy-package"))]
    configure_omarchy_webkit_renderer();
    #[cfg(windows)]
    let _single_instance = match windows_single_instance::Guard::acquire() {
        Some(guard) => guard,
        None => return,
    };
    #[cfg(target_os = "linux")]
    let _single_instance = match linux_single_instance::Guard::acquire() {
        Some(guard) => guard,
        None => return,
    };
    tunbridge_desktop_lib::run();
}
