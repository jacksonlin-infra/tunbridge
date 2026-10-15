//! Executables of the local proxy client that must reach the network
//! directly.
//!
//! The engine bypasses only the process that owns the upstream listener. A
//! client such as a commercial VPN app logs in from a different process (its UI) before
//! the listener exists, so after a restart that login traffic followed
//! `MATCH,upstream` into the closed listener and the client could never come
//! back. The client family is every running executable signed by the same
//! Developer ID team as the verified upstream, or shipped in the same app
//! bundle. The engine sends exactly those paths DIRECT; every other app keeps
//! failing closed while the upstream is down.

use std::{
    collections::BTreeSet,
    ffi::{c_void, CString},
    os::raw::{c_char, c_int},
    path::{Path, PathBuf},
};

use crate::native::process_executable_path;

const MAX_FAMILY_PATHS: usize = 16;
const MAX_LISTED_PIDS: usize = 8192;
const MAX_RULE_PATH_BYTES: usize = 1024;
/// Platform binaries carry no team identifier and are never a proxy client.
const SYSTEM_PREFIXES: &[&str] = &["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"];

/// Running executables of the client that owns `upstream_pid`, as absolute
/// paths safe to embed in an engine rule. Empty when nothing can be proven.
pub fn client_family_paths(upstream_pid: u32) -> Vec<String> {
    let Ok(upstream) = process_executable_path(upstream_pid) else {
        return Vec::new();
    };
    let team = verified_team_identifier(&upstream);
    let candidates: BTreeSet<PathBuf> = listed_pids()
        .into_iter()
        .filter_map(|pid| process_executable_path(pid).ok())
        .collect();
    select_family_paths(&upstream, team.as_deref(), &candidates, |path, team| {
        signed_by_team(path, team)
    })
}

fn select_family_paths(
    upstream: &Path,
    team: Option<&str>,
    candidates: &BTreeSet<PathBuf>,
    signed_by: impl Fn(&Path, &str) -> bool,
) -> Vec<String> {
    let bundle = app_bundle_root(upstream);
    let mut selected = Vec::new();
    for path in candidates {
        if selected.len() == MAX_FAMILY_PATHS {
            break;
        }
        let Some(rule_path) = rule_safe_path(path) else {
            continue;
        };
        if SYSTEM_PREFIXES
            .iter()
            .any(|prefix| rule_path.starts_with(prefix))
        {
            continue;
        }
        let same_bundle = bundle
            .as_deref()
            .is_some_and(|bundle| path.starts_with(bundle));
        if same_bundle || team.is_some_and(|team| signed_by(path, team)) {
            selected.push(rule_path.to_owned());
        }
    }
    selected
}

/// The enclosing `*.app` directory of an executable, if any.
fn app_bundle_root(executable: &Path) -> Option<PathBuf> {
    executable
        .ancestors()
        .find(|ancestor| {
            ancestor
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
        })
        .map(Path::to_path_buf)
}

/// Engine rules are comma separated lines; refuse anything that could break
/// out of a single PROCESS-PATH value.
fn rule_safe_path(path: &Path) -> Option<&str> {
    path.to_str().filter(|value| {
        value.starts_with('/')
            && value.len() <= MAX_RULE_PATH_BYTES
            && !value.contains(',')
            && !value.chars().any(char::is_control)
    })
}

fn valid_team_identifier(team: &str) -> bool {
    team.len() == 10
        && team
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn listed_pids() -> Vec<u32> {
    let mut pids = vec![0 as c_int; MAX_LISTED_PIDS];
    // SAFETY: the buffer holds MAX_LISTED_PIDS c_int values and its byte size
    // is passed; the call writes at most that many entries.
    let count = unsafe {
        proc_listallpids(
            pids.as_mut_ptr().cast(),
            (pids.len() * std::mem::size_of::<c_int>()) as c_int,
        )
    };
    if count <= 0 {
        return Vec::new();
    }
    pids.truncate((count as usize).min(MAX_LISTED_PIDS));
    pids.into_iter()
        .filter_map(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 1)
        .collect()
}

/// The Developer ID team of a signed executable, proven by validating it
/// against an Apple-anchored requirement for that team.
fn verified_team_identifier(path: &Path) -> Option<String> {
    let code = StaticCode::from_path(path)?;
    let team = code.team_identifier()?;
    (valid_team_identifier(&team) && code.satisfies_team(&team)).then_some(team)
}

fn signed_by_team(path: &Path, team: &str) -> bool {
    valid_team_identifier(team)
        && StaticCode::from_path(path).is_some_and(|code| code.satisfies_team(team))
}

type CfRef = *const c_void;

struct CfOwned(CfRef);

impl Drop for CfOwned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the reference was returned by a Create/Copy function.
            unsafe { CFRelease(self.0) };
        }
    }
}

struct StaticCode(CfOwned);

impl StaticCode {
    fn from_path(path: &Path) -> Option<Self> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        // SAFETY: bytes is valid for its length for the duration of the call.
        let url = CfOwned(unsafe {
            CFURLCreateFromFileSystemRepresentation(
                std::ptr::null(),
                bytes.as_ptr(),
                bytes.len() as isize,
                0,
            )
        });
        if url.0.is_null() {
            return None;
        }
        let mut code: CfRef = std::ptr::null();
        // SAFETY: url is a valid CFURL; code receives an owned reference.
        let status = unsafe { SecStaticCodeCreateWithPath(url.0, 0, &mut code) };
        (status == 0 && !code.is_null()).then(|| Self(CfOwned(code)))
    }

    fn team_identifier(&self) -> Option<String> {
        let mut information: CfRef = std::ptr::null();
        // SAFETY: self.0 is a SecStaticCode; information receives an owned
        // dictionary. kSecCSSigningInformation = 1 << 1.
        let status = unsafe { SecCodeCopySigningInformation(self.0 .0, 1 << 1, &mut information) };
        let information = CfOwned(information);
        if status != 0 || information.0.is_null() {
            return None;
        }
        // SAFETY: information is a CFDictionary and the key is a constant.
        let value = unsafe { CFDictionaryGetValue(information.0, kSecCodeInfoTeamIdentifier) };
        // SAFETY: the type is checked before reading the value as a string.
        if value.is_null() || unsafe { CFGetTypeID(value) != CFStringGetTypeID() } {
            return None;
        }
        let mut buffer = [0 as c_char; 32];
        // SAFETY: value is a CFString and the buffer length is passed.
        let ok = unsafe {
            CFStringGetCString(
                value,
                buffer.as_mut_ptr(),
                buffer.len() as isize,
                0x0800_0100,
            )
        };
        if ok == 0 {
            return None;
        }
        // SAFETY: CFStringGetCString NUL-terminated the buffer on success.
        unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
            .to_str()
            .ok()
            .map(str::to_owned)
    }

    /// Validates the signature (not every page) against an Apple-anchored
    /// Developer ID requirement for `team`.
    fn satisfies_team(&self, team: &str) -> bool {
        let Ok(text) = CString::new(format!(
            "anchor apple generic and certificate leaf[subject.OU] = \"{team}\""
        )) else {
            return false;
        };
        // SAFETY: text is NUL-terminated; kCFStringEncodingUTF8.
        let string = CfOwned(unsafe {
            CFStringCreateWithCString(std::ptr::null(), text.as_ptr(), 0x0800_0100)
        });
        if string.0.is_null() {
            return false;
        }
        let mut requirement: CfRef = std::ptr::null();
        // SAFETY: string is a CFString; requirement receives an owned ref.
        let status = unsafe { SecRequirementCreateWithString(string.0, 0, &mut requirement) };
        let requirement = CfOwned(requirement);
        if status != 0 || requirement.0.is_null() {
            return false;
        }
        // kSecCSDoNotValidateExecutable | kSecCSDoNotValidateResources.
        // SAFETY: both references are valid for the call.
        unsafe { SecStaticCodeCheckValidity(self.0 .0, (1 << 1) | (1 << 2), requirement.0) == 0 }
    }
}

#[link(name = "proc")]
unsafe extern "C" {
    fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: CfRef);
    fn CFGetTypeID(value: CfRef) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFDictionaryGetValue(dictionary: CfRef, key: CfRef) -> CfRef;
    fn CFStringGetCString(value: CfRef, buffer: *mut c_char, size: isize, encoding: u32) -> u8;
    fn CFStringCreateWithCString(allocator: CfRef, value: *const c_char, encoding: u32) -> CfRef;
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: CfRef,
        buffer: *const u8,
        length: isize,
        is_directory: u8,
    ) -> CfRef;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecCodeInfoTeamIdentifier: CfRef;
    fn SecStaticCodeCreateWithPath(path: CfRef, flags: u32, code: *mut CfRef) -> i32;
    fn SecCodeCopySigningInformation(code: CfRef, flags: u32, information: *mut CfRef) -> i32;
    fn SecRequirementCreateWithString(text: CfRef, flags: u32, requirement: *mut CfRef) -> i32;
    fn SecStaticCodeCheckValidity(code: CfRef, flags: u32, requirement: CfRef) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    const UPSTREAM: &str = "/Library/PrivilegedHelperTools/com.example.ExampleProxyHelper";
    const UI: &str = "/Applications/ExampleProxy.app/Contents/MacOS/ExampleProxy";

    #[test]
    fn same_team_executables_form_the_client_family() {
        let candidates = BTreeSet::from([
            PathBuf::from(UPSTREAM),
            PathBuf::from(UI),
            PathBuf::from("/Applications/Safari.app/Contents/MacOS/Safari"),
            PathBuf::from("/usr/libexec/trustd"),
            PathBuf::from("/Applications/Evil,App.app/Contents/MacOS/x"),
        ]);
        let mono = |path: &Path, team: &str| {
            team == "7TM75YLBNA"
                && (path == Path::new(UPSTREAM)
                    || path == Path::new(UI)
                    || path.to_str().is_some_and(|p| p.contains("Evil")))
        };
        assert_eq!(
            select_family_paths(Path::new(UPSTREAM), Some("7TM75YLBNA"), &candidates, mono),
            [UI.to_owned(), UPSTREAM.to_owned()]
        );
        // Without a proven team only the upstream's own bundle qualifies.
        assert_eq!(
            select_family_paths(Path::new(UI), None, &candidates, mono),
            [UI.to_owned()]
        );
        assert!(select_family_paths(Path::new(UPSTREAM), None, &candidates, mono).is_empty());
    }

    #[test]
    fn family_is_bounded_and_rule_paths_are_strict() {
        let candidates: BTreeSet<PathBuf> = (0..40)
            .map(|index| {
                PathBuf::from(format!(
                    "/Applications/Client.app/Contents/MacOS/p{index:02}"
                ))
            })
            .collect();
        let selected = select_family_paths(
            Path::new("/Applications/Client.app/Contents/MacOS/p00"),
            None,
            &candidates,
            |_, _| false,
        );
        assert_eq!(selected.len(), MAX_FAMILY_PATHS);
        assert!(rule_safe_path(Path::new("relative/path")).is_none());
        assert!(rule_safe_path(Path::new("/tmp/a\nb")).is_none());
        assert!(valid_team_identifier("7TM75YLBNA"));
        assert!(!valid_team_identifier("adhoc"));
        assert_eq!(
            app_bundle_root(Path::new(UI)),
            Some(PathBuf::from("/Applications/ExampleProxy.app"))
        );
        assert_eq!(app_bundle_root(Path::new(UPSTREAM)), None);
    }

    #[test]
    fn signed_system_binary_reports_no_team_and_self_is_listed() {
        assert!(verified_team_identifier(Path::new("/usr/bin/true")).is_none());
        assert!(listed_pids().contains(&std::process::id()));
    }
}
