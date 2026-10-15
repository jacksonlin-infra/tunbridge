use std::{ffi::c_void, io, mem::size_of, ptr};

use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL},
    Security::{
        Authorization::ConvertSidToStringSidW, CheckTokenMembership, CreateWellKnownSid,
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, RevertToSelf,
        TokenIntegrityLevel, TokenIsAppContainer, TokenSessionId, TokenUser,
        WinAuthenticatedUserSid, WinBuiltinAdministratorsSid, WinInteractiveSid, PSID,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, WELL_KNOWN_SID_TYPE,
    },
    System::{
        RemoteDesktop::ProcessIdToSessionId,
        SystemServices::SECURITY_MANDATORY_MEDIUM_RID,
        Threading::{GetCurrentThread, OpenThreadToken},
    },
};

use crate::state::Caller;

const SECURITY_MAX_SID_SIZE: usize = 68;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenFacts {
    pub authenticated: bool,
    pub interactive: bool,
    pub app_container: bool,
    pub integrity_rid: u32,
    pub token_session_id: u32,
    pub process_session_id: u32,
}

impl TokenFacts {
    pub fn validate(self) -> Result<(), IdentityError> {
        if !self.authenticated || !self.interactive {
            return Err(IdentityError::AccessDenied(
                "caller is not an authenticated interactive user".into(),
            ));
        }
        if self.app_container || self.integrity_rid < SECURITY_MANDATORY_MEDIUM_RID as u32 {
            return Err(IdentityError::LowIntegrityDenied);
        }
        if self.token_session_id != self.process_session_id {
            return Err(IdentityError::AccessDenied(
                "client token and process sessions do not match".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    pub caller: Caller,
    pub client_process_id: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("access denied: {0}")]
    AccessDenied(String),
    #[error("low-integrity and AppContainer callers are denied")]
    LowIntegrityDenied,
    #[error("Windows identity query failed: {0}")]
    Windows(#[source] io::Error),
}

impl IdentityError {
    fn last_windows_error() -> Self {
        Self::Windows(io::Error::last_os_error())
    }
}

/// Read the effective impersonation token after the named-pipe server has
/// called `ImpersonateNamedPipeClient`.
pub(super) fn capture_impersonated_client(
    client_process_id: u32,
) -> Result<CallerIdentity, IdentityError> {
    let mut raw_token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentThread returns a pseudo-handle valid for this call and
    // raw_token points to writable storage.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut raw_token) };
    if opened == 0 {
        return Err(IdentityError::last_windows_error());
    }
    let token = OwnedHandle(raw_token);

    let token_session_id = token_u32(token.0, TokenSessionId)?;
    let app_container = token_u32(token.0, TokenIsAppContainer)? != 0;
    let integrity_rid = token_integrity_rid(token.0)?;
    let authenticated = token_is_member(token.0, WinAuthenticatedUserSid)?;
    let interactive = token_is_member(token.0, WinInteractiveSid)?;
    let is_admin = token_is_member(token.0, WinBuiltinAdministratorsSid)?;

    let mut process_session_id = 0_u32;
    // SAFETY: output pointer is valid for one u32.
    if unsafe { ProcessIdToSessionId(client_process_id, &mut process_session_id) } == 0 {
        return Err(IdentityError::last_windows_error());
    }

    TokenFacts {
        authenticated,
        interactive,
        app_container,
        integrity_rid,
        token_session_id,
        process_session_id,
    }
    .validate()?;

    let principal_id = token_user_sid_string(token.0)?;
    Ok(CallerIdentity {
        caller: Caller {
            principal_id,
            session_id: token_session_id,
            is_admin,
        },
        client_process_id,
    })
}

pub(super) struct ImpersonationGuard {
    active: bool,
}

impl ImpersonationGuard {
    pub(super) fn active() -> Self {
        Self { active: true }
    }

    pub(super) fn revert(mut self) -> Result<(), IdentityError> {
        // SAFETY: the current thread is the thread that performed pipe
        // impersonation. RevertToSelf has no pointer preconditions.
        if unsafe { RevertToSelf() } == 0 {
            return Err(IdentityError::last_windows_error());
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: best-effort fail-safe for early returns. The explicit
            // revert path still reports errors to the caller.
            unsafe {
                RevertToSelf();
            }
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: handle ownership was transferred by OpenThreadToken.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct TokenBuffer {
    words: Vec<usize>,
}

impl TokenBuffer {
    fn query(token: HANDLE, class: i32) -> Result<Self, IdentityError> {
        let mut required = 0_u32;
        // SAFETY: the first call intentionally supplies no output buffer to get
        // the required size.
        unsafe {
            GetTokenInformation(token, class, ptr::null_mut(), 0, &mut required);
        }
        if required == 0 {
            return Err(IdentityError::last_windows_error());
        }

        let word_count = (required as usize).div_ceil(size_of::<usize>());
        let mut words = vec![0_usize; word_count];
        // SAFETY: the allocation is aligned to usize and has at least required
        // writable bytes. Windows initializes the returned structure.
        if unsafe {
            GetTokenInformation(
                token,
                class,
                words.as_mut_ptr().cast::<c_void>(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(IdentityError::last_windows_error());
        }
        Ok(Self { words })
    }

    fn as_ptr<T>(&self) -> *const T {
        self.words.as_ptr().cast::<T>()
    }
}

fn token_u32(token: HANDLE, class: i32) -> Result<u32, IdentityError> {
    let buffer = TokenBuffer::query(token, class)?;
    // SAFETY: both queried information classes return a DWORD and TokenBuffer
    // guarantees suitable alignment and storage.
    Ok(unsafe { *buffer.as_ptr::<u32>() })
}

fn token_integrity_rid(token: HANDLE) -> Result<u32, IdentityError> {
    let buffer = TokenBuffer::query(token, TokenIntegrityLevel)?;
    // SAFETY: TokenIntegrityLevel returns TOKEN_MANDATORY_LABEL.
    let label = unsafe { &*buffer.as_ptr::<TOKEN_MANDATORY_LABEL>() };
    let sid = label.Label.Sid;
    if sid.is_null() {
        return Err(IdentityError::AccessDenied(
            "token integrity SID is missing".into(),
        ));
    }
    // SAFETY: SID came from a successful GetTokenInformation call.
    let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
    if count_ptr.is_null() {
        return Err(IdentityError::last_windows_error());
    }
    // SAFETY: the SID remains backed by buffer for this scope.
    let count = unsafe { *count_ptr };
    if count == 0 {
        return Err(IdentityError::AccessDenied(
            "token integrity SID has no RID".into(),
        ));
    }
    // SAFETY: count is nonzero and supplied by the valid SID.
    let rid_ptr = unsafe { GetSidSubAuthority(sid, u32::from(count - 1)) };
    if rid_ptr.is_null() {
        return Err(IdentityError::last_windows_error());
    }
    Ok(unsafe { *rid_ptr })
}

fn token_user_sid_string(token: HANDLE) -> Result<String, IdentityError> {
    let buffer = TokenBuffer::query(token, TokenUser)?;
    // SAFETY: TokenUser returns TOKEN_USER.
    let user = unsafe { &*buffer.as_ptr::<TOKEN_USER>() };
    sid_to_string(user.User.Sid)
}

fn token_is_member(token: HANDLE, sid_type: WELL_KNOWN_SID_TYPE) -> Result<bool, IdentityError> {
    let word_count = SECURITY_MAX_SID_SIZE.div_ceil(size_of::<usize>());
    let mut sid_storage = vec![0_usize; word_count];
    let mut sid_size = SECURITY_MAX_SID_SIZE as u32;
    let sid = sid_storage.as_mut_ptr().cast::<c_void>();
    // SAFETY: sid_storage is writable and at least SECURITY_MAX_SID_SIZE bytes.
    if unsafe { CreateWellKnownSid(sid_type, ptr::null_mut(), sid, &mut sid_size) } == 0 {
        return Err(IdentityError::last_windows_error());
    }

    let mut is_member = 0;
    // SAFETY: token has TOKEN_QUERY and sid contains a valid well-known SID.
    if unsafe { CheckTokenMembership(token, sid, &mut is_member) } == 0 {
        return Err(IdentityError::last_windows_error());
    }
    Ok(is_member != 0)
}

fn sid_to_string(sid: PSID) -> Result<String, IdentityError> {
    if sid.is_null() {
        return Err(IdentityError::AccessDenied("user SID is missing".into()));
    }
    let mut wide = ptr::null_mut();
    // SAFETY: sid is backed by a successful TokenUser query; Windows allocates
    // the returned NUL-terminated string with LocalAlloc.
    if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
        return Err(IdentityError::last_windows_error());
    }
    let local = LocalAllocation(wide.cast::<c_void>());
    let mut length = 0_usize;
    // SAFETY: wide points to a NUL-terminated UTF-16 string.
    unsafe {
        while *wide.add(length) != 0 {
            length += 1;
        }
    }
    // SAFETY: length was measured within the Windows-allocated string.
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(wide, length) })
        .map_err(|_| IdentityError::AccessDenied("user SID is not valid UTF-16".into()))?;
    drop(local);
    Ok(value)
}

struct LocalAllocation(HLOCAL);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: ownership came from a LocalAlloc-family Windows API.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> TokenFacts {
        TokenFacts {
            authenticated: true,
            interactive: true,
            app_container: false,
            integrity_rid: SECURITY_MANDATORY_MEDIUM_RID as u32,
            token_session_id: 1,
            process_session_id: 1,
        }
    }

    #[test]
    fn policy_accepts_medium_interactive_authenticated_token() {
        allowed().validate().unwrap();
    }

    #[test]
    fn policy_rejects_network_or_unauthenticated_token() {
        let mut facts = allowed();
        facts.interactive = false;
        assert!(matches!(
            facts.validate(),
            Err(IdentityError::AccessDenied(_))
        ));

        facts = allowed();
        facts.authenticated = false;
        assert!(matches!(
            facts.validate(),
            Err(IdentityError::AccessDenied(_))
        ));
    }

    #[test]
    fn policy_rejects_low_integrity_and_appcontainer() {
        let mut facts = allowed();
        facts.integrity_rid = SECURITY_MANDATORY_MEDIUM_RID as u32 - 1;
        assert!(matches!(
            facts.validate(),
            Err(IdentityError::LowIntegrityDenied)
        ));

        facts = allowed();
        facts.app_container = true;
        assert!(matches!(
            facts.validate(),
            Err(IdentityError::LowIntegrityDenied)
        ));
    }

    #[test]
    fn policy_rejects_process_token_session_mismatch() {
        let mut facts = allowed();
        facts.process_session_id = 2;
        assert!(matches!(
            facts.validate(),
            Err(IdentityError::AccessDenied(_))
        ));
    }
}
