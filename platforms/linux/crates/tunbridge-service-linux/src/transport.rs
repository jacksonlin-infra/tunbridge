use libc::{c_void, gid_t, pid_t, socklen_t, uid_t, SOL_SOCKET, SO_PEERCRED};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tunbridge_desktop_contract::adapter::{AdapterError, AdapterErrorCode, ServiceTransport};
use tunbridge_service::protocol::MAX_FRAME_BYTES;

const PREFIX_BYTES: usize = 4;
const SOCKET_MODE: u32 = 0o666;
const ROOT_USER_ID: u32 = 0;
pub const SERVICE_SOCKET_PATH: &str = "/run/tunbridge/service.sock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub process_id: u32,
    pub user_id: u32,
    pub group_id: u32,
}

pub struct UnixServiceTransport {
    stream: UnixStream,
    peer: PeerCredentials,
}

impl UnixServiceTransport {
    pub fn connect_system() -> Result<Self, AdapterError> {
        Self::connect(Path::new(SERVICE_SOCKET_PATH), ROOT_USER_ID)
    }

    pub fn connect(path: &Path, expected_server_uid: u32) -> Result<Self, AdapterError> {
        validate_socket_path(path, expected_server_uid)?;
        let stream = UnixStream::connect(path).map_err(|_| unavailable())?;
        let peer = peer_credentials(&stream)?;
        if peer.user_id != expected_server_uid {
            return Err(identity_rejected());
        }
        Ok(Self { stream, peer })
    }

    pub fn peer_credentials(&self) -> PeerCredentials {
        self.peer
    }
}

impl ServiceTransport for UnixServiceTransport {
    fn transact(
        &mut self,
        request_frame: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, AdapterError> {
        validate_frame_shape(request_frame)?;
        configure_timeouts(&self.stream, timeout)?;
        self.stream
            .write_all(request_frame)
            .and_then(|_| self.stream.flush())
            .map_err(|_| unavailable())?;
        read_frame(&mut self.stream)
    }
}

pub struct UnixServiceListener {
    listener: UnixListener,
    path: PathBuf,
}

impl UnixServiceListener {
    pub fn bind_system() -> Result<Self, AdapterError> {
        Self::bind(PathBuf::from(SERVICE_SOCKET_PATH), ROOT_USER_ID)
    }

    pub fn bind(path: PathBuf, expected_owner_uid: u32) -> Result<Self, AdapterError> {
        validate_parent(&path, expected_owner_uid)?;
        if fs::symlink_metadata(&path).is_ok() {
            return Err(identity_rejected());
        }
        let listener = UnixListener::bind(&path).map_err(|_| unavailable())?;
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(SOCKET_MODE)) {
            let _ = fs::remove_file(&path);
            return Err(if error.kind() == std::io::ErrorKind::PermissionDenied {
                permission_denied()
            } else {
                unavailable()
            });
        }
        Ok(Self { listener, path })
    }

    pub fn accept(
        &self,
        expected_client_uid: Option<u32>,
        timeout: Duration,
    ) -> Result<UnixServiceConnection, AdapterError> {
        let (stream, _) = self.listener.accept().map_err(|_| unavailable())?;
        configure_timeouts(&stream, timeout)?;
        let peer = peer_credentials(&stream)?;
        if expected_client_uid.is_some_and(|expected| peer.user_id != expected) {
            return Err(identity_rejected());
        }
        Ok(UnixServiceConnection { stream, peer })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for UnixServiceListener {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o777 == SOCKET_MODE
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub struct UnixServiceConnection {
    stream: UnixStream,
    peer: PeerCredentials,
}

impl UnixServiceConnection {
    pub fn peer_credentials(&self) -> PeerCredentials {
        self.peer
    }

    pub fn receive_frame(&mut self) -> Result<Vec<u8>, AdapterError> {
        read_frame(&mut self.stream)
    }

    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), AdapterError> {
        validate_frame_shape(frame)?;
        self.stream
            .write_all(frame)
            .and_then(|_| self.stream.flush())
            .map_err(|_| unavailable())
    }
}

fn validate_socket_path(path: &Path, expected_owner_uid: u32) -> Result<(), AdapterError> {
    validate_parent(path, expected_owner_uid)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o777 != SOCKET_MODE
    {
        return Err(identity_rejected());
    }
    Ok(())
}

fn validate_parent(path: &Path, expected_owner_uid: u32) -> Result<(), AdapterError> {
    if !path.is_absolute() {
        return Err(identity_rejected());
    }
    let Some(parent) = path.parent() else {
        return Err(identity_rejected());
    };
    let metadata = fs::symlink_metadata(parent).map_err(|_| unavailable())?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(identity_rejected());
    }
    Ok(())
}

fn configure_timeouts(stream: &UnixStream, timeout: Duration) -> Result<(), AdapterError> {
    if timeout.is_zero() {
        return Err(invalid_data());
    }
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| unavailable())
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, AdapterError> {
    let mut prefix = [0_u8; PREFIX_BYTES];
    stream.read_exact(&mut prefix).map_err(|_| unavailable())?;
    let length = u32::from_le_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(invalid_data());
    }
    let mut frame = Vec::with_capacity(PREFIX_BYTES + length);
    frame.extend_from_slice(&prefix);
    frame.resize(PREFIX_BYTES + length, 0);
    stream
        .read_exact(&mut frame[PREFIX_BYTES..])
        .map_err(|_| unavailable())?;
    Ok(frame)
}

fn validate_frame_shape(frame: &[u8]) -> Result<(), AdapterError> {
    if frame.len() < PREFIX_BYTES {
        return Err(invalid_data());
    }
    let mut prefix = [0_u8; PREFIX_BYTES];
    prefix.copy_from_slice(&frame[..PREFIX_BYTES]);
    let length = u32::from_le_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES || frame.len() != PREFIX_BYTES + length {
        return Err(invalid_data());
    }
    Ok(())
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, AdapterError> {
    let mut credentials = libc::ucred {
        pid: 0 as pid_t,
        uid: 0 as uid_t,
        gid: 0 as gid_t,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast::<c_void>(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() || credentials.pid <= 0
    {
        return Err(identity_rejected());
    }
    Ok(PeerCredentials {
        process_id: credentials.pid as u32,
        user_id: credentials.uid,
        group_id: credentials.gid,
    })
}

const fn invalid_data() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::InvalidData,
        safe_message: "The Linux service frame is invalid.",
        retryable: false,
    }
}

const fn identity_rejected() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::IdentityRejected,
        safe_message: "The Linux service identity could not be verified.",
        retryable: false,
    }
}

const fn permission_denied() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::PermissionDenied,
        safe_message: "The Linux service socket permissions could not be secured.",
        retryable: false,
    }
}

const fn unavailable() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::Unavailable,
        safe_message: "The Linux service transport is unavailable.",
        retryable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tunbridge_service::frame;
    use tunbridge_service::protocol::Hello;

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn status_only_system_socket_has_no_login_group_gate() {
        assert_eq!(SOCKET_MODE, 0o666);
    }

    fn test_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "tunbridge-linux-transport-{}-{}-{}",
            std::process::id(),
            name,
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn framed_round_trip_uses_kernel_peer_credentials() {
        let directory = test_directory("round-trip");
        let path = directory.join("service.sock");
        let uid = unsafe { libc::geteuid() };
        let listener = UnixServiceListener::bind(path.clone(), uid).unwrap();

        let server = std::thread::spawn(move || {
            let mut connection = listener.accept(Some(uid), Duration::from_secs(2)).unwrap();
            assert_eq!(connection.peer_credentials().user_id, uid);
            let request = connection.receive_frame().unwrap();
            let hello: Hello = frame::decode(&request).unwrap();
            hello.validate().unwrap();
            connection.send_frame(&request).unwrap();
        });

        let mut client = UnixServiceTransport::connect(&path, uid).unwrap();
        assert_eq!(client.peer_credentials().user_id, uid);
        let request = frame::encode(&Hello::new("0.2.0")).unwrap();
        let response = client.transact(&request, Duration::from_secs(2)).unwrap();
        assert_eq!(
            frame::decode::<Hello>(&response).unwrap(),
            Hello::new("0.2.0")
        );
        server.join().unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn rejects_wrong_server_and_client_uid() {
        let directory = test_directory("peer");
        let path = directory.join("service.sock");
        let uid = unsafe { libc::geteuid() };
        let listener = UnixServiceListener::bind(path.clone(), uid).unwrap();

        assert!(matches!(
            UnixServiceTransport::connect(&path, uid.saturating_add(1)),
            Err(error) if error.code == AdapterErrorCode::IdentityRejected
        ));

        let server = std::thread::spawn(move || {
            assert!(matches!(
                listener.accept(Some(uid.saturating_add(1)), Duration::from_secs(2)),
                Err(error) if error.code == AdapterErrorCode::IdentityRejected
            ));
        });
        let _client = UnixStream::connect(&path).unwrap();
        server.join().unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn rejects_symlink_existing_socket_and_insecure_parent() {
        let directory = test_directory("paths");
        let uid = unsafe { libc::geteuid() };
        let target = directory.join("target");
        fs::write(&target, b"not a socket").unwrap();
        let link = directory.join("service.sock");
        symlink(&target, &link).unwrap();
        assert!(matches!(
            UnixServiceListener::bind(link.clone(), uid),
            Err(error) if error.code == AdapterErrorCode::IdentityRejected
        ));
        fs::remove_file(&link).unwrap();

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            UnixServiceListener::bind(link, uid),
            Err(error) if error.code == AdapterErrorCode::IdentityRejected
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_malformed_and_oversized_frames_before_io() {
        assert_eq!(
            validate_frame_shape(&[]).unwrap_err().code,
            AdapterErrorCode::InvalidData
        );
        let mut oversized = ((MAX_FRAME_BYTES + 1) as u32).to_le_bytes().to_vec();
        oversized.extend_from_slice(b"{}");
        assert_eq!(
            validate_frame_shape(&oversized).unwrap_err().code,
            AdapterErrorCode::InvalidData
        );
        let trailing = [2_u32.to_le_bytes().as_slice(), b"{}x"].concat();
        assert_eq!(
            validate_frame_shape(&trailing).unwrap_err().code,
            AdapterErrorCode::InvalidData
        );
    }
}
