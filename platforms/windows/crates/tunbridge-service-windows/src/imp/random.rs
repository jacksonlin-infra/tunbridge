use std::{fmt::Write as _, io, ptr};

use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};

pub(super) fn random_hex_32() -> io::Result<String> {
    let bytes = random_bytes_32()?;
    let mut result = String::with_capacity(64);
    for byte in bytes {
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(result)
}

pub(super) fn random_bytes_32() -> io::Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    // SAFETY: a null algorithm handle is required with
    // BCRYPT_USE_SYSTEM_PREFERRED_RNG and bytes is writable for its full size.
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_csprng_shaped_and_distinct() {
        let first = random_hex_32().unwrap();
        let second = random_hex_32().unwrap();
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }
}
