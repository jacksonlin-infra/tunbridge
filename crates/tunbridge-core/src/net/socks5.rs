use crate::{CoreError, Result};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

fn dial(proxy: SocketAddr, timeout: Duration) -> Result<TcpStream> {
    let s = TcpStream::connect_timeout(&proxy, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    Ok(s)
}

fn negotiate_no_auth(s: &mut TcpStream, auth: Option<(&str, &str)>) -> Result<()> {
    // We only advertise no-auth (0x00) and, if creds given, user/pass (0x02).
    if let Some((u, p)) = auth {
        s.write_all(&[0x05, 0x02, 0x00, 0x02])?;
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel)?;
        if sel[1] == 0x02 {
            let mut req = vec![0x01, u.len() as u8];
            req.extend_from_slice(u.as_bytes());
            req.push(p.len() as u8);
            req.extend_from_slice(p.as_bytes());
            s.write_all(&req)?;
            let mut ok = [0u8; 2];
            s.read_exact(&mut ok)?;
            if ok[1] != 0x00 {
                return Err(CoreError::Discovery("socks5 auth rejected".into()));
            }
        } else if sel[1] != 0x00 {
            return Err(CoreError::Discovery("socks5 no acceptable auth".into()));
        }
    } else {
        s.write_all(&[0x05, 0x01, 0x00])?;
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel)?;
        if sel[0] != 0x05 || sel[1] != 0x00 {
            return Err(CoreError::Discovery("socks5 no-auth not offered".into()));
        }
    }
    Ok(())
}

pub fn connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
    timeout: Duration,
) -> Result<TcpStream> {
    let mut s = dial(proxy, timeout)?;
    negotiate_no_auth(&mut s, auth)?;
    // CONNECT with domain atyp so the proxy resolves the name.
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(CoreError::Discovery(format!(
            "socks5 connect failed, rep={}",
            head[1]
        )));
    }
    // consume BND.ADDR + BND.PORT
    match head[3] {
        0x01 => {
            let mut a = [0u8; 6];
            s.read_exact(&mut a)?;
        }
        0x04 => {
            let mut a = [0u8; 18];
            s.read_exact(&mut a)?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            let mut rest = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut rest)?;
        }
        _ => return Err(CoreError::Discovery("socks5 bad atyp in reply".into())),
    }
    Ok(s)
}

pub fn handshake_only(proxy: SocketAddr, timeout: Duration) -> Result<()> {
    let mut s = dial(proxy, timeout)?;
    negotiate_no_auth(&mut s, None)
}

pub fn udp_associate_ok(proxy: SocketAddr, timeout: Duration) -> bool {
    let attempt = || -> Result<bool> {
        let mut s = dial(proxy, timeout)?;
        negotiate_no_auth(&mut s, None)?;
        // UDP ASSOCIATE, atyp ipv4 0.0.0.0:0
        s.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
        let mut head = [0u8; 4];
        s.read_exact(&mut head)?;
        Ok(head[1] == 0x00)
    };
    attempt().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::thread;
    use std::time::Duration;

    /// Minimal SOCKS5 server that accepts no-auth, replies success to CONNECT.
    fn spawn_socks5_ok() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut hello = [0u8; 2];
            s.read_exact(&mut hello).unwrap(); // VER, NMETHODS
            let mut methods = vec![0u8; hello[1] as usize];
            s.read_exact(&mut methods).unwrap();
            s.write_all(&[0x05, 0x00]).unwrap(); // no-auth selected
            let mut head = [0u8; 4];
            if s.read_exact(&mut head).is_err() {
                return;
            } // handshake_only closes here
            match head[3] {
                0x01 => {
                    let mut a = [0u8; 4];
                    s.read_exact(&mut a).unwrap();
                }
                0x03 => {
                    let mut l = [0u8; 1];
                    s.read_exact(&mut l).unwrap();
                    let mut d = vec![0u8; l[0] as usize];
                    s.read_exact(&mut d).unwrap();
                }
                _ => {}
            }
            let mut port = [0u8; 2];
            s.read_exact(&mut port).unwrap();
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
        });
        addr
    }

    #[test]
    fn connect_negotiates_and_succeeds() {
        let addr = spawn_socks5_ok();
        let s = connect(addr, "example.com", 80, None, Duration::from_secs(3));
        assert!(s.is_ok(), "socks5 connect should succeed: {:?}", s.err());
    }

    #[test]
    fn handshake_only_succeeds_on_socks5() {
        let addr = spawn_socks5_ok();
        assert!(handshake_only(addr, Duration::from_secs(3)).is_ok());
    }
}
