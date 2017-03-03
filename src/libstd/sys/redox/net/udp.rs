// Copyright 2016 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use cell::UnsafeCell;
use io::{Error, ErrorKind, Result};
use net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use path::Path;
use sys::fs::{File, OpenOptions};
use sys_common::{AsInner, FromInner, IntoInner};
use time::Duration;

use super::{parse_address};

#[derive(Debug)]
pub struct UdpSocket {
    handle: File,
    connected: UnsafeCell<bool>,
}

impl UdpSocket {
    pub fn bind(addr: &SocketAddr) -> Result<UdpSocket> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.write(true);
        let path = format!("ethernet:udp/{}", addr);

        let handle = File::open(&Path::new(path.as_str()), &options)?;

        Ok(UdpSocket {
            handle: handle,
            connected: UnsafeCell::new(false),
        })
    }

    pub fn connect(&self, addr: &SocketAddr) -> Result<()> {
        self.handle.dup(format!("connect/{}", addr).as_bytes())?;
        unsafe { *self.connected.get() = true };
        Ok(())
    }

    fn is_connected(&self) -> bool {
        unsafe { *self.connected.get() }
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        if self.is_connected() {
            return Err(Error::new(ErrorKind::Other, "UdpSocket::recv_from: socket is connected"));
        }
        let count = self.handle.read(buf)?;
        if let Some(peer) = parse_address(self.handle.path()?.to_str().ok_or(Error::new(ErrorKind::Other, "UdpSocket::recv_from: Failed to read peer address"))?) {
            return Ok((count, peer));
        } else {
            Err(Error::new(ErrorKind::Other, "UdpSocket::recv_from: failed to parse peer address"))
        }
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        if ! self.is_connected() {
            return Err(Error::new(ErrorKind::Other, "UdpSocket::recv: socket is not connected"));
        }
        Ok(self.handle.read(buf)?)
    }

    pub fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        if self.is_connected() {
            return Err(Error::new(ErrorKind::Other, "UdpSocket::send_to: socket is connected"));
        }
        self.handle.dup(format!("peer_to/{}", addr).as_bytes())?;
        Ok(self.handle.write(buf)?)
    }

    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        if self.is_connected() {
            return Ok(self.handle.write(buf)?);
        } else {
            return Err(Error::new(ErrorKind::Other, "UdpSocket::send not connected"));
        }
    }

    pub fn duplicate(&self) -> Result<UdpSocket> {
        Ok(UdpSocket {
            handle: self.handle.dup(b"")?,
            connected: UnsafeCell::new(self.is_connected()),
        })
    }

    pub fn take_error(&self) -> Result<Option<Error>> {
        Ok(None)
    }

    pub fn socket_addr(&self) -> Result<SocketAddr> {
        // FIXME
        panic!()
        // let path = self.handle.path()?;
        // Ok(path_to_local_addr(path.to_str().unwrap_or("")))
    }

    pub fn peek(&self, _buf: &mut [u8]) -> Result<usize> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::peek not implemented"))
    }

    pub fn peek_from(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::peek_from not implemented"))
    }

    pub fn broadcast(&self) -> Result<bool> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::broadcast not implemented"))
    }

    pub fn multicast_loop_v4(&self) -> Result<bool> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::multicast_loop_v4 not implemented"))
    }

    pub fn multicast_loop_v6(&self) -> Result<bool> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::multicast_loop_v6 not implemented"))
    }

    pub fn multicast_ttl_v4(&self) -> Result<u32> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::multicast_ttl_v4 not implemented"))
    }

    pub fn nonblocking(&self) -> Result<bool> {
        self.handle.fd().nonblocking()
    }

    pub fn only_v6(&self) -> Result<bool> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::only_v6 not implemented"))
    }

    pub fn ttl(&self) -> Result<u32> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::ttl not implemented"))
    }

    pub fn read_timeout(&self) -> Result<Option<Duration>> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::read_timeout not implemented"))
    }

    pub fn write_timeout(&self) -> Result<Option<Duration>> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::write_timeout not implemented"))
    }

    pub fn set_broadcast(&self, _broadcast: bool) -> Result<()> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::set_broadcast not implemented"))
    }

    pub fn set_multicast_loop_v4(&self, _multicast_loop_v4: bool) -> Result<()> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::set_multicast_loop_v4 not implemented"))
    }

    pub fn set_multicast_loop_v6(&self, _multicast_loop_v6: bool) -> Result<()> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::set_multicast_loop_v6 not implemented"))
    }

    pub fn set_multicast_ttl_v4(&self, _multicast_ttl_v4: u32) -> Result<()> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::set_multicast_ttl_v4 not implemented"))
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.handle.fd().set_nonblocking(nonblocking)
    }

    pub fn set_only_v6(&self, _only_v6: bool) -> Result<()> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::set_only_v6 not implemented"))
    }

    pub fn set_ttl(&self, _ttl: u32) -> Result<()> {
        unimplemented!();
    }

    pub fn set_read_timeout(&self, _duration_option: Option<Duration>) -> Result<()> {
        unimplemented!();
    }

    pub fn set_write_timeout(&self, _duration_option: Option<Duration>) -> Result<()> {
        unimplemented!();
    }

    pub fn join_multicast_v4(&self, _multiaddr: &Ipv4Addr, _interface: &Ipv4Addr) -> Result<()> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::join_multicast_v4 not implemented"))
    }

    pub fn join_multicast_v6(&self, _multiaddr: &Ipv6Addr, _interface: u32) -> Result<()> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::join_multicast_v6 not implemented"))
    }

    pub fn leave_multicast_v4(&self, _multiaddr: &Ipv4Addr, _interface: &Ipv4Addr) -> Result<()> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::leave_multicast_v4 not implemented"))
    }

    pub fn leave_multicast_v6(&self, _multiaddr: &Ipv6Addr, _interface: u32) -> Result<()> {
        Err(Error::new(ErrorKind::Other, "UdpSocket::leave_multicast_v6 not implemented"))
    }
}

impl AsInner<File> for UdpSocket {
    fn as_inner(&self) -> &File { &self.handle }
}

impl FromInner<File> for UdpSocket {
    fn from_inner(file: File) -> UdpSocket {
        UdpSocket {
            handle: file,
            connected: UnsafeCell::new(false),
        }
    }
}

impl IntoInner<File> for UdpSocket {
    fn into_inner(self) -> File { self.handle }
}
