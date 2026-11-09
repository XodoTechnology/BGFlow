//! Big-endian cursor over a byte slice. All NetFlow/IPFIX/sFlow multi-byte
//! integers are network byte order.

use anyhow::{bail, Result};

#[derive(Debug)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn slice(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            bail!("cursor overflow: need {} have {}", n, self.remaining());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Take bytes without advancing (peek).
    pub fn peek(&self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            bail!("cursor peek overflow");
        }
        Ok(&self.buf[self.pos..self.pos + n])
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.slice(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.slice(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.slice(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.slice(8)?.try_into().unwrap()))
    }

    pub fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_be_bytes(self.slice(16)?.try_into().unwrap()))
    }

    /// Unsigned big-endian integer of arbitrary byte length (<=16).
    /// Used for IPFIX counters which may be encoded in 1-8 bytes.
    pub fn uint_be(&mut self, len: usize) -> Result<u128> {
        if len == 0 || len > 16 {
            bail!("bad uint length {}", len);
        }
        let b = self.slice(len)?;
        let mut buf = [0u8; 16];
        buf[16 - len..].copy_from_slice(b);
        Ok(u128::from_be_bytes(buf))
    }

    /// Skip n bytes (padding etc).
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.slice(n).map(|_| ())
    }
}
