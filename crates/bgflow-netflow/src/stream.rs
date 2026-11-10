//! TCP stream framing for IPFIX (RFC 7011 §6 transport considerations).
//!
//! TCP has no datagram boundaries, so we reassemble IPFIX Messages from the
//! byte stream. Each Message starts with a 16-byte header whose first u16 is
//! the version (10). A Set ID can never be 10 (valid IDs are 2, 3, >=256, or
//! enterprise-flagged >=0x8000), so a u16==10 at a message boundary reliably
//! indicates a new header. Messages are length-prefixed in the header, so we
//! buffer until a complete message is available, then decode it with the
//! normal IPFIX parser.
//!
//! NetFlow v9 over TCP is not supported (its header carries no message
//! length, making boundaries ambiguous); sFlow is UDP-only per RFC 3176.

use crate::ipfix;
use crate::netflow_v9::{DomainTemplates, TemplateKey};
use bgflow_types::FlowRecord;
use std::collections::HashMap;
use std::net::IpAddr;

/// Max buffered bytes before we declare the stream corrupt and resync.
const MAX_BUF: usize = 4 * 1024 * 1024;
/// IPFIX message header size.
const HDR: usize = 16;

pub struct IpfixTcpDecoder {
    exporter: IpAddr,
    templates: HashMap<TemplateKey, DomainTemplates>,
    boots: ipfix::BootEstimator,
    buf: Vec<u8>,
}

impl IpfixTcpDecoder {
    pub fn new(exporter: IpAddr) -> Self {
        IpfixTcpDecoder {
            exporter,
            templates: HashMap::new(),
            boots: ipfix::BootEstimator::default(),
            buf: Vec::with_capacity(64 * 1024),
        }
    }

    /// Feed received bytes; returns any complete flow records decoded.
    pub fn feed(&mut self, data: &[u8], now_ms: u64) -> Vec<FlowRecord> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();

        loop {
            if self.buf.len() < 4 {
                break;
            }
            let v = u16::from_be_bytes([self.buf[0], self.buf[1]]);
            if v != 10 {
                // Not at a header: try to resync to the next plausible header.
                if !self.resync() {
                    break;
                }
                continue;
            }
            if self.buf.len() < HDR {
                break; // wait for the rest of the header
            }
            let msg_len = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize;
            if msg_len < HDR || msg_len > 65535 {
                // Bogus length — drop one byte and resync.
                self.buf.drain(..1);
                continue;
            }
            if self.buf.len() < msg_len {
                break; // wait for the full message
            }
            let msg: Vec<u8> = self.buf.drain(..msg_len).collect();
            out.extend(ipfix::parse(
                &msg,
                self.exporter,
                &mut self.templates,
                &mut self.boots,
                now_ms,
            ));
        }

        if self.buf.len() > MAX_BUF {
            tracing::warn!(
                "ipfix tcp {}: buffer overflow ({} bytes), clearing",
                self.exporter,
                self.buf.len()
            );
            self.buf.clear();
        }
        out
    }

    /// Drop bytes until a plausible IPFIX header (version=10, sane length)
    /// is at the front. Returns true if resynced, false if none found yet.
    fn resync(&mut self) -> bool {
        let n = self.buf.len();
        let mut i = 1usize;
        while i + HDR <= n {
            if self.buf[i] == 0 && self.buf[i + 1] == 10 {
                let len = u16::from_be_bytes([self.buf[i + 2], self.buf[i + 3]]) as usize;
                if (HDR..=65535).contains(&len) {
                    self.buf.drain(..i);
                    return true;
                }
            }
            i += 1;
        }
        // No header in sight: keep last few bytes (could be a partial header)
        // but bound memory.
        if n > 1024 {
            self.buf.drain(..n - 64);
        }
        false
    }
}
