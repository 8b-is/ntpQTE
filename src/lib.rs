//! ntpQTE — the constellation's clock daemon in Rust.
//!
//! A hand-welded NTP client (RFC 5905 packet math, no dependencies —
//! readability is freedom: the 48-byte packet is assembled in plain
//! sight), a consensus layer modelled on the elders' council, and a drift
//! journal the ledger can row. The theory shelf: the ntp council-of-clocks
//! note in the vault; the discipline: admissible degradation's own time
//! chapter (a clock that never freezes, only degrades gracefully).
//!
//! The offset math (classic NTP):
//!   offset = ((t1 - t0) + (t2 - t3)) / 2
//!   delay  = (t2 - t1) + (t3 - t0)
//! where t0 = client send, t1 = server receive, t2 = server transmit,
//! t3 = client receive. All in seconds on the client's own clock.

use std::io;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

/// NTP epoch offset: 1900-01-01 to 1970-01-01, in seconds.
pub const NTP_UNIX_OFFSET: u64 = 2_208_988_800;
pub const PACKET_LEN: usize = 48;

/// The 48-byte NTP header, readable field by field (RFC 5905 §6).
#[derive(Debug, Clone, Copy, Default)]
pub struct Packet {
    pub li_vn_mode: u8,       // leap indicator (2) · version (3) · mode (3)
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub ref_id: u32,
    pub ref_ts: u64,
    pub orig_ts: u64,         // t1, echoed back by the server
    pub recv_ts: u64,         // t2
    pub tx_ts: u64,           // t3
}

impl Packet {
    pub fn request(version: u8) -> Packet {
        Packet {
            li_vn_mode: (3 << 3) | (version << 0) | 3, // NTP v3-style: li=0 … actually mode 3 (client) in the low bits
            ..Default::default()
        }
    }

    pub fn to_bytes(&self) -> [u8; PACKET_LEN] {
        let mut b = [0u8; PACKET_LEN];
        b[0] = self.li_vn_mode;
        b[1] = self.stratum;
        b[2] = self.poll as u8;
        b[3] = self.precision as u8;
        b[4..8].copy_from_slice(&self.root_delay.to_be_bytes());
        b[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());
        b[12..16].copy_from_slice(&self.ref_id.to_be_bytes());
        b[16..24].copy_from_slice(&self.ref_ts.to_be_bytes());
        b[24..32].copy_from_slice(&self.orig_ts.to_be_bytes());
        b[32..40].copy_from_slice(&self.recv_ts.to_be_bytes());
        b[40..48].copy_from_slice(&self.tx_ts.to_be_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Packet {
        Packet {
            li_vn_mode: b[0],
            stratum: b[1],
            poll: b[2] as i8,
            precision: b[3] as i8,
            root_delay: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            root_dispersion: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            ref_id: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
            ref_ts: u64::from_be_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
            orig_ts: u64::from_be_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]),
            recv_ts: u64::from_be_bytes([b[32], b[33], b[34], b[35], b[36], b[37], b[38], b[39]]),
            tx_ts: u64::from_be_bytes([b[40], b[41], b[42], b[43], b[44], b[45], b[46], b[47]]),
        }
    }
}

/// NTP timestamp (seconds.fraction in 64-bit fixed point) to seconds since
/// the UNIX epoch, as f64.
pub fn ntp_ts_to_unix_f64(ts: u64) -> f64 {
    let seconds = (ts >> 32) as u64;
    let fraction = (ts & 0xFFFF_FFFF) as u64;
    let frac = fraction as f64 / 4_294_967_296.0;
    if seconds >= NTP_UNIX_OFFSET {
        (seconds - NTP_UNIX_OFFSET) as f64 + frac
    } else {
        let past = NTP_UNIX_OFFSET - seconds;
        -(past as f64 - frac)
    }
}

/// A measured exchange: the four timestamps, t0..t3 in client seconds.
#[derive(Debug, Clone, Copy)]
pub struct Exchange {
    pub t0: f64,
    pub t1: f64,
    pub t2: f64,
    pub t3: f64,
}

impl Exchange {
    /// The classic clock offset, seconds.
    pub fn offset(self) -> f64 {
        ((self.t1 - self.t0) + (self.t2 - self.t3)) / 2.0
    }
    /// The round-trip delay, seconds.
    pub fn delay(self) -> f64 {
        (self.t2 - self.t1) + (self.t3 - self.t0)
    }
}

/// The council consensus: the median of the measured offsets — robust to a
/// single bad peer, the way the geometric mean of the elders is robust to a
/// single loud voice. Signed offsets have no natural geometric mean, so the
/// median is the honest locus.
pub fn consensus_ms(offsets: &[f64]) -> f64 {
    let mut v: Vec<f64> = offsets.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n == 0 {
        return 0.0;
    }
    let median = if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    };
    median
}

fn now_unix_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// One query against the server: returns the consensus offset in
/// milliseconds and the delay in milliseconds.
pub fn query(server: &str, port: u16, timeout: std::time::Duration) -> io::Result<(f64, f64)> {
    let addrs: Vec<_> = (server, port).to_socket_addrs()?.collect();
    let sock = UdpSocket::bind(("0.0.0.0", 0))?;
    sock.set_read_timeout(Some(timeout))?;

    let mut req = Packet::request(4).to_bytes();
    let t0 = now_unix_f64();
    // set the transmit timestamp just before sending
    let tx = unix_to_ntp_ts(t0);
    req[40..48].copy_from_slice(&tx.to_be_bytes());
    sock.send_to(&req, &addrs[0])?;

    let mut buf = [0u8; PACKET_LEN];
    let (n, _) = sock.recv_from(&mut buf)?;
    let t3 = now_unix_f64();
    let pkt = Packet::from_bytes(&buf[..n]);

    let t1 = ntp_ts_to_unix_f64(pkt.recv_ts);
    let t2 = ntp_ts_to_unix_f64(pkt.tx_ts);
    let ex = Exchange { t0, t1, t2, t3 };
    Ok((ex.offset() * 1000.0, ex.delay() * 1000.0))
}

/// seconds-since-unix → NTP fixed-point timestamp (guard: t0 from this
/// process is assumed to be sanely post-1970).
pub fn unix_to_ntp_ts(t: f64) -> u64 {
    let secs = if t >= 0.0 { (t as u64).saturating_add(NTP_UNIX_OFFSET) } else { NTP_UNIX_OFFSET };
    let frac = (t.fract() * 4_294_967_296.0).round() as u64 & 0xFFFF_FFFF;
    (secs << 32) | frac
}

/// The drift journal: one append-only row per query, in the ledger's
/// grammar. The file is the fleet's own clock-record (the NOT-resettable
/// audits, Rust edition).
pub fn journal_row(path: &std::path::Path, server: &str, offset_ms: f64, delay_ms: f64) -> io::Result<()> {
    use std::io::Write;
    let ts = now_unix_f64();
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(
        f,
        "{}",
        serde_json_free_row(ts, server, offset_ms, delay_ms)
    )?;
    Ok(())
}

/// No-dependency JSON row (std only): a tiny, predictable line.
fn serde_json_free_row(ts: f64, server: &str, offset_ms: f64, delay_ms: f64) -> String {
    format!(
        "{{\"ts\":{:.3},\"server\":\"{}\",\"offset_ms\":{:.2},\"delay_ms\":{:.2}}}",
        ts, server, offset_ms, delay_ms
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: u64, frac: u32) -> u64 {
        (secs << 32) | (frac as u64 & 0xFFFF_FFFF)
    }

    #[test]
    fn packet_roundtrip() {
        let p = Packet {
            li_vn_mode: 0x23, // version 4, mode 3 (client)
            stratum: 2, poll: 6, precision: -6,
            root_delay: 0x0000_0100,
            root_dispersion: 0x0000_0200,
            ref_id: 0x0102_0304,
            ref_ts: ts(1, 2),
            orig_ts: ts(3, 4),
            recv_ts: ts(5, 6),
            tx_ts: ts(7, 8),
        };
        let bytes = p.to_bytes();
        let back = Packet::from_bytes(&bytes);
        assert_eq!(back.li_vn_mode, 0x23);
        assert_eq!(back.stratum, 2);
        assert_eq!(back.orig_ts, ts(3, 4));
        assert_eq!(back.tx_ts, ts(7, 8));
        assert_eq!(bytes.len(), PACKET_LEN);
    }

    #[test]
    fn ntp_epoch_boundary() {
        assert_eq!(ntp_ts_to_unix_f64(ts(NTP_UNIX_OFFSET, 0)), 0.0);
        // one second past the unix epoch
        assert!((ntp_ts_to_unix_f64(ts(NTP_UNIX_OFFSET + 1, 0)) - 1.0).abs() < 1e-9);
        // half a second, fraction 0x8000_0000
        assert!((ntp_ts_to_unix_f64(ts(NTP_UNIX_OFFSET, 0x8000_0000)) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn offset_math_is_classic() {
        // t0=0, t1=4, t2=6, t3=10: offset = ((4-0)+(6-10))/2 = 0
        let ex = Exchange { t0: 0.0, t1: 4.0, t2: 6.0, t3: 10.0 };
        assert!((ex.offset() * 1000.0).abs() < 1e-9);
        assert!((ex.delay() - 12.0).abs() < 1e-9);
        // a +20ms displacement: server timestamps shifted
        let ex2 = Exchange { t0: 0.0, t1: 4.02, t2: 6.02, t3: 10.0 };
        assert!((ex2.offset() * 1000.0 - 20.0).abs() < 1e-6);
    }

    #[test]
    fn consensus_is_the_median() {
        assert!((consensus_ms(&[10.0, 20.0, 30.0]) - 20.0).abs() < 1e-9);
        assert!((consensus_ms(&[10.0, 20.0, 30.0, 40.0]) - 25.0).abs() < 1e-9);
        assert!((consensus_ms(&[1000.0, -5.0, 3.0]) - 3.0).abs() < 1e-9);
        assert!((consensus_ms(&[])).abs() < 1e-9);
    }

    #[test]
    fn journal_rows_are_valid_json_lines() {
        let path = std::path::Path::new("/tmp/ntpqte-test-journal.jsonl");
        journal_row(path, "time.apple.com", 21.9, 15.8).unwrap();
        let line = std::fs::read_to_string(path).unwrap().trim().to_string();
        assert!(line.starts_with("{\"ts\":"));
        assert!(line.contains("\"server\":\"time.apple.com\""));
        assert!(line.contains("\"offset_ms\":21.90"));
        let _ = std::fs::remove_file(path);
    }
}