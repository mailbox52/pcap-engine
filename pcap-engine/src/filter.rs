//! A small display-filter language evaluated over the index columns.
//!
//! ```text
//! tcp                    protocol: tcp udp dns icmp icmpv6 arp ipv4 ipv6 other
//! syn  fin  rst  psh  ack  urg         TCP flag set
//! 10.0.0.4               any address match (source or destination)
//! 10.0.0.0/24  2001:db8::/32           address ranges
//! host X   src X   dst X               address, either side / source / destination
//! port 443   sport 443   dport 443     TCP/UDP ports
//! len > 1000                           packet length on the wire (> >= < <= = ==)
//! not X   X and Y   X or Y   ( ... )   also ! && ||
//! ```
//! `not` binds tighter than `and`, which binds tighter than `or`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::core::PacketIndex;
use crate::dissect::{PROTO_ARP, PROTO_DNS, PROTO_ICMP, PROTO_ICMPV6, PROTO_OTHER, PROTO_TCP, PROTO_UDP};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterError {
    pub message: String,
    /// Byte offset into the query where the problem starts.
    pub position: usize,
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (at character {})", self.message, self.position + 1)
    }
}

impl std::error::Error for FilterError {}

fn err<T>(message: impl Into<String>, position: usize) -> Result<T, FilterError> {
    Err(FilterError {
        message: message.into(),
        position,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmp {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Src,
    Dst,
    Either,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtoTest {
    Exact(u8),
    /// UDP, including DNS (which is UDP on port 53).
    Udp,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    version: u8,
    bytes: [u8; 16],
    prefix_bits: u8,
}

/// A parsed filter, opaque outside this module.
pub struct Filter(Expr);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    Proto(ProtoTest),
    Flag(u16),
    Addr(Side, Cidr),
    Port(Side, u16),
    Len(Cmp, u32),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

// ---------------------------------------------------------------- lexer

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    LParen,
    RParen,
    Not,
    And,
    Or,
    Op(Cmp),
}

fn lex(q: &str) -> Result<Vec<(Tok, usize)>, FilterError> {
    let mut out = Vec::new();
    let chars: Vec<(usize, char)> = q.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        let (pos, c) = chars[i];
        let next = chars.get(i + 1).map(|x| x.1);
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                out.push((Tok::LParen, pos));
                i += 1;
            }
            ')' => {
                out.push((Tok::RParen, pos));
                i += 1;
            }
            '!' => {
                out.push((Tok::Not, pos));
                i += 1;
            }
            '&' if next == Some('&') => {
                out.push((Tok::And, pos));
                i += 2;
            }
            '|' if next == Some('|') => {
                out.push((Tok::Or, pos));
                i += 2;
            }
            '>' | '<' => {
                let with_eq = next == Some('=');
                let op = match (c, with_eq) {
                    ('>', false) => Cmp::Gt,
                    ('>', true) => Cmp::Ge,
                    ('<', false) => Cmp::Lt,
                    _ => Cmp::Le,
                };
                out.push((Tok::Op(op), pos));
                i += if with_eq { 2 } else { 1 };
            }
            '=' => {
                out.push((Tok::Op(Cmp::Eq), pos));
                i += if next == Some('=') { 2 } else { 1 };
            }
            c if c.is_alphanumeric() || matches!(c, '.' | ':' | '/' | '_') => {
                let start = pos;
                let mut word = String::new();
                while i < chars.len() {
                    let ch = chars[i].1;
                    if ch.is_alphanumeric() || matches!(ch, '.' | ':' | '/' | '_') {
                        word.push(ch);
                        i += 1;
                    } else {
                        break;
                    }
                }
                let tok = match word.to_ascii_lowercase().as_str() {
                    "and" => Tok::And,
                    "or" => Tok::Or,
                    "not" => Tok::Not,
                    _ => Tok::Word(word),
                };
                out.push((tok, start));
            }
            other => return err(format!("Unexpected character '{other}'"), pos),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- parser

struct Parser {
    toks: Vec<(Tok, usize)>,
    at: usize,
    end: usize,
}

impl Parser {
    fn peek(&self) -> Option<&(Tok, usize)> {
        self.toks.get(self.at)
    }

    fn bump(&mut self) -> Option<(Tok, usize)> {
        let t = self.toks.get(self.at).cloned();
        if t.is_some() {
            self.at += 1;
        }
        t
    }

    fn or(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.and()?;
        while matches!(self.peek(), Some((Tok::Or, _))) {
            self.bump();
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.unary()?;
        while matches!(self.peek(), Some((Tok::And, _))) {
            self.bump();
            let right = self.unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, FilterError> {
        if matches!(self.peek(), Some((Tok::Not, _))) {
            self.bump();
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, FilterError> {
        let at_end = self.end;
        let Some((tok, pos)) = self.bump() else {
            return err("The filter ends too early; expected a term", at_end);
        };
        match tok {
            Tok::LParen => {
                let inner = self.or()?;
                match self.bump() {
                    Some((Tok::RParen, _)) => Ok(inner),
                    Some((_, p)) => err("Expected ')'", p),
                    None => err("Missing closing ')'", self.end),
                }
            }
            Tok::Word(w) => self.atom(&w, pos),
            Tok::RParen => err("Unexpected ')'", pos),
            Tok::And | Tok::Or => err("Expected a term before 'and' / 'or'", pos),
            Tok::Op(_) => err("Unexpected comparison operator", pos),
            Tok::Not => err("Unexpected 'not'", pos),
        }
    }

    fn word_after(&mut self, keyword: &str, kw_pos: usize, what: &str) -> Result<(String, usize), FilterError> {
        match self.bump() {
            Some((Tok::Word(w), p)) => Ok((w, p)),
            Some((_, p)) => err(format!("Expected {what} after '{keyword}'"), p),
            None => err(format!("Expected {what} after '{keyword}'"), self.end.max(kw_pos)),
        }
    }

    fn atom(&mut self, word: &str, pos: usize) -> Result<Expr, FilterError> {
        let lower = word.to_ascii_lowercase();
        let proto = |t: ProtoTest| Ok(Expr::Proto(t));
        match lower.as_str() {
            "tcp" => proto(ProtoTest::Exact(PROTO_TCP)),
            "udp" => proto(ProtoTest::Udp),
            "dns" => proto(ProtoTest::Exact(PROTO_DNS)),
            "icmp" => proto(ProtoTest::Exact(PROTO_ICMP)),
            "icmpv6" => proto(ProtoTest::Exact(PROTO_ICMPV6)),
            "arp" => proto(ProtoTest::Exact(PROTO_ARP)),
            "other" => proto(ProtoTest::Exact(PROTO_OTHER)),
            "ipv4" => proto(ProtoTest::Ipv4),
            "ipv6" => proto(ProtoTest::Ipv6),
            "fin" => Ok(Expr::Flag(0x01)),
            "syn" => Ok(Expr::Flag(0x02)),
            "rst" => Ok(Expr::Flag(0x04)),
            "psh" => Ok(Expr::Flag(0x08)),
            "ack" => Ok(Expr::Flag(0x10)),
            "urg" => Ok(Expr::Flag(0x20)),
            "port" | "sport" | "dport" => {
                let side = match lower.as_str() {
                    "sport" => Side::Src,
                    "dport" => Side::Dst,
                    _ => Side::Either,
                };
                let (w, p) = self.word_after(&lower, pos, "a port number")?;
                match w.parse::<u16>() {
                    Ok(n) => Ok(Expr::Port(side, n)),
                    Err(_) => err(format!("'{w}' is not a port number (0 to 65535)"), p),
                }
            }
            "len" | "length" => {
                let op = match self.bump() {
                    Some((Tok::Op(op), _)) => op,
                    Some((_, p)) => return err("Expected a comparison such as > or < after 'len'", p),
                    None => return err("Expected a comparison such as > or < after 'len'", self.end),
                };
                let (w, p) = self.word_after("len", pos, "a number")?;
                match w.parse::<u32>() {
                    Ok(n) => Ok(Expr::Len(op, n)),
                    Err(_) => err(format!("'{w}' is not a number"), p),
                }
            }
            "host" | "src" | "dst" => {
                let side = match lower.as_str() {
                    "src" => Side::Src,
                    "dst" => Side::Dst,
                    _ => Side::Either,
                };
                let (w, p) = self.word_after(&lower, pos, "an address")?;
                Ok(Expr::Addr(side, parse_cidr(&w, p)?))
            }
            _ if word.contains('.') || word.contains(':') => Ok(Expr::Addr(Side::Either, parse_cidr(word, pos)?)),
            _ => err(
                format!("Unknown term '{word}'. Try tcp, udp, dns, icmp, arp, ipv4, ipv6, an address, port N, or len > N"),
                pos,
            ),
        }
    }
}

fn parse_cidr(word: &str, pos: usize) -> Result<Cidr, FilterError> {
    let (addr, prefix) = match word.split_once('/') {
        Some((a, p)) => match p.parse::<u8>() {
            Ok(n) => (a, Some(n)),
            Err(_) => return err(format!("'{p}' is not a valid prefix length"), pos),
        },
        None => (word, None),
    };
    let mut bytes = [0u8; 16];
    if let Ok(v4) = Ipv4Addr::from_str(addr) {
        let bits = prefix.unwrap_or(32);
        if bits > 32 {
            return err("An IPv4 prefix length is at most 32", pos);
        }
        bytes[..4].copy_from_slice(&v4.octets());
        return Ok(Cidr {
            version: 4,
            bytes,
            prefix_bits: bits,
        });
    }
    if addr.contains(':') {
        if let Ok(v6) = Ipv6Addr::from_str(addr) {
            let bits = prefix.unwrap_or(128);
            if bits > 128 {
                return err("An IPv6 prefix length is at most 128", pos);
            }
            return Ok(Cidr {
                version: 6,
                bytes: v6.octets(),
                prefix_bits: bits,
            });
        }
    }
    err(format!("'{word}' is not a valid IPv4 or IPv6 address"), pos)
}

fn parse_filter(query: &str) -> Result<Option<Filter>, FilterError> {
    let toks = lex(query)?;
    if toks.is_empty() {
        return Ok(None);
    }
    let mut p = Parser {
        toks,
        at: 0,
        end: query.len(),
    };
    let expr = p.or()?;
    if let Some((_, pos)) = p.peek() {
        return err("Unexpected text; combine terms with 'and' or 'or'", *pos);
    }
    Ok(Some(Filter(expr)))
}

// ------------------------------------------------------------- evaluation

fn prefix_matches(packet_addr: &[u8], c: &Cidr) -> bool {
    let bits = usize::from(c.prefix_bits);
    let full = bits / 8;
    if packet_addr[..full] != c.bytes[..full] {
        return false;
    }
    let rem = bits % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    packet_addr[full] & mask == c.bytes[full] & mask
}

fn has_ports(proto: u8) -> bool {
    matches!(proto, PROTO_TCP | PROTO_UDP | PROTO_DNS)
}

fn compare(op: Cmp, left: u32, right: u32) -> bool {
    match op {
        Cmp::Gt => left > right,
        Cmp::Ge => left >= right,
        Cmp::Lt => left < right,
        Cmp::Le => left <= right,
        Cmp::Eq => left == right,
    }
}

fn eval(e: &Expr, idx: &PacketIndex, i: usize) -> bool {
    match e {
        Expr::Proto(t) => {
            let proto = idx.proto[i];
            match t {
                ProtoTest::Exact(p) => proto == *p,
                ProtoTest::Udp => proto == PROTO_UDP || proto == PROTO_DNS,
                // ARP carries IPv4 addresses but is not an IPv4 packet.
                ProtoTest::Ipv4 => idx.ip_version[i] == 4 && proto != PROTO_ARP,
                ProtoTest::Ipv6 => idx.ip_version[i] == 6,
            }
        }
        Expr::Flag(bit) => idx.proto[i] == PROTO_TCP && idx.detail[i] & bit != 0,
        Expr::Addr(side, c) => {
            if idx.ip_version[i] != c.version {
                return false;
            }
            let src = &idx.addr[i * 32..i * 32 + 16];
            let dst = &idx.addr[i * 32 + 16..i * 32 + 32];
            match side {
                Side::Src => prefix_matches(src, c),
                Side::Dst => prefix_matches(dst, c),
                Side::Either => prefix_matches(src, c) || prefix_matches(dst, c),
            }
        }
        Expr::Port(side, n) => {
            has_ports(idx.proto[i])
                && match side {
                    Side::Src => idx.src_port[i] == *n,
                    Side::Dst => idx.dst_port[i] == *n,
                    Side::Either => idx.src_port[i] == *n || idx.dst_port[i] == *n,
                }
        }
        Expr::Len(op, n) => compare(*op, idx.orig_len[i], *n),
        Expr::Not(inner) => !eval(inner, idx, i),
        Expr::And(a, b) => eval(a, idx, i) && eval(b, idx, i),
        Expr::Or(a, b) => eval(a, idx, i) || eval(b, idx, i),
    }
}

/// Indexes of the packets matching `query`, in order. An empty query matches everything.
pub fn filter(idx: &PacketIndex, query: &str) -> Result<Vec<u32>, FilterError> {
    let n = idx.len();
    match parse_filter(query)? {
        None => Ok((0..n as u32).collect()),
        Some(Filter(expr)) => Ok((0..n).filter(|&i| eval(&expr, idx, i)).map(|i| i as u32).collect()),
    }
}
