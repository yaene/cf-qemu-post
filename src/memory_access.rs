use std;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum MemoryAccess {
    Regular(MemRecord),
    Rowclone(RowcloneRecord),
}

#[derive(Debug, Clone)]
pub struct MemRecord {
    pub insn_count: u64,
    pub address: u64,
    pub store: bool,
}

#[derive(Debug, Clone)]
pub struct RowcloneRecord {
    pub insn_count: u64,
    pub from: u64,
    pub to: u64,
}

impl fmt::Display for MemRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.store {
            write!(f, "{},-1,0x{:016x}", self.insn_count, self.address)
        } else {
            write!(f, "{},0x{:016x}", self.insn_count, self.address)
        }
    }
}

impl fmt::Display for RowcloneRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{},0x{:016x},0x{:016x}",
            self.insn_count, self.from, self.to
        )
    }
}

impl fmt::Display for MemoryAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryAccess::Regular(rec) => rec.fmt(f),
            MemoryAccess::Rowclone(rec) => rec.fmt(f),
        }
    }
}

fn parse_hex_addr(addr: &str) -> u64 {
    u64::from_str_radix(addr.trim_start_matches("0x"), 16).expect("Failed to parse hex address")
}

pub enum ParseError {
    InvalidFormat(String),
}

impl FromStr for MemoryAccess {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.trim().split(',').collect();
        let insn_count = parts[0].parse::<u64>().expect("fail");
        if parts.len() == 4 {
            // rowclone
            Ok(MemoryAccess::Rowclone(RowcloneRecord {
                insn_count,
                from: parse_hex_addr(parts[1]),
                to: parse_hex_addr(parts[2]),
            }))
        } else if parts.len() == 3 {
            Ok(MemoryAccess::Regular(MemRecord {
                insn_count,
                address: parse_hex_addr(parts[2]),
                store: true,
            }))
        } else if parts.len() == 2 {
            Ok(MemoryAccess::Regular(MemRecord {
                insn_count,
                address: parse_hex_addr(parts[1]),
                store: false,
            }))
        } else {
            return Err(ParseError::InvalidFormat(
                "Record must have at least two fields".into(),
            ));
        }
    }
}
