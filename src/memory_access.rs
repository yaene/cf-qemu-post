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
    pub cpu: usize,
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
            write!(
                f,
                "{},0,1,{},0x{:016x}",
                self.insn_count, self.cpu, self.address
            )
        } else {
            write!(
                f,
                "{},0,0,{},0x{:016x}",
                self.insn_count, self.cpu, self.address
            )
        }
    }
}

impl fmt::Display for RowcloneRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{},1,0,0x{:016x},0x{:016x}",
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

impl FromStr for MemoryAccess {
    type Err = Box<dyn std::error::Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.trim().split(',').collect();
        if parts.len() != 5 {
            return Err("Record must have at least five fields".into());
        }
        let insn_count = parts[0].parse::<u64>()?;
        if parts[1] == "1" {
            Ok(MemoryAccess::Rowclone(RowcloneRecord {
                insn_count,
                from: parse_hex_addr(parts[3]),
                to: parse_hex_addr(parts[4]),
            }))
        } else {
            Ok(MemoryAccess::Regular(MemRecord {
                insn_count,
                address: parse_hex_addr(parts[4]),
                store: parts[2] == "1",
                cpu: parts[3].parse::<usize>()?,
            }))
        }
    }
}
