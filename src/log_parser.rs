use std::cmp;
use std::fmt;
use std::fs::File;
use std::io::SeekFrom;
use std::io::{self, BufReader, Read, Seek};
use std::mem;
use std::str::FromStr;

#[repr(C)]
pub struct LogRecord {
    pub insn_count: u64,
    pub cpu: u8,
    pub store: u8,
    pub size: u8,
    pub address: u64,
}

impl LogRecord {
    pub const SIZE: usize = mem::size_of::<LogRecord>();

    pub fn deserialize(buffer: &mut [u8; Self::SIZE]) -> LogRecord {
        unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const _) }
    }
    pub fn serialize(&self, buffer: &mut [u8; Self::SIZE]) {
        unsafe {
            std::ptr::copy_nonoverlapping(
                self as *const LogRecord as *const u8,
                buffer.as_mut_ptr(),
                Self::SIZE,
            );
        }
    }
}

impl fmt::Display for LogRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},0x{:016x}",
            self.insn_count, self.cpu, self.store, self.size, self.address
        )
    }
}

impl FromStr for LogRecord {
    type Err = Box<dyn std::error::Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.trim().split(',').collect();
        if parts.len() != 5 {
            return Err("Record must have 5 fields".into());
        }

        Ok(LogRecord {
            insn_count: parts[0].parse::<u64>()?,
            cpu: parts[1].parse()?,
            store: parts[2].parse()?,
            size: parts[3].parse()?,
            address: u64::from_str_radix(parts[4].trim_start_matches("0x"), 16)?,
        })
    }
}
impl fmt::Debug for LogRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "LogRecord {{insn_count: {}, cpu: {}, store: {}, size: {}, address: 0x{:016x} }}",
            self.insn_count, self.cpu, self.store, self.size, self.address
        )
    }
}

impl PartialEq for LogRecord {
    fn eq(&self, other: &Self) -> bool {
        self.insn_count == other.insn_count
    }
}

impl Eq for LogRecord {}

impl PartialOrd for LogRecord {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.insn_count.cmp(&other.insn_count))
    }
}
impl Ord for LogRecord {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.insn_count.cmp(&other.insn_count)
    }
}

pub struct LogParser {
    reader: BufReader<File>,
    buffer: [u8; LogRecord::SIZE],
}

impl LogParser {
    pub fn new(filename: &str) -> io::Result<Self> {
        File::open(filename).map(|file| LogParser {
            reader: BufReader::new(file),
            buffer: [0u8; mem::size_of::<LogRecord>()],
        })
    }
    pub fn reset(&mut self) {
        self.reader
            .seek(SeekFrom::Start(0))
            .expect("failed to reset");
    }
}

impl Iterator for LogParser {
    type Item = io::Result<LogRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_exact(&mut self.buffer) {
            Ok(_) => Some(Ok(LogRecord::deserialize(&mut self.buffer))),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => None,
            Err(e) => {
                eprintln!("error: {}", e);
                Some(Err(e))
            }
        }
    }
}
