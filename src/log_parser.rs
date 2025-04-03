use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::mem;

#[repr(C)]
#[derive(Debug)]
struct _LogRecord {
    insn_count: u64,
    store: u8,
    address: u64,
}

pub struct LogRecord {
    insn_count: u64,
    store: bool,
    address: u64,
}
impl fmt::Debug for LogRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "LogRecord {{insn_count: {}, store: {}, address: 0x{:016x} }}",
            self.insn_count, self.store, self.address
        )
    }
}

pub struct LogParser {
    file: File,
    buffer: Vec<u8>,
}

impl LogParser {
    pub fn new(filename: &str) -> io::Result<Self> {
        File::open(filename).map(|file| LogParser {
            file,
            buffer: vec![0u8; mem::size_of::<_LogRecord>()],
        })
    }
}

impl Iterator for LogParser {
    type Item = io::Result<LogRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.file.read_exact(&mut self.buffer) {
            Ok(_) => {
                let record: _LogRecord =
                    unsafe { std::ptr::read(self.buffer.as_ptr() as *const _) };

                Some(Ok(LogRecord {
                    insn_count: record.insn_count,
                    store: record.store != 0,
                    address: record.address,
                }))
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => None,
            Err(e) => Some(Err(e)),
        }
    }
}
