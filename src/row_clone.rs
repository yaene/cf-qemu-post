use crate::log_parser;
use crate::lookahead_iter::LookaheadIterator;
use once_cell::sync::Lazy;
use regex::Regex;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

const COPY_WINDOW: usize = 20;
const COPY_CONFIDENCE_THRESHOLD: usize = 8; // how many bytes worth of matching of loads AND stores we should see 
const COPY_CONFIDENCE_WINDOW: usize = 100; // in the next COPY_CONFIDENCE_WINDOW accesses

// need ongoing copy operations.
// when a new memory access matches a beginning address of a read/write in the current window ->
// check next N memory accesses to decide whether it is the beginning of the copy -> add to ongoing
// memory operations
// check new memory record whether it matches any of the ongoing copy operations, skip it if yes
// if determined to be not a start of a memory region nor belong to an ongoing one just print it as
// a regular load/store
//

struct KernelRecord {
    command: String,
    cpu: u32,
    size: u64,
    operation: char,
    kernel_address: u64,
    user_address: u64,
}

static KERNEL_LOG_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"N=([^,]+),([rw]),(\d+),(\d+),(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+)"#).expect("failed to compile regex")
});

impl fmt::Debug for KernelRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KernelRecord {{command: {}, cpu: {}, size: {}, op: {}, kernel_address: 0x{:016x}, user_address: 0x{:016x} }}",
            self.command,
            self.cpu,
            self.size,
            self.operation,
            self.kernel_address,
            self.user_address
        )
    }
}

struct MemCpy {
    from: u64,
    to: u64,
    size: u64,
    current_from: u64,
    current_to: u64,
}

fn parse_hex_address(hex_str: &str) -> Option<u64> {
    // Remove the "0x" prefix and parse as a base 16 number
    u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).ok()
}

fn parse_kernel_line(line: &str) -> Option<KernelRecord> {
    // Regular expression to capture the CSV-like part of the log line

    if let Some(caps) = KERNEL_LOG_PATTERN.captures(line) {
        Some(KernelRecord {
            command: caps[1].to_string(),
            cpu: caps[3].parse().ok()?,
            size: caps[4].parse().ok()?,
            operation: caps[2].chars().next()?,
            kernel_address: parse_hex_address(&caps[6])?,
            user_address: parse_hex_address(&caps[8])?,
        })
    } else {
        println!("Failed to parse kernel line: {}", line);
        None
    }
}

fn address_in_same_subarray(a: u64, b: u64) -> bool {
    let subarray_mask = 0x7F; // 7 bits
    let subarray_lsb = 21;
    let a_subarray = (a >> subarray_lsb) & subarray_mask;
    let b_subarray = (b >> subarray_lsb) & subarray_mask;

    return a_subarray == b_subarray;
}

fn page_number(address: u64) -> u64 {
    address & !0xFFF
}

fn mem_copy_match(mem_access: &log_parser::LogRecord, copy: &MemCpy) -> bool {
    (copy.from == mem_access.address && mem_access.store == 0)
        || (copy.to == mem_access.address && mem_access.store == 1)
}

fn is_part_of_copy(
    mem_access: &log_parser::LogRecord,
    ongoing_copies: &Vec<MemCpy>,
) -> Option<usize> {
    for (i, copy) in ongoing_copies.iter().enumerate() {
        if mem_copy_match(mem_access, copy) {
            return Some(i);
        }
    }
    None
}

fn copy_done(copy: &MemCpy) -> bool {
    copy.current_to >= copy.to + copy.size
}

fn update_copy(
    ongoing_copies: &mut Vec<MemCpy>,
    copy_idx: usize,
    mem_access: &log_parser::LogRecord,
) {
    // mem_access.size is in shifts (0 = 1 byte, 1 = 2 bytes,...)
    let access_size_bytes = 1 << mem_access.size;
    let ongoing_copy = &mut ongoing_copies[copy_idx];
    if mem_access.store == 1 {
        ongoing_copy.current_to += access_size_bytes;
    } else {
        ongoing_copy.current_from += access_size_bytes;
    }
    if copy_done(&ongoing_copy) {
        ongoing_copies.remove(copy_idx);
    }
}

fn new_ongoing_copy(copy: &KernelRecord) -> Option<MemCpy> {
    match copy.operation {
        'r' => Some(MemCpy {
            from: copy.kernel_address,
            to: copy.user_address,
            size: copy.size,
            current_from: copy.kernel_address,
            current_to: copy.user_address,
        }),
        'w' => Some(MemCpy {
            from: copy.user_address,
            to: copy.kernel_address,
            size: copy.size,
            current_from: copy.user_address,
            current_to: copy.kernel_address,
        }),
        _ => {
            eprintln!("Invalid operation in kernel record!");
            None
        }
    }
}

fn copy_start_confidence(
    copy: &KernelRecord,
    mem_accesses: &mut LookaheadIterator<log_parser::LogParser>,
) -> usize {
    let confidence_window = mem_accesses.peek_n(COPY_CONFIDENCE_WINDOW);
    let copy = new_ongoing_copy(copy).expect("failed to parse");
    let mut tmp_copy = vec![copy];
    eprintln!("checking start!");

    let mut load_bytes: usize = 0;
    let mut store_bytes: usize = 0;
    for access in confidence_window {
        if let Ok(access) = access {
            if let Some(copy_idx) = is_part_of_copy(&access, &tmp_copy) {
                update_copy(&mut tmp_copy, copy_idx, &access);
                if tmp_copy.is_empty() {
                    // all copies found in confidence window
                    return COPY_CONFIDENCE_THRESHOLD + 1;
                }
                if access.store == 1 {
                    store_bytes += access.size as usize;
                } else {
                    load_bytes += access.size as usize;
                }
            }
        }
    }
    return std::cmp::min(load_bytes, store_bytes);
}

fn is_copy_start(
    mem_access: &log_parser::LogRecord,
    copy_window: &Vec<KernelRecord>,
    mem_accesses: &mut LookaheadIterator<log_parser::LogParser>,
) -> Option<usize> {
    for (i, copy) in copy_window.iter().enumerate() {
        let is_start = match copy.operation {
            'r' => {
                // kernel to user copy
                mem_access.store == 0
                    && copy.kernel_address == mem_access.address
                    && copy_start_confidence(&copy, mem_accesses) > COPY_CONFIDENCE_THRESHOLD
            }
            'w' => {
                //user to kernel copy
                mem_access.store == 0
                    && copy.user_address == mem_access.address
                    && copy_start_confidence(&copy, mem_accesses) > COPY_CONFIDENCE_THRESHOLD
            }
            _ => {
                eprintln!("Invalid operation in kernel record!");
                false
            }
        };
        if is_start {
            return Some(i);
        }
    }
    None
}

fn next_kernel_line(lines: &mut impl Iterator<Item = io::Result<String>>) -> Option<KernelRecord> {
    if let Some(Ok(line)) = lines.next() {
        if let Some(record) = parse_kernel_line(&line) {
            return Some(record);
        } else {
            println!("not parsed?");
        }
    }
    None
}

fn push_ongoing_copy(
    ongoing_copies: &mut Vec<MemCpy>,
    copy: &KernelRecord,
    mem_access: &log_parser::LogRecord,
) {
    if let Some(copy) = new_ongoing_copy(copy) {
        println!(
            "{},rowclone,{},{}",
            mem_access.insn_count, copy.from, copy.to
        );
        ongoing_copies.push(copy);
    }
}

fn print_regular_access(mem_access: &log_parser::LogRecord) {

    //    if mem_access.store == 1 {
    //        println!("{},-1,{}", mem_access.insn_count, mem_access.address);
    //    } else {
    //        println!("{},{}", mem_access.insn_count, mem_access.address);
    //    }
}

fn match_copy_to_mem_accesses(
    mem_parser: log_parser::LogParser,
    mut copy_logs: impl Iterator<Item = io::Result<String>>,
    copy_window: &mut Vec<KernelRecord>,
) {
    let mut ongoing_copies: Vec<MemCpy> = vec![];
    let mut mem_accesses = LookaheadIterator::new(mem_parser);

    while let Some(Ok(mem_access)) = mem_accesses.next() {
        if let Some(copy_idx) = is_part_of_copy(&mem_access, &ongoing_copies) {
            update_copy(&mut ongoing_copies, copy_idx, &mem_access);
        } else if let Some(i) = is_copy_start(&mem_access, &copy_window, &mut mem_accesses) {
            eprintln!("New copy!");
            push_ongoing_copy(&mut ongoing_copies, &copy_window[i], &mem_access);
            if let Some(line) = next_kernel_line(&mut copy_logs) {
                copy_window[i] = line;
            } else {
                copy_window.remove(i);
            }
        } else {
            print_regular_access(&mem_access);
        }
    }
}

pub fn add_rowclone_info(parser: log_parser::LogParser, kernel_logfile: &str) -> io::Result<()> {
    let kernel_log = File::open(kernel_logfile)?;
    let reader = BufReader::new(kernel_log);
    let mut lines = reader.lines();
    let mut copy_window = lines
        .by_ref()
        .take(COPY_WINDOW)
        .filter_map(|l| {
            let line = l.expect("Failed to read copy line");
            parse_kernel_line(&line)
        })
        .collect();

    match_copy_to_mem_accesses(parser, lines, &mut copy_window);

    eprintln!("Unmatched copies: {}", copy_window.len());

    Ok(())
}
