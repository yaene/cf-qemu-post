pub mod cache;
pub mod log_parser;
pub mod lookahead_iter;
pub mod row_clone;

use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
};

use crate::cache::Cache;

struct RowcloneRecord {
    insn_count: u64,
    rowclone: bool,
    address1: u64,
    address2: u64,
}

fn parse_rowclone_record(line: &str) -> Option<RowcloneRecord> {
    let parts: Vec<&str> = line.trim().split(',').collect();
    let insn_count = parts[0].parse::<u64>().expect("fail");
    let rowclone = parts.len() == 4;
    let address1 = if parts.len() == 3 {
        0
    } else if rowclone {
        u64::from_str_radix(parts[2].trim_start_matches("0x"), 16).expect("fail")
    } else {
        u64::from_str_radix(parts[1].trim_start_matches("0x"), 16).expect("fail")
    };
    let address2 = if rowclone {
        u64::from_str_radix(parts[3].trim_start_matches("0x"), 16).expect("fail")
    } else if parts.len() == 3 {
        u64::from_str_radix(parts[2].trim_start_matches("0x"), 16).expect("fail")
    } else {
        0
    };

    Some(RowcloneRecord {
        insn_count,
        rowclone,
        address1,
        address2,
    })
}

fn main() {
    //    let parser = log_parser::LogParser::new("logs/firefox/merged.log").unwrap();
    //
    //    row_clone::add_rowclone_info(
    //        parser,
    //        "logs/firefox/kernel.log",
    //        "logs/firefox/rowclone.log",
    //    );
    //
    let reader = BufReader::new(
        File::open("logs/firefox/rowclone.log").expect("cant open rowclone info file"),
    );
    let mut writer = BufWriter::new(
        File::create("logs/firefox/trace.log").expect("cant open trace output file"),
    );

    // TODO: [yb] per CPU cache..
    // Create an L2 cache: 256KB, 64B blocks, 8-way associative.
    let mut l2 = Cache::new(1024, 64, 8);

    let mut prev_inst = 0;

    let mut lines = reader.lines();
    while let Some(Ok(line)) = lines.next() {
        if let Some(rec) = parse_rowclone_record(&line) {
            let bubble_count = if prev_inst > rec.insn_count {
                1
            } else {
                rec.insn_count - prev_inst
            };
            if rec.rowclone {
                writeln!(
                    writer,
                    "rowclone,0x{:016x},0x{:016x}",
                    rec.address1, rec.address2,
                );
            } else if rec.address1 != 0 {
                if !l2.access(rec.address1) {
                    writeln!(writer, "{},0x{:016x}", bubble_count, rec.address1);
                    prev_inst = rec.insn_count;
                }
            } else {
                if !l2.access(rec.address2) {
                    writeln!(writer, "{},-1,0x{:016x}", bubble_count, rec.address2);
                    prev_inst = rec.insn_count;
                }
            }
        }
    }
    // TODO: [yb] make logfile an argument
}
