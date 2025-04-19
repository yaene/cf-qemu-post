use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    fs::File,
    io::{BufWriter, Write},
};

use cf_qemu_post::log_parser;

const CPUS: usize = 8;

fn push_next_record(
    heap: &mut BinaryHeap<Reverse<(log_parser::LogRecord, usize)>>,
    parser: &mut log_parser::LogParser,
    i: usize,
) {
    if let Some(Ok(record)) = parser.next() {
        heap.push(Reverse((record, i)));
    }
}

fn main() {
    let mut parsers: Vec<log_parser::LogParser> = Vec::new();
    for c in 0..CPUS {
        let filename = format!("logs/firefox/log.txt.{c}");
        parsers.push(
            log_parser::LogParser::new(&filename)
                .expect(format!("Failed to open log file {filename}").as_str()),
        );
    }

    let output_file = File::create("logs/firefox/merged.log").expect("cant open output file");

    let mut writer = BufWriter::new(output_file);
    let mut output_buf = [0u8; log_parser::LogRecord::SIZE];
    let mut prev_insn_count = 0;

    let mut heap: BinaryHeap<Reverse<(log_parser::LogRecord, usize)>> = BinaryHeap::new();
    for (i, parser) in parsers.iter_mut().enumerate() {
        push_next_record(&mut heap, parser, i);
    }
    while let Some(Reverse((record, i))) = heap.pop() {
        if prev_insn_count > record.insn_count {
            eprintln!("Warning: instruction count out of order!");
        }
        prev_insn_count = record.insn_count;
        record.serialize(&mut output_buf);
        writer
            .write_all(&output_buf)
            .expect("Failed to write to output file");
        push_next_record(&mut heap, &mut parsers[i], i);
    }
}
