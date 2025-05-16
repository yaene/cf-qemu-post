use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    fs::{self, File},
    io::{BufWriter, Write},
};

use cf_qemu_post::log_parser;
use clap::Parser;

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

#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    // Whether the input logs are in binary format
    #[arg(short, long)]
    log_dir: String,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut parsers: Vec<log_parser::LogParser> = fs::read_dir(args.log_dir)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.path().into_os_string().into_string().ok())
        .filter_map(|file| log_parser::LogParser::new(&file).ok())
        .collect();

    let mut writer = BufWriter::new(std::io::stdout());
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
        writeln!(writer, "{}", record);
        push_next_record(&mut heap, &mut parsers[i], i);
    }
    Ok(())
}
