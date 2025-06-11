use std::{
    io::{BufRead, BufReader, BufWriter, Write},
    str::FromStr,
};

use cf_qemu_post::{
    log_parser::{self},
    memory_access::{MemRecord, MemoryAccess},
};
use clap::Parser;

#[derive(Debug)]
pub struct Cache {
    block_size: usize, // in bytes
    sets: Vec<CacheSet>,
}

#[derive(Debug)]
struct CacheSet {
    // Each cache line stores an optional tag (here, a u64 representing the block address)
    lines: Vec<Option<u64>>,
    // For LRU, we maintain an ordering of indices (least-recently used first)
    lru_order: Vec<usize>,
}

impl CacheSet {
    pub fn new(associativity: usize) -> Self {
        CacheSet {
            lines: vec![None; associativity],
            lru_order: vec![],
        }
    }

    // TODO: [yb] handle rowclone (invalidation) in cache
    /// Returns true if tag hit; false if miss.
    pub fn access(&mut self, tag: u64) -> bool {
        if let Some(pos) = self.lines.iter().position(|&line| line == Some(tag)) {
            // Cache hit: update LRU ordering.
            self.lru_order.retain(|&i| i != pos);
            self.lru_order.push(pos);
            true
        } else {
            // Cache miss: evict the least-recently used line.
            if let Some(free_pos) = self.lines.iter().position(|&line| line.is_none()) {
                // Found a free line, so use it.
                self.lines[free_pos] = Some(tag);
                self.lru_order.push(free_pos);
            } else {
                // No free line: evict the least-recently used line.
                let evict_index = self.lru_order.remove(0);
                self.lines[evict_index] = Some(tag);
                self.lru_order.push(evict_index);
            }
            false
        }
    }
}

impl Cache {
    pub fn new(size: usize, block_size: usize, associativity: usize) -> Self {
        // total number of cache lines = size / block_size
        // number of sets = (size / block_size) / associativity
        let num_lines = size / block_size;
        let num_sets = num_lines / associativity;
        let sets = (0..num_sets)
            .map(|_| CacheSet::new(associativity))
            .collect();
        Cache { block_size, sets }
    }

    /// Simulate an access to the cache.
    /// Returns true if hit, false if miss.
    pub fn access(&mut self, address: u64) -> bool {
        let block_addr = address / (self.block_size as u64);
        let set_index = (block_addr as usize) % self.sets.len();
        // The tag can simply be the block_addr
        self.sets[set_index].access(block_addr)
    }
}

fn parse_rowclone_record(line: &str) -> Result<MemoryAccess, Box<dyn std::error::Error>> {
    MemoryAccess::from_str(line)
}

fn parse_binary_record(line: &str) -> Result<MemoryAccess, Box<dyn std::error::Error>> {
    let access = log_parser::LogRecord::from_str(line)?;
    Ok(MemoryAccess::Regular(MemRecord {
        cpu: access.cpu.into(),
        address: access.address,
        insn_count: access.insn_count,
        store: access.store == 1,
    }))
}

#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    // Whether the input logs are in binary format
    #[arg(short, long, default_value_t = false)]
    binary_in: bool,

    // the number of CPUs
    #[arg(short, long, default_value_t = 8)]
    cpus: usize,
}

fn ramulator_mem_format(rec: &MemRecord, prev_insn_count: &u64) -> String {
    let bubble = rec.insn_count - prev_insn_count;
    if rec.store {
        format!("{}, -1, 0x{:016x}", bubble, rec.address)
    } else {
        format!("{}, 0x{:016x}", bubble, rec.address)
    }
}

fn main() {
    let args = Args::parse();
    let reader = BufReader::new(std::io::stdin());
    let mut writer = BufWriter::new(std::io::stdout());
    let input_parser = if args.binary_in {
        parse_binary_record
    } else {
        parse_rowclone_record
    };

    // Create an L2 cache: 512KB, 64B blocks, 8-way associative.
    // no need for an L1 since we model inclusive cache and only care about
    // memory accesses
    let mut caches: Vec<Cache> = (0..args.cpus)
        .map(|_| Cache::new(512 * 1024, 64, 8))
        .collect();

    let mut lines = reader.lines();
    let mut first = true;
    let mut prev_insn_count = 0;

    while let Some(Ok(line)) = lines.next() {
        if let Ok(rec) = input_parser(&line) {
            if let MemoryAccess::Regular(mem) = rec {
                if first {
                    prev_insn_count = mem.insn_count;
                    first = false;
                }
                if !caches[mem.cpu].access(mem.address) {
                    writeln!(writer, "{}", ramulator_mem_format(&mem, &prev_insn_count));
                    prev_insn_count = mem.insn_count;
                }
            } else {
                // TODO: [yb] handle rowclone in cache
            }
        }
    }
}
