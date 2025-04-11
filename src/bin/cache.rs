use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
};

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
            lru_order: (0..associativity).collect(),
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
