pub mod cache;
pub mod log_parser;

use crate::cache::Cache;

fn main() {
    // Create an L2 cache: 256KB, 64B blocks, 8-way associative.
    let mut l2 = Cache::new(512, 64, 8);

    // Example memory addresses (in bytes) to access.
    let addresses = vec![
        0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000, 0x1000, 0x2000,
        0x3000, 0x5000,
    ];

    for addr in addresses {
        // If L1 misses, try L2.
        let hit_l2 = l2.access(addr);

        println!("Access 0x{:x}:  L2 hit: {}", addr, hit_l2);
    }

    let parser = log_parser::LogParser::new("logs/firefox/exec.log.0").unwrap();
    for record in parser.take(5) {
        println!("{:?}", record);
    }
}
