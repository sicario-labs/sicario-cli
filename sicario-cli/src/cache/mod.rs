//! Incremental scan cache module — content-addressable scan result cache.

pub mod scan_cache;

pub use scan_cache::{CachedFinding, CachedScanResult, CacheStats, ScanCache, ScanCaching};
