//! Incremental scan cache module — content-addressable scan result cache.

pub mod scan_cache;

pub use scan_cache::{CacheStats, CachedFinding, CachedScanResult, ScanCache, ScanCaching};
