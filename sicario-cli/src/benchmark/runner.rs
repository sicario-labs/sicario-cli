//! Performance benchmarking — timing, memory, per-language breakdown.

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::engine::sast_engine::SastEngine;
use crate::parser::Language;

// ── Data models ──────────────────────────────────────────────────────────────

/// Result of a single benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub timestamp: chrono::DateTime<Utc>,
    pub total_wall_clock_ms: u64,
    pub files_per_second: f64,
    pub rules_per_second: f64,
    pub peak_memory_bytes: u64,
    pub files_scanned: usize,
    pub rules_loaded: usize,
    pub findings_count: usize,
    pub per_language: HashMap<String, LanguageBenchmark>,
}

/// Per-language breakdown within a benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageBenchmark {
    pub files_scanned: usize,
    pub scan_time_ms: u64,
    pub rules_evaluated: usize,
}

/// Comparison between two benchmark runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkComparison {
    pub baseline: BenchmarkResult,
    pub current: BenchmarkResult,
    pub wall_clock_delta_pct: f64,
    pub files_per_second_delta_pct: f64,
    pub memory_delta_pct: f64,
}

// ── BenchmarkRunner ──────────────────────────────────────────────────────────

pub struct BenchmarkRunner {
    project_root: PathBuf,
    rule_paths: Vec<PathBuf>,
}

impl BenchmarkRunner {
    pub fn new(project_root: &Path, rule_paths: Vec<PathBuf>) -> Self {
        Self {
            project_root: project_root.to_path_buf(),
            rule_paths,
        }
    }

    /// Run the full benchmark: warm-up + measured run.
    pub fn run(&self, scan_dir: &Path) -> Result<BenchmarkResult> {
        // Warm-up: throwaway run to prime OS caches
        eprintln!("[benchmark] warm-up run…");
        let _ = self.execute_scan(scan_dir);

        // Measured run
        eprintln!("[benchmark] measured run…");
        let mem_before = Self::current_process_memory();
        let start = Instant::now();

        let (files_scanned, findings_count, per_language) = self.execute_scan(scan_dir)?;

        let elapsed = start.elapsed();
        let total_ms = elapsed.as_millis() as u64;
        let mem_after = Self::current_process_memory();
        let peak_memory = mem_after.saturating_sub(mem_before).max(mem_after);

        let rules_loaded = self.count_rules()?;
        let files_per_second = if total_ms > 0 {
            files_scanned as f64 / (total_ms as f64 / 1000.0)
        } else {
            files_scanned as f64
        };
        let rules_per_second = if total_ms > 0 {
            (rules_loaded as f64 * files_scanned as f64) / (total_ms as f64 / 1000.0)
        } else {
            rules_loaded as f64 * files_scanned as f64
        };

        let result = BenchmarkResult {
            timestamp: Utc::now(),
            total_wall_clock_ms: total_ms,
            files_per_second,
            rules_per_second,
            peak_memory_bytes: peak_memory,
            files_scanned,
            rules_loaded,
            findings_count,
            per_language,
        };

        // Auto-persist
        self.save(&result)?;

        Ok(result)
    }

    /// Persist a benchmark result to `.sicario/benchmarks/`.
    pub fn save(&self, result: &BenchmarkResult) -> Result<PathBuf> {
        let benchmarks_dir = self.project_root.join(".sicario").join("benchmarks");
        fs::create_dir_all(&benchmarks_dir)?;

        let filename = format!(
            "benchmark-{}.json",
            result.timestamp.format("%Y%m%dT%H%M%S")
        );
        let path = benchmarks_dir.join(&filename);
        let json = serde_json::to_string_pretty(result)?;
        fs::write(&path, json)?;
        Ok(path)
    }

    /// Load the most recent saved benchmark for comparison.
    pub fn load_latest_baseline(&self) -> Result<Option<BenchmarkResult>> {
        let benchmarks_dir = self.project_root.join(".sicario").join("benchmarks");
        if !benchmarks_dir.exists() {
            return Ok(None);
        }
        let mut entries: Vec<PathBuf> = fs::read_dir(&benchmarks_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect();
        entries.sort();
        match entries.last() {
            Some(path) => {
                let content = fs::read_to_string(path)?;
                let result: BenchmarkResult = serde_json::from_str(&content)
                    .with_context(|| format!("Failed to parse baseline: {:?}", path))?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Load a specific baseline by tag (filename stem).
    pub fn load_baseline(&self, tag: &str) -> Result<Option<BenchmarkResult>> {
        let benchmarks_dir = self.project_root.join(".sicario").join("benchmarks");
        let candidates = [
            benchmarks_dir.join(tag),
            benchmarks_dir.join(format!("{}.json", tag)),
        ];
        for path in &candidates {
            if path.exists() {
                let content = fs::read_to_string(path)?;
                let result: BenchmarkResult = serde_json::from_str(&content)?;
                return Ok(Some(result));
            }
        }
        Ok(None)
    }

    /// Compare current result against a baseline.
    pub fn compare(baseline: &BenchmarkResult, current: &BenchmarkResult) -> BenchmarkComparison {
        let wall_clock_delta_pct = if baseline.total_wall_clock_ms > 0 {
            ((current.total_wall_clock_ms as f64 - baseline.total_wall_clock_ms as f64)
                / baseline.total_wall_clock_ms as f64)
                * 100.0
        } else {
            0.0
        };
        let files_per_second_delta_pct = if baseline.files_per_second > 0.0 {
            ((current.files_per_second - baseline.files_per_second) / baseline.files_per_second)
                * 100.0
        } else {
            0.0
        };
        let memory_delta_pct = if baseline.peak_memory_bytes > 0 {
            ((current.peak_memory_bytes as f64 - baseline.peak_memory_bytes as f64)
                / baseline.peak_memory_bytes as f64)
                * 100.0
        } else {
            0.0
        };
        BenchmarkComparison {
            baseline: baseline.clone(),
            current: current.clone(),
            wall_clock_delta_pct,
            files_per_second_delta_pct,
            memory_delta_pct,
        }
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn execute_scan(
        &self,
        scan_dir: &Path,
    ) -> Result<(usize, usize, HashMap<String, LanguageBenchmark>)> {
        let mut engine = SastEngine::new(&self.project_root)?;
        for rule_path in &self.rule_paths {
            if rule_path.exists() {
                let _ = engine.load_rules(rule_path);
            }
        }

        let files = Self::collect_scannable_files(scan_dir)?;
        let total_files = files.len();
        let rules_loaded = engine.get_rules().len();

        // Group by language
        let mut by_language: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for file in &files {
            if let Some(lang) = Language::from_path(file) {
                by_language
                    .entry(format!("{:?}", lang))
                    .or_default()
                    .push(file.clone());
            }
        }

        let mut per_language = HashMap::new();
        let mut total_findings = 0;

        for (lang_name, lang_files) in &by_language {
            let lang_start = Instant::now();
            let mut lang_findings = 0;
            for file in lang_files {
                if let Ok(vulns) = engine.scan_file(file) {
                    lang_findings += vulns.len();
                }
            }
            let lang_elapsed = lang_start.elapsed().as_millis() as u64;
            total_findings += lang_findings;
            per_language.insert(
                lang_name.clone(),
                LanguageBenchmark {
                    files_scanned: lang_files.len(),
                    scan_time_ms: lang_elapsed,
                    rules_evaluated: rules_loaded,
                },
            );
        }

        Ok((total_files, total_findings, per_language))
    }

    fn count_rules(&self) -> Result<usize> {
        let mut engine = SastEngine::new(&self.project_root)?;
        for rule_path in &self.rule_paths {
            if rule_path.exists() {
                let _ = engine.load_rules(rule_path);
            }
        }
        Ok(engine.get_rules().len())
    }

    fn collect_scannable_files(dir: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        if dir.exists() {
            Self::walk_dir(dir, &mut files)?;
        }
        Ok(files)
    }

    fn walk_dir(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name.starts_with('.') || name == "node_modules" || name == "target" {
                    continue;
                }
                Self::walk_dir(&path, files)?;
            } else if Language::from_path(&path).is_some() {
                files.push(path);
            }
        }
        Ok(())
    }

    fn current_process_memory() -> u64 {
        use sysinfo::{Pid, System};
        let pid = std::process::id() as usize;
        let mut sys = System::new();
        sys.refresh_process(Pid::from(pid));
        sys.process(Pid::from(pid)).map(|p| p.memory()).unwrap_or(0)
    }
}

// ── Display helpers (return String for print!) ───────────────────────────────

impl BenchmarkResult {
    pub fn display_text(&self) -> String {
        let mut s = String::new();
        s.push_str("╔══════════════════════════════════════════╗\n");
        s.push_str("║        Sicario Benchmark Results         ║\n");
        s.push_str("╠══════════════════════════════════════════╣\n");
        s.push_str(&format!(
            "║ Wall clock:    {:>8} ms               ║\n",
            self.total_wall_clock_ms
        ));
        s.push_str(&format!(
            "║ Files scanned: {:>8}                  ║\n",
            self.files_scanned
        ));
        s.push_str(&format!(
            "║ Rules loaded:  {:>8}                  ║\n",
            self.rules_loaded
        ));
        s.push_str(&format!(
            "║ Findings:      {:>8}                  ║\n",
            self.findings_count
        ));
        s.push_str(&format!(
            "║ Files/sec:     {:>8.1}                  ║\n",
            self.files_per_second
        ));
        s.push_str(&format!(
            "║ Rules/sec:     {:>8.1}                  ║\n",
            self.rules_per_second
        ));
        s.push_str(&format!(
            "║ Peak memory:   {:>8.1} MB               ║\n",
            self.peak_memory_bytes as f64 / (1024.0 * 1024.0)
        ));
        s.push_str("╠══════════════════════════════════════════╣\n");
        s.push_str("║ Per-language breakdown:                  ║\n");
        for (lang, bench) in &self.per_language {
            s.push_str(&format!(
                "║  {:<12} {:>5} files  {:>6} ms       ║\n",
                lang, bench.files_scanned, bench.scan_time_ms
            ));
        }
        s.push_str("╚══════════════════════════════════════════╝\n");
        s
    }
}

impl BenchmarkComparison {
    pub fn display_text(&self) -> String {
        let mut s = String::new();
        s.push_str("╔══════════════════════════════════════════╗\n");
        s.push_str("║      Benchmark Comparison                ║\n");
        s.push_str("╠══════════════════════════════════════════╣\n");
        s.push_str(&format!(
            "║ Wall clock:  {:>8} ms → {:>8} ms ({:+.1}%)\n",
            self.baseline.total_wall_clock_ms,
            self.current.total_wall_clock_ms,
            self.wall_clock_delta_pct
        ));
        s.push_str(&format!(
            "║ Files/sec:   {:>8.1} → {:>8.1} ({:+.1}%)\n",
            self.baseline.files_per_second,
            self.current.files_per_second,
            self.files_per_second_delta_pct
        ));
        s.push_str(&format!(
            "║ Peak memory: {:>8.1} MB → {:>8.1} MB ({:+.1}%)\n",
            self.baseline.peak_memory_bytes as f64 / (1024.0 * 1024.0),
            self.current.peak_memory_bytes as f64 / (1024.0 * 1024.0),
            self.memory_delta_pct
        ));
        s.push_str("╚══════════════════════════════════════════╝\n");
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_result_serde_roundtrip() {
        let result = BenchmarkResult {
            timestamp: Utc::now(),
            total_wall_clock_ms: 1234,
            files_per_second: 500.0,
            rules_per_second: 25000.0,
            peak_memory_bytes: 100 * 1024 * 1024,
            files_scanned: 500,
            rules_loaded: 50,
            findings_count: 42,
            per_language: HashMap::from([(
                "JavaScript".to_string(),
                LanguageBenchmark {
                    files_scanned: 200,
                    scan_time_ms: 400,
                    rules_evaluated: 50,
                },
            )]),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: BenchmarkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_wall_clock_ms, 1234);
        assert_eq!(deserialized.files_scanned, 500);
    }

    #[test]
    fn test_benchmark_comparison() {
        let baseline = BenchmarkResult {
            timestamp: Utc::now(),
            total_wall_clock_ms: 1000,
            files_per_second: 500.0,
            rules_per_second: 25000.0,
            peak_memory_bytes: 100 * 1024 * 1024,
            files_scanned: 500,
            rules_loaded: 50,
            findings_count: 42,
            per_language: HashMap::new(),
        };
        let current = BenchmarkResult {
            timestamp: Utc::now(),
            total_wall_clock_ms: 800,
            files_per_second: 625.0,
            rules_per_second: 31250.0,
            peak_memory_bytes: 90 * 1024 * 1024,
            files_scanned: 500,
            rules_loaded: 50,
            findings_count: 42,
            per_language: HashMap::new(),
        };
        let cmp = BenchmarkRunner::compare(&baseline, &current);
        assert!(cmp.wall_clock_delta_pct < 0.0); // faster
        assert!(cmp.files_per_second_delta_pct > 0.0); // more throughput
        assert!(cmp.memory_delta_pct < 0.0); // less memory
    }

    #[test]
    fn test_display_text_not_empty() {
        let result = BenchmarkResult {
            timestamp: Utc::now(),
            total_wall_clock_ms: 100,
            files_per_second: 10.0,
            rules_per_second: 500.0,
            peak_memory_bytes: 50 * 1024 * 1024,
            files_scanned: 10,
            rules_loaded: 5,
            findings_count: 3,
            per_language: HashMap::new(),
        };
        let text = result.display_text();
        assert!(text.contains("Benchmark Results"));
        assert!(text.contains("100"));
    }
}
