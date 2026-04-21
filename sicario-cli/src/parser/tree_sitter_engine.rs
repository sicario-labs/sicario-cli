//! Tree-sitter parsing engine implementation
//!
//! Provides high-performance AST parsing with caching and parallel processing support.

use anyhow::Result;
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use tree_sitter::{Parser, Tree};

use super::{ExclusionManager, Language};

/// Main parsing engine that manages tree-sitter parsers and AST caching
pub struct TreeSitterEngine {
    parsers: HashMap<Language, Parser>,
    ast_cache: LruCache<PathBuf, Tree>,
    pub exclusion_manager: ExclusionManager,
}

impl TreeSitterEngine {
    /// Create a new TreeSitterEngine with default cache size
    pub fn new(project_root: &Path) -> Result<Self> {
        Self::with_cache_size(project_root, 100)
    }

    /// Create a new TreeSitterEngine with custom cache size
    pub fn with_cache_size(project_root: &Path, cache_size: usize) -> Result<Self> {
        let mut engine = Self {
            parsers: HashMap::new(),
            ast_cache: LruCache::new(NonZeroUsize::new(cache_size).unwrap()),
            exclusion_manager: ExclusionManager::new(project_root)?,
        };

        // Initialize parsers for all supported languages
        engine.init_parsers()?;

        Ok(engine)
    }

    /// Initialize tree-sitter parsers for all supported languages
    fn init_parsers(&mut self) -> Result<()> {
        // JavaScript
        let mut js_parser = Parser::new();
        js_parser.set_language(tree_sitter_javascript::language())?;
        self.parsers.insert(Language::JavaScript, js_parser);

        // TypeScript
        let mut ts_parser = Parser::new();
        ts_parser.set_language(tree_sitter_typescript::language_typescript())?;
        self.parsers.insert(Language::TypeScript, ts_parser);

        // Python
        let mut py_parser = Parser::new();
        py_parser.set_language(tree_sitter_python::language())?;
        self.parsers.insert(Language::Python, py_parser);

        // Rust
        let mut rust_parser = Parser::new();
        rust_parser.set_language(tree_sitter_rust::language())?;
        self.parsers.insert(Language::Rust, rust_parser);

        // Go
        let mut go_parser = Parser::new();
        go_parser.set_language(tree_sitter_go::language())?;
        self.parsers.insert(Language::Go, go_parser);

        // Java
        let mut java_parser = Parser::new();
        java_parser.set_language(tree_sitter_java::language())?;
        self.parsers.insert(Language::Java, java_parser);

        Ok(())
    }

    /// Parse a file and return its AST
    pub fn parse_file(&mut self, path: &Path) -> Result<Tree> {
        // Check if file should be scanned
        if !self.should_scan_file(path) {
            anyhow::bail!("File is excluded from scanning: {:?}", path);
        }

        // Check cache first
        if let Some(cached_tree) = self.ast_cache.get(&path.to_path_buf()) {
            return Ok(cached_tree.clone());
        }

        // Detect language from file extension
        let language = Language::from_path(path)
            .ok_or_else(|| anyhow::anyhow!("Unsupported file type: {:?}", path))?;

        // Get the appropriate parser
        let parser = self.parsers.get_mut(&language)
            .ok_or_else(|| anyhow::anyhow!("Parser not initialized for language: {:?}", language))?;

        // Read file content
        let source_code = std::fs::read_to_string(path)?;

        // Parse the file
        let tree = parser.parse(&source_code, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse file: {:?}", path))?;

        // Cache the AST
        self.ast_cache.put(path.to_path_buf(), tree.clone());

        Ok(tree)
    }

    /// Get a cached AST if available
    pub fn get_cached_ast(&self, path: &Path) -> Option<&Tree> {
        self.ast_cache.peek(path)
    }

    /// Clear the AST cache
    pub fn clear_cache(&mut self) {
        self.ast_cache.clear();
    }

    /// Check if a file should be scanned based on exclusion rules
    pub fn should_scan_file(&self, path: &Path) -> bool {
        !self.exclusion_manager.is_excluded(path)
    }

    /// Parse source code directly without caching (useful for parallel processing)
    pub fn parse_source(&self, source_code: &str, language: Language) -> Result<Tree> {
        // Get a parser for the language - we need to clone it for thread safety
        // Since Parser is not Clone, we'll need to create a new one
        let mut parser = Parser::new();
        
        let ts_language = match language {
            Language::JavaScript => tree_sitter_javascript::language(),
            Language::TypeScript => tree_sitter_typescript::language_typescript(),
            Language::Python => tree_sitter_python::language(),
            Language::Rust => tree_sitter_rust::language(),
            Language::Go => tree_sitter_go::language(),
            Language::Java => tree_sitter_java::language(),
        };
        
        parser.set_language(ts_language)?;
        
        // Parse the source code
        let tree = parser.parse(source_code, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse source code for language: {:?}", language))?;
        
        Ok(tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_engine_creation() {
        let temp_dir = std::env::temp_dir();
        let engine = TreeSitterEngine::new(&temp_dir);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_parser_initialization() {
        let temp_dir = std::env::temp_dir();
        let engine = TreeSitterEngine::new(&temp_dir).unwrap();
        
        // Verify all parsers are initialized
        assert_eq!(engine.parsers.len(), 6);
        assert!(engine.parsers.contains_key(&Language::JavaScript));
        assert!(engine.parsers.contains_key(&Language::TypeScript));
        assert!(engine.parsers.contains_key(&Language::Python));
        assert!(engine.parsers.contains_key(&Language::Rust));
        assert!(engine.parsers.contains_key(&Language::Go));
        assert!(engine.parsers.contains_key(&Language::Java));
    }

    #[test]
    fn test_parse_javascript_file() {
        let temp_dir = std::env::temp_dir().join("sicario_test_js");
        fs::create_dir_all(&temp_dir).unwrap();
        
        let test_file = temp_dir.join("test.js");
        fs::write(&test_file, "function hello() { return 'world'; }").unwrap();
        
        let mut engine = TreeSitterEngine::new(&temp_dir).unwrap();
        let result = engine.parse_file(&test_file);
        
        assert!(result.is_ok());
        let tree = result.unwrap();
        assert!(tree.root_node().child_count() > 0);
        
        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_parse_python_file() {
        let temp_dir = std::env::temp_dir().join("sicario_test_py");
        fs::create_dir_all(&temp_dir).unwrap();
        
        let test_file = temp_dir.join("test.py");
        fs::write(&test_file, "def hello():\n    return 'world'").unwrap();
        
        let mut engine = TreeSitterEngine::new(&temp_dir).unwrap();
        let result = engine.parse_file(&test_file);
        
        assert!(result.is_ok());
        let tree = result.unwrap();
        assert!(tree.root_node().child_count() > 0);
        
        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_parse_rust_file() {
        let temp_dir = std::env::temp_dir().join("sicario_test_rs");
        fs::create_dir_all(&temp_dir).unwrap();
        
        let test_file = temp_dir.join("test.rs");
        fs::write(&test_file, "fn hello() -> &'static str { \"world\" }").unwrap();
        
        let mut engine = TreeSitterEngine::new(&temp_dir).unwrap();
        let result = engine.parse_file(&test_file);
        
        assert!(result.is_ok());
        let tree = result.unwrap();
        assert!(tree.root_node().child_count() > 0);
        
        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_ast_caching() {
        let temp_dir = std::env::temp_dir().join("sicario_test_cache");
        fs::create_dir_all(&temp_dir).unwrap();
        
        let test_file = temp_dir.join("test.js");
        fs::write(&test_file, "const x = 42;").unwrap();
        
        let mut engine = TreeSitterEngine::new(&temp_dir).unwrap();
        
        // First parse - should cache
        let tree1 = engine.parse_file(&test_file).unwrap();
        
        // Second parse - should retrieve from cache
        let tree2 = engine.parse_file(&test_file).unwrap();
        
        // Trees should be equivalent
        assert_eq!(tree1.root_node().to_sexp(), tree2.root_node().to_sexp());
        
        // Verify cache contains the file
        assert!(engine.get_cached_ast(&test_file).is_some());
        
        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_cache_clear() {
        let temp_dir = std::env::temp_dir().join("sicario_test_clear");
        fs::create_dir_all(&temp_dir).unwrap();
        
        let test_file = temp_dir.join("test.js");
        fs::write(&test_file, "const x = 42;").unwrap();
        
        let mut engine = TreeSitterEngine::new(&temp_dir).unwrap();
        
        // Parse and cache
        engine.parse_file(&test_file).unwrap();
        assert!(engine.get_cached_ast(&test_file).is_some());
        
        // Clear cache
        engine.clear_cache();
        assert!(engine.get_cached_ast(&test_file).is_none());
        
        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_unsupported_file_type() {
        let temp_dir = std::env::temp_dir().join("sicario_test_unsupported");
        fs::create_dir_all(&temp_dir).unwrap();
        
        let test_file = temp_dir.join("test.txt");
        fs::write(&test_file, "some text").unwrap();
        
        let mut engine = TreeSitterEngine::new(&temp_dir).unwrap();
        let result = engine.parse_file(&test_file);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported file type"));
        
        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_excluded_file() {
        let temp_dir = std::env::temp_dir().join("sicario_test_excluded");
        fs::create_dir_all(&temp_dir.join("node_modules")).unwrap();
        
        let test_file = temp_dir.join("node_modules/test.js");
        fs::write(&test_file, "const x = 42;").unwrap();
        
        let mut engine = TreeSitterEngine::new(&temp_dir).unwrap();
        
        // Use relative path from project root
        let relative_path = Path::new("node_modules/test.js");
        let result = engine.parse_file(relative_path);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("excluded from scanning"));
        
        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_should_scan_file() {
        let temp_dir = std::env::temp_dir();
        let engine = TreeSitterEngine::new(&temp_dir).unwrap();
        
        assert!(engine.should_scan_file(Path::new("src/main.rs")));
        assert!(!engine.should_scan_file(Path::new("node_modules/package/index.js")));
        assert!(!engine.should_scan_file(Path::new("dist/bundle.min.js")));
        assert!(!engine.should_scan_file(Path::new("target/debug/app")));
    }

    #[test]
    fn test_custom_cache_size() {
        let temp_dir = std::env::temp_dir();
        let engine = TreeSitterEngine::with_cache_size(&temp_dir, 50);
        
        assert!(engine.is_ok());
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use rayon::prelude::*;
    use std::fs;
    use std::sync::{Arc, Mutex};

    // Feature: sicario-cli-core, Property 5: Parallel parsing correctness
    // Validates: Requirements 2.3
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]
        
        #[test]
        fn test_parallel_parsing_correctness(
            file_count in 1usize..20,
            code_complexity in 1usize..10
        ) {
            let temp_dir = std::env::temp_dir().join(format!("sicario_prop_test_{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&temp_dir).unwrap();
            
            // Generate test files with varying complexity
            let mut test_files = Vec::new();
            for i in 0..file_count {
                let file_path = temp_dir.join(format!("test_{}.js", i));
                let code = generate_js_code(code_complexity);
                fs::write(&file_path, code).unwrap();
                test_files.push(file_path);
            }
            
            // Parse sequentially
            let mut engine_seq = TreeSitterEngine::new(&temp_dir).unwrap();
            let mut sequential_results = Vec::new();
            for file in &test_files {
                match engine_seq.parse_file(file) {
                    Ok(tree) => sequential_results.push((file.clone(), tree.root_node().to_sexp())),
                    Err(_) => {}
                }
            }
            
            // Parse in parallel using Rayon
            let engine_par = Arc::new(Mutex::new(TreeSitterEngine::new(&temp_dir).unwrap()));
            let parallel_results: Vec<_> = test_files.par_iter()
                .filter_map(|file| {
                    let mut engine = engine_par.lock().unwrap();
                    match engine.parse_file(file) {
                        Ok(tree) => Some((file.clone(), tree.root_node().to_sexp())),
                        Err(_) => None
                    }
                })
                .collect();
            
            // Sort both results by file path for comparison
            let mut seq_sorted = sequential_results.clone();
            seq_sorted.sort_by(|a, b| a.0.cmp(&b.0));
            
            let mut par_sorted = parallel_results.clone();
            par_sorted.sort_by(|a, b| a.0.cmp(&b.0));
            
            // Verify same number of successful parses
            prop_assert_eq!(seq_sorted.len(), par_sorted.len());
            
            // Verify ASTs are identical
            for (seq, par) in seq_sorted.iter().zip(par_sorted.iter()) {
                prop_assert_eq!(&seq.0, &par.0, "File paths should match");
                prop_assert_eq!(&seq.1, &par.1, "AST s-expressions should match for file {:?}", &seq.0);
            }
            
            // Cleanup
            fs::remove_dir_all(&temp_dir).ok();
        }
    }
    
    // Feature: sicario-cli-core, Property 6: AST cache consistency
    // Validates: Requirements 2.4
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]
        
        #[test]
        fn test_ast_cache_consistency(
            code_complexity in 1usize..15,
            parse_count in 2usize..10
        ) {
            let temp_dir = std::env::temp_dir().join(format!("sicario_cache_test_{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&temp_dir).unwrap();
            
            // Generate a test file
            let test_file = temp_dir.join("test.js");
            let code = generate_js_code(code_complexity);
            fs::write(&test_file, &code).unwrap();
            
            let mut engine = TreeSitterEngine::new(&temp_dir).unwrap();
            
            // Parse the file multiple times
            let mut ast_results = Vec::new();
            for _ in 0..parse_count {
                match engine.parse_file(&test_file) {
                    Ok(tree) => ast_results.push(tree.root_node().to_sexp()),
                    Err(e) => prop_assert!(false, "Parse failed: {}", e),
                }
            }
            
            // Verify all ASTs are identical (cache consistency)
            let first_ast = &ast_results[0];
            for (i, ast) in ast_results.iter().enumerate().skip(1) {
                prop_assert_eq!(
                    first_ast, ast,
                    "AST from parse {} should match first parse (cached)", i
                );
            }
            
            // Verify the file is in cache
            prop_assert!(
                engine.get_cached_ast(&test_file).is_some(),
                "File should be in cache after parsing"
            );
            
            // Verify cached AST matches parsed AST
            if let Some(cached_tree) = engine.get_cached_ast(&test_file) {
                prop_assert_eq!(
                    &cached_tree.root_node().to_sexp(), first_ast,
                    "Cached AST should match parsed AST"
                );
            }
            
            // Cleanup
            fs::remove_dir_all(&temp_dir).ok();
        }
    }
    
    // Helper function to generate JavaScript code with varying complexity
    fn generate_js_code(complexity: usize) -> String {
        let mut code = String::new();
        code.push_str("// Generated test code\n");
        
        for i in 0..complexity {
            code.push_str(&format!("function func{}() {{\n", i));
            code.push_str(&format!("  const x{} = {};\n", i, i * 10));
            code.push_str(&format!("  return x{} + 1;\n", i));
            code.push_str("}\n\n");
        }
        
        code.push_str("module.exports = { ");
        for i in 0..complexity {
            if i > 0 {
                code.push_str(", ");
            }
            code.push_str(&format!("func{}", i));
        }
        code.push_str(" };\n");
        
        code
    }
}
