//! False-Positive Corpus — definitions for the 10 popular open-source
//! repositories used to assert zero high-confidence findings.
//!
//! These are clean, well-maintained projects. The Sicario SAST engine must
//! produce zero `confidence: high` findings against any of them.
//!
//! Requirement: Req 2 — False-Positive Corpus

/// A single repository in the false-positive corpus.
#[derive(Debug, Clone)]
pub struct FpCorpusRepo {
    /// Short machine-readable identifier (e.g. `"express"`).
    pub name: &'static str,
    /// Human-readable display name (e.g. `"Express.js"`).
    pub display_name: &'static str,
    /// GitHub clone URL.
    pub url: &'static str,
    /// Primary language(s) of the repository.
    pub languages: &'static [&'static str],
    /// One-line description of the project.
    pub description: &'static str,
}

/// The 10 canonical FP corpus repositories defined by Requirement 2.
///
/// These are used by `sicario benchmark --fp-corpus` to assert that the
/// SAST engine produces zero high-confidence findings against clean,
/// popular open-source projects.
pub const FP_CORPUS_REPOS: &[FpCorpusRepo] = &[
    FpCorpusRepo {
        name: "express",
        display_name: "Express.js",
        url: "https://github.com/expressjs/express",
        languages: &["JavaScript"],
        description: "Fast, unopinionated, minimalist web framework for Node.js",
    },
    FpCorpusRepo {
        name: "django",
        display_name: "Django",
        url: "https://github.com/django/django",
        languages: &["Python"],
        description: "The web framework for perfectionists with deadlines",
    },
    FpCorpusRepo {
        name: "fastapi",
        display_name: "FastAPI",
        url: "https://github.com/tiangolo/fastapi",
        languages: &["Python"],
        description: "FastAPI framework, high performance, easy to learn, fast to code, ready for production",
    },
    FpCorpusRepo {
        name: "next.js",
        display_name: "Next.js",
        url: "https://github.com/vercel/next.js",
        languages: &["JavaScript", "TypeScript"],
        description: "The React Framework for the Web",
    },
    FpCorpusRepo {
        name: "flask",
        display_name: "Flask",
        url: "https://github.com/pallets/flask",
        languages: &["Python"],
        description: "The Python micro framework for building web applications",
    },
    FpCorpusRepo {
        name: "rails",
        display_name: "Rails",
        url: "https://github.com/rails/rails",
        languages: &["Ruby"],
        description: "Ruby on Rails — a web-application framework for the MVC pattern",
    },
    FpCorpusRepo {
        name: "laravel",
        display_name: "Laravel",
        url: "https://github.com/laravel/laravel",
        languages: &["PHP"],
        description: "Laravel is a web application framework with expressive, elegant syntax",
    },
    FpCorpusRepo {
        name: "spring-boot",
        display_name: "Spring Boot",
        url: "https://github.com/spring-projects/spring-boot",
        languages: &["Java"],
        description: "Spring Boot helps you to create Spring-powered, production-grade applications",
    },
    FpCorpusRepo {
        name: "aspnetcore",
        display_name: "ASP.NET Core",
        url: "https://github.com/dotnet/aspnetcore",
        languages: &["CSharp"],
        description: "ASP.NET Core is a cross-platform .NET framework for building modern cloud-based web applications",
    },
    FpCorpusRepo {
        name: "nest",
        display_name: "NestJS",
        url: "https://github.com/nestjs/nest",
        languages: &["TypeScript"],
        description: "A progressive Node.js framework for building efficient, scalable, and enterprise-grade server-side applications",
    },
];

/// Returns the full list of FP corpus repositories.
///
/// This is the primary entry point used by `sicario benchmark --fp-corpus`.
/// The returned slice contains all 10 repositories defined by Requirement 2.
pub fn load_fp_corpus() -> Vec<&'static FpCorpusRepo> {
    FP_CORPUS_REPOS.iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fp_corpus_has_ten_repos() {
        assert_eq!(
            FP_CORPUS_REPOS.len(),
            10,
            "Requirement 2 mandates exactly 10 FP corpus repositories"
        );
    }

    #[test]
    fn fp_corpus_contains_all_required_repos() {
        let names: Vec<&str> = FP_CORPUS_REPOS.iter().map(|r| r.name).collect();
        let required = [
            "express",
            "django",
            "fastapi",
            "next.js",
            "flask",
            "rails",
            "laravel",
            "spring-boot",
            "aspnetcore",
            "nest",
        ];
        for req in &required {
            assert!(
                names.contains(req),
                "FP corpus is missing required repo: {}",
                req
            );
        }
    }

    #[test]
    fn all_repos_have_valid_github_urls() {
        for repo in FP_CORPUS_REPOS {
            assert!(
                repo.url.starts_with("https://github.com/"),
                "Repo '{}' has invalid URL: {}",
                repo.name,
                repo.url
            );
        }
    }

    #[test]
    fn all_repos_have_non_empty_fields() {
        for repo in FP_CORPUS_REPOS {
            assert!(!repo.name.is_empty(), "Repo has empty name");
            assert!(!repo.display_name.is_empty(), "Repo '{}' has empty display_name", repo.name);
            assert!(!repo.url.is_empty(), "Repo '{}' has empty url", repo.name);
            assert!(!repo.languages.is_empty(), "Repo '{}' has no languages", repo.name);
            assert!(!repo.description.is_empty(), "Repo '{}' has empty description", repo.name);
        }
    }

    #[test]
    fn load_fp_corpus_returns_all_repos() {
        let corpus = load_fp_corpus();
        assert_eq!(corpus.len(), FP_CORPUS_REPOS.len());
    }

    #[test]
    fn fp_corpus_covers_required_languages() {
        // Requirement 2 implicitly requires coverage of JS, TS, Python, Ruby, PHP, Java, C#
        let all_languages: Vec<&str> = FP_CORPUS_REPOS
            .iter()
            .flat_map(|r| r.languages.iter().copied())
            .collect();

        let required_languages = [
            "JavaScript",
            "TypeScript",
            "Python",
            "Ruby",
            "PHP",
            "Java",
            "CSharp",
        ];
        for lang in &required_languages {
            assert!(
                all_languages.contains(lang),
                "FP corpus has no repo covering language: {}",
                lang
            );
        }
    }
}
