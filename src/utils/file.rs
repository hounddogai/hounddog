use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::Result;
use git2::Repository;
use ignore::WalkBuilder;
use strum::IntoEnumIterator;

use crate::enums::{CiType, GitProvider, Language};
use crate::err;
use crate::structs::{DirectoryInfo, FileStats};
use crate::utils::git::{get_git_commit, get_git_branch, parse_git_remote_url};

pub fn get_dir_info(path: &PathBuf, ci_type: &Option<CiType>) -> Result<DirectoryInfo> {
    let mut per_lang_file_stats = Language::iter()
        .map(|lang| (lang, FileStats::new()))
        .collect::<HashMap<Language, FileStats>>();
    let mut total_file_stats = FileStats::new();

    for file in get_files_in_dir(path) {
        if let Some(language) = get_file_language(&file) {
            if let Ok(lines) = get_file_line_count(&file) {
                per_lang_file_stats.entry(language).and_modify(|s| {
                    s.file_count += 1;
                    s.line_count += lines;
                });
                total_file_stats.file_count += 1;
                total_file_stats.line_count += lines;
            }
        }
    }

    if path.join(".git").is_dir() {
        let repo = Repository::open(path)?;
        let git_remote_url = repo
            .find_remote("origin")
            .map_err(|_| err!("Failed to access Git remote origin"))?
            .url()
            .ok_or(err!("Failed to access Git remote origin URL"))
            .map(|url| url.trim_end_matches('/').trim_end_matches(".git").to_string())?
            .to_lowercase();

        let (git_remote_url, git_repo_name) = parse_git_remote_url(&git_remote_url)?;
        let git_branch = get_git_branch(&repo, &ci_type)?;
        let git_commit = get_git_commit(&repo, &ci_type)?;
        let git_provider = match &git_remote_url {
            url if url.contains("github") => Some(GitProvider::GitHub),
            url if url.contains("gitlab") => Some(GitProvider::GitLab),
            url if url.contains("bitbucket") => Some(GitProvider::Bitbucket),
            _ => None,
        };
        Ok(DirectoryInfo {
            git_remote_url,
            git_repo_name,
            git_branch,
            git_commit,
            git_provider,
            per_lang_file_stats,
            total_file_stats,
        })
    } else {
        Ok(DirectoryInfo {
            git_remote_url: format!(
                "file://{}",
                path.display().to_string().trim_start_matches('/')
            ),
            git_repo_name: format!(
                "local/{}",
                path.file_stem().unwrap().to_string_lossy().to_string()
            ),
            git_branch: "main".to_string(),
            git_commit: "HEAD".to_string(),
            git_provider: None,
            per_lang_file_stats,
            total_file_stats,
        })
    }
}

pub fn get_files_in_dir(dir_path: &PathBuf) -> impl Iterator<Item = PathBuf> {
    WalkBuilder::new(dir_path)
        .add_custom_ignore_filename(".hounddogignore")
        .build()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| entry.into_path())
}

pub fn get_file_language(file_path: &Path) -> Option<Language> {
    match file_path.extension().unwrap_or_default().to_str().unwrap() {
        "cs" => Some(Language::CSharp),
        "gql" | "graphql" => Some(Language::GraphQL),
        "java" => Some(Language::Java),
        "js" | "jsx" | "ts" | "tsx" => Some(Language::Typescript),
        "kt" => Some(Language::Kotlin),
        "py" => Some(Language::Python),
        "rb" => Some(Language::Ruby),
        "sql" => Some(Language::SQL),
        _ => None,
    }
}

fn get_file_line_count(file_path: &PathBuf) -> Result<usize> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::with_capacity(1024 * 32, file);
    let mut count = 0;
    loop {
        let len = {
            let buf = reader.fill_buf()?;
            if buf.is_empty() {
                break;
            }
            count += bytecount::count(&buf, b'\n');
            buf.len()
        };
        reader.consume(len);
    }
    Ok(count)
}
