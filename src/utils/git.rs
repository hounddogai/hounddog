use std::env;
use std::path::PathBuf;

use anyhow::Result;
use git2::Repository;
use url::Url;

use crate::enums::{CiType, GitProvider};
use crate::{err, sentry_err};

pub fn parse_git_remote_url(remote_url: &str) -> Result<(String, String)> {
    // Local file system (e.g. file:///path/org/repo).
    if remote_url.starts_with("file://") {
        let url = remote_url.trim_end_matches('/').trim_end_matches(".git");
        let repo_name = url.trim_start_matches("file://");
        return Ok((url.to_string(), repo_name.to_string()));
        // HTTP/HTTPS/SSH (e.g. https://github.hounddog.ai:8000/org/repo.git/).
    } else if remote_url.contains("://") {
        let parsed = Url::parse(&remote_url)
            .map_err(|_| err!("Failed to parse Git remote URL: {}", remote_url))?;
        let domain = parsed.domain().ok_or(err!(
            "Failed to get domain from Git remote URL: {}",
            remote_url
        ))?;
        let scheme = match parsed.scheme() {
            "ssh" => "https",
            scheme => scheme,
        };
        let repo_name = parsed
            .path()
            .trim_start_matches('/')
            .trim_end_matches('/')
            .trim_end_matches(".git")
            .to_string();
        let url = match parsed.port() {
            Some(port) => format!("{}://{}:{}/{}", scheme, domain, port, repo_name),
            None => format!("{}://{}/{}", scheme, domain, repo_name),
        };
        return Ok((url.to_string(), repo_name.to_string()));
    } else if remote_url.starts_with("git@") {
        let url_parts = remote_url.trim_start_matches("git@").split(':').collect::<Vec<&str>>();
        if url_parts.len() != 2 {
            return Err(err!("Failed to parse Git remote URL: {}", remote_url));
        }
        let domain = url_parts[0];
        let repo_name = url_parts[1]
            .trim_start_matches('/')
            .trim_end_matches('/')
            .trim_end_matches(".git")
            .to_string();
        let normalized_repo_url = format!("https://{}/{}", domain, repo_name);
        Ok((normalized_repo_url, repo_name))
    } else {
        Err(err!("Unsupported Git remote URL scheme: {}", remote_url))
    }
}

pub fn get_git_branch(repository: &Repository, ci_type: &Option<CiType>) -> Result<String> {
    repository
        .head()
        .ok()
        .and_then(|head| head.shorthand().map(|branch| branch.to_string()))
        .or(match ci_type {
            Some(CiType::BitbucketPipelines) => {
                env::var("BITBUCKET_BRANCH").ok().or(env::var("BITBUCKET_TAG").ok())
            }
            Some(CiType::Buildkite) => {
                env::var("BUILDKITE_BRANCH").ok().or(env::var("BUILDKITE_TAG").ok())
            }
            Some(CiType::CircleCI) => {
                env::var("CIRCLE_BRANCH").ok().or(env::var("CIRCLE_TAG").ok())
            }
            Some(CiType::GithubActions) => {
                env::var("GITHUB_HEAD_REF").ok().or(env::var("GITHUB_REF_NAME").ok())
            }
            Some(CiType::GitlabCICD) => env::var("CI_COMMIT_REF_NAME")
                .ok()
                .or(env::var("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME").ok())
                .or(env::var("CI_COMMIT_REF_NAME").ok()),
            _ => env::var("HOUNDDOG_GIT_BRANCH").ok(),
        })
        .ok_or(err!("Failed to get Git branch"))
}

pub fn get_git_commit(repository: &Repository, ci_type: &Option<CiType>) -> Result<String> {
    repository
        .head()
        .ok()
        .and_then(|head| head.peel_to_commit().ok())
        .map(|commit| commit.id().to_string())
        .or(match ci_type {
            Some(CiType::BitbucketPipelines) => env::var("BITBUCKET_COMMIT").ok(),
            Some(CiType::Buildkite) => env::var("BUILDKITE_COMMIT").ok(),
            Some(CiType::CircleCI) => env::var("CIRCLE_SHA1").ok(),
            Some(CiType::GithubActions) => env::var("GITHUB_SHA").ok(),
            Some(CiType::GitlabCICD) => env::var("CI_COMMIT_SHA").ok(),
            _ => env::var("HOUNDDOG_GIT_COMMIT").ok(),
        })
        .ok_or(err!("Failed to access Git commit hash"))
}

pub fn get_git_diff_files(repo: &Repository, baseline: Option<&str>) -> Result<Vec<PathBuf>> {
    Ok(match baseline {
        Some(baseline) => {
            let baseline_tree = repo
                .revparse_single(&baseline)
                .map_err(|e| {
                    if e.code() == git2::ErrorCode::NotFound {
                        err!("Git diff baseline '{}' not found", baseline)
                    } else {
                        sentry_err!("Cannot get Git diff baseline '{}': {}", baseline, e)
                    }
                })?
                .peel_to_tree()?;
            let head_tree = repo.head()?.peel_to_tree()?;
            let diff_tree = repo.diff_tree_to_tree(Some(&baseline_tree), Some(&head_tree), None)?;
            diff_tree
                .deltas()
                .map(|delta| delta.new_file().path())
                .filter_map(|path| path)
                .map(|path| path.to_path_buf())
                .collect()
        }
        None => vec![],
    })
}

pub fn get_url_link(
    git_provider: &Option<GitProvider>,
    remote_url: &str,
    commit: &str,
    relative_file_path: &str,
    line_start: usize,
    line_end: usize,
) -> String {
    match git_provider {
        Some(GitProvider::GitHub) => format!(
            "{}/blob/{}/{}#L{}-L{}",
            remote_url, commit, relative_file_path, line_start, line_end
        ),
        Some(GitProvider::GitLab) => format!(
            "{}/-/blob/{}/{}#L{}-{}",
            remote_url, commit, relative_file_path, line_start, line_end
        ),
        Some(GitProvider::Bitbucket) => format!(
            "{}/src/{}/{}#lines-{}:{}",
            remote_url, commit, relative_file_path, line_start, line_end
        ),
        _ => remote_url.to_string(),
    }
}

// Write tests for get_normalized_remote_url_and_repo_name
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_git_remote_url() {
        let (url, repo_name) = parse_git_remote_url("file:///path/to/repo.git/").unwrap();
        assert_eq!(url, "file:///path/to/repo");
        assert_eq!(repo_name, "/path/to/repo");

        let (url, repo_name) =
            parse_git_remote_url("https://username@github.com/org/repo/").unwrap();
        assert_eq!(url, "https://github.com/org/repo");
        assert_eq!(repo_name, "org/repo");

        let (url, repo_name) =
            parse_git_remote_url("http://gitlab.hounddog.ai:8000/org/repo.git/").unwrap();
        assert_eq!(url, "http://gitlab.hounddog.ai:8000/org/repo");
        assert_eq!(repo_name, "org/repo");

        let (url, repo_name) =
            parse_git_remote_url("ssh://gitlab.hounddog.ai:8000/org/repo").unwrap();
        assert_eq!(url, "https://gitlab.hounddog.ai:8000/org/repo");
        assert_eq!(repo_name, "org/repo");

        let (url, repo_name) =
            parse_git_remote_url("git@github.hounddog.ai:org/repo.git/").unwrap();
        assert_eq!(url, "https://github.hounddog.ai/org/repo");
        assert_eq!(repo_name, "org/repo");
    }
}
