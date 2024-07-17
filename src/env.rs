use crate::enums::{CiType, HoundDogEnv};
use crate::{env_bool, env_str};
use std::env;
use std::path::PathBuf;

#[derive(Debug)]
pub struct Environment {
    pub debug: bool,
    pub home_dir_path: PathBuf,
    pub hounddog_env: HoundDogEnv,
    pub hounddog_api_key: String,
    pub hounddog_rules_dir: String,
    pub ci_type: Option<CiType>,
    pub openai_api_key: String,
}

pub fn load_env() -> Environment {
    Environment {
        debug: env_bool!("HOUNDDOG_DEBUG"),
        home_dir_path: PathBuf::from(env::var("HOME").unwrap()),
        hounddog_env: match env_str!("HOUNDDOG_ENV").as_str() {
            "staging" => HoundDogEnv::Staging,
            "prod" => HoundDogEnv::Prod,
            "dev" => HoundDogEnv::Dev,
            _ => HoundDogEnv::Prod,
        },
        hounddog_api_key: env_str!("HOUNDDOG_API_KEY"),
        hounddog_rules_dir: env_str!("HOUNDDOG_RULES_DIR"),
        ci_type: {
            if env_bool!("AZURE_PIPELINES") {
                Some(CiType::AzurePipelines)
            } else if env_bool!("BITBUCKET_COMMIT") {
                Some(CiType::BitbucketPipelines)
            } else if env_bool!("BUILDKITE_COMMIT") {
                Some(CiType::Buildkite)
            } else if env_bool!("CIRCLECI") {
                Some(CiType::CircleCI)
            } else if env_bool!("GITHUB_ACTIONS") {
                Some(CiType::GithubActions)
            } else if env_bool!("GITLAB_CI") {
                Some(CiType::GitlabCICD)
            } else if env_bool!("JENKINS_URL") {
                Some(CiType::Jenkins)
            } else {
                None
            }
        },
        openai_api_key: env_str!("OPENAI_API_KEY"),
    }
}
