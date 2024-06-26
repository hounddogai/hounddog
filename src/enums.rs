use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter, EnumString};

#[derive(Debug, Eq, PartialEq, Display)]
pub enum HoundDogEnv {
    Dev,
    Staging,
    Prod,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Display, EnumString, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    AI,
    User,
    HoundDog,
}

#[derive(Debug, Display, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CiType {
    AzurePipelines,
    BitbucketPipelines,
    Buildkite,
    CircleCI,
    GithubActions,
    GitlabCICD,
    Jenkins,
}

#[derive(Clone, Debug, Display, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum GitProvider {
    Bitbucket,
    GitHub,
    GitLab,
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
    Display,
    Deserialize,
    EnumString,
    Serialize,
    ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    Critical,
    Medium,
    Low,
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
    Display,
    Deserialize,
    EnumIter,
    EnumString,
    Serialize,
    ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Medium,
    Low,
}

#[derive(Clone, Debug, Display, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Cacilian,
    Console,
    GitLab,
    Markdown,
    Json,
    Sarif,
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
    Display,
    Deserialize,
    EnumIter,
    EnumString,
    Serialize,
    ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    CSharp,
    GraphQL,
    Java,
    Kotlin,
    Python,
    Ruby,
    SQL,
    Typescript,
}

#[derive(Clone, Debug, Display)]
pub(crate) enum ScopeType {
    Global,
    Anonymous,
    Class,
    Function,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VisitChildren {
    Yes,
    No,
}