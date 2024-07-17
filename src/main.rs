use std::env::current_dir;
use std::fs::canonicalize;
use std::path::PathBuf;
use std::process;
use std::time::Instant;

use anyhow::Result;
use clap::{ArgAction, Args, Parser, Subcommand};
use colored::Colorize;

use utils::file::get_repository_info;

use crate::cloud_api::HoundDogCloudApi;
use crate::enums::{GitProvider, HoundDogEnv, OutputFormat, Severity};
use crate::error::HoundDogError;
use crate::rules::{get_local_data_elements, get_local_data_sinks, get_local_sanitizers};
use crate::structs::ScanConfig;
use crate::utils::table::print_table;
use output::cacilian::generate_cacilian_output;
use output::console::print_console_output;
use output::gitlab::generate_gitlab_output;
use output::markdown::generate_markdown_output;
use output::sarif::generate_sarif_output;

mod cloud_api;
mod enums;
mod env;
mod error;
mod macros;
mod output;
mod rules;
mod scanner;
mod structs;
mod utils;

const SENTRY_DSN: Option<&str> = option_env!("HOUNDDOG_SENTRY_DSN");

#[derive(Debug, Parser)]
#[command(author = "HoundDog.ai, Inc.", name = "hounddog", version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan a directory
    Scan(ScanArguments),
    Info,
}

#[derive(Args, Debug)]
struct ScanArguments {
    /// Target directory to scan
    #[arg(long, default_value = ".", value_name = "DIR")]
    dir: Option<PathBuf>,
    /// Run in debug mode
    #[arg(long, action = ArgAction::SetTrue)]
    debug: bool,
    /// Data sink IDs to skip
    #[arg(long, num_args = 1.., value_name = "ID", value_delimiter = ' ')]
    skip_data_sink: Vec<String>,
    /// Vulnerability hashes to skip
    #[arg(long, num_args = 1.., value_name = "HASH", value_delimiter = ' ')]
    skip_vulnerability: Vec<String>,
    /// Data element IDs to skip
    #[arg(long, num_args = 1.., value_name = "ID", value_delimiter = ' ')]
    skip_data_element: Vec<String>,
    /// Data element occurrence hashes to skip
    #[arg(long, num_args = 1.., value_name = "HASH", value_delimiter = ' ')]
    skip_occurrence: Vec<String>,
    /// Include severity levels in the scan results
    #[arg(long, num_args = 1.., value_name = "SEVERITY", value_delimiter = ' ')]
    include_severity: Vec<Severity>,
    /// Fail on vulnerability with given severity or higher
    #[arg(long)]
    fail_severity_threshold: Option<Severity>,
    /// Scan output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Console)]
    output_format: OutputFormat,
    /// Output filename [default: hounddog-{datetime}.{ext}]
    #[arg(long)]
    output_filename: Option<String>,
    /// Git provider to use if auto-detection fails
    #[arg(long, value_enum)]
    git_provider: Option<GitProvider>,
    /// Baseline Git commit or branch for diff-aware scanning
    #[arg(long)]
    diff_baseline: Option<String>,
    /// Include sensitive datamap in the output
    #[arg(long)]
    sensitivity_datamap: Option<bool>,
    /// Include dataflow visualization in the output
    #[arg(long)]
    dataflow_visualization: Option<bool>,
    /// Include vulnerabilities in the output
    #[arg(long)]
    vulnerability_report: Option<bool>,
    /// Discover new data elements using AI
    #[arg(long)]
    discover_data_elements: Option<bool>,
    /// Auto-enable AI-discovered data elements
    #[arg(long)]
    enable_data_elements: Option<bool>,
    /// Upload new data elements to HoundDog Cloud Platform
    #[arg(long)]
    upload_data_elements: Option<bool>,
    /// Upload scan output to HoundDog Cloud Platform
    #[arg(long, default_value_t = true)]
    no_upload_scan_results: bool,
    /// AI model to use for data element discovery
    #[arg(long, default_value = "gpt-3.5-turbo")]
    ai_model: String,
}

fn scan(env: &env::Environment, args: &ScanArguments) -> Result<()> {
    let is_debug = env.debug || args.debug;

    let repository_path = match &args.dir {
        Some(path) => {
            canonicalize(&path).map_err(|e| err!("Bad directory '{}': {e}", path.display()))?
        }
        None => canonicalize(&current_dir()?)?,
    };
    let rules_dir_path = match env.hounddog_env {
        HoundDogEnv::Dev => env.home_dir_path.join("hounddog-workspace/hounddog/rules"),
        _ => PathBuf::from(&env.hounddog_rules_dir),
    };

    let repository = get_repository_info(&repository_path, &env.ci_type)?;
    sentry::configure_scope(|scope| {
        scope.set_tag("repo_url", &repository.base_url);
        scope.set_tag("branch", &repository.branch);
        scope.set_tag("commit", &repository.commit);
    });

    print_header!("Files to Scan");
    print_table(vec!["Language", "Files", "Lines"], repository.get_dir_stats_table_rows());

    let cloud = if env.hounddog_api_key.is_empty() {
        println!("Fetching default scanner rules ...");
        None
    } else {
        print_dbg!(is_debug, "Detected HOUNDDOG_API_KEY. Authenticating ...");
        let api = HoundDogCloudApi::new(&env.hounddog_env, &env.hounddog_api_key)?;
        let user = api.authenticate()?;
        print_dbg!(is_debug, "Authenticated user in organization {}", &user.org_name);

        sentry::configure_scope(|scope| {
            scope.set_tag("org_id", &user.org_id);
            scope.set_tag("org_name", &user.org_name);
        });
        Some(api)
    };

    println!("Fetching scanner rules ...");
    let mut data_elements = match &cloud {
        Some(api) => api.get_data_elements()?,
        None => get_local_data_elements(&rules_dir_path)?,
    };
    let mut data_sinks = match &cloud {
        Some(api) => api.get_data_sinks()?,
        None => get_local_data_sinks(&rules_dir_path)?,
    };
    let sanitizers = match &cloud {
        Some(api) => api.get_sanitizers()?,
        None => get_local_sanitizers(&rules_dir_path)?,
    };
    print_dbg!(is_debug, "Found {} data elements", data_elements.len());
    print_dbg!(is_debug, "Found {} data sinks", data_sinks.values().flatten().count());
    print_dbg!(is_debug, "Found {} sanitizers", sanitizers.len());

    // Skip data elements and data sinks.
    args.skip_data_element.iter().for_each(|id| {
        data_elements.remove(id);
    });
    args.skip_data_sink.iter().for_each(|id| {
        data_sinks.values_mut().for_each(|map| {
            map.remove(id);
        });
    });

    let config = ScanConfig {
        is_debug,
        is_paid_features_enabled: cloud.is_some(),
        repository,
        data_elements,
        data_sinks,
        sanitizers,
        output_filename: args.output_filename.clone(),
        output_format: args.output_format.clone(),
        skip_data_elements: args.skip_data_element.iter().map(|id| id.to_lowercase()).collect(),
        skip_data_sinks: args.skip_data_sink.iter().map(|id| id.to_lowercase()).collect(),
        skip_occurrences: args.skip_occurrence.iter().map(|h| h.to_uppercase()).collect(),
        skip_vulnerabilities: args.skip_vulnerability.iter().map(|h| h.to_uppercase()).collect(),
    };
    println!("Running scan (this might take a while) ...");
    let start_time = Instant::now();
    let results = scanner::run_scan(&config)?;
    println!("Scan completed in {} seconds.\n", start_time.elapsed().as_secs_f64());

    print_console_output(&results)?;

    match config.output_format {
        OutputFormat::Cacilian => {
            generate_cacilian_output(&results)?;
        }
        OutputFormat::Markdown => {
            generate_markdown_output(&results)?;
        }
        OutputFormat::GitLab => {
            generate_gitlab_output(&results)?;
        }
        OutputFormat::Sarif => {
            generate_sarif_output(&results)?;
        }
        _ => {}
    }
    Ok(())
}

fn print_hounddog_info() -> Result<()> {
    println!("HoundDog.ai, Inc.");
    println!("Homepage: https://hounddog.ai");
    println!("Contact: support@hounddog.ai");
    Ok(())
}

fn main() -> Result<()> {
    let env = env::load_env();

    let _sentry_guard = sentry::init((
        SENTRY_DSN.unwrap_or_default(),
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: Some(env.hounddog_env.to_string().to_lowercase().into()),
            attach_stacktrace: true,
            ..Default::default()
        },
    ));

    let command_result = match Cli::parse().command {
        Some(Command::Scan(args)) => scan(&env, &args),
        Some(Command::Info) => print_hounddog_info(),
        None => Ok(()),
    };
    match command_result {
        Ok(_) => Ok(()),
        Err(err) => {
            if let Some(scanner_err) = err.downcast_ref::<HoundDogError>() {
                if scanner_err.sentry {
                    sentry_anyhow::capture_anyhow(&err);
                }
            }
            if env.hounddog_env == HoundDogEnv::Dev {
                print_err!("{:?}", err);
            } else {
                print_err!("{}", err);
            }
            process::exit(1);
        }
    }
}
