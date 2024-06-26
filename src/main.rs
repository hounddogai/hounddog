use std::collections::HashMap;
use std::env::current_dir;
use std::fs::canonicalize;
use std::path::PathBuf;
use std::process;
use std::time::Instant;

use anyhow::Result;
use clap::{ArgAction, Args, Parser, Subcommand};
use colored::Colorize;

use utils::file::get_dir_info;

use crate::cloud_api::HoundDogCloudApi;
use crate::enums::{GitProvider, HoundDogEnv, Language, OutputFormat, Severity};
use crate::error::HoundDogError;
use crate::output::common::{get_dir_stats_table_rows};
use crate::output::handlers::cacilian::export_cacilian_json;
use crate::output::handlers::console::print_scan_results_to_console;
use crate::output::handlers::gitlab::export_gitlab_json;
use crate::output::handlers::json::generate_hounddog_json;
use crate::output::handlers::markdown::export_markdown_report;
use crate::output::handlers::sarif::export_sarif;
use crate::rules::{get_local_data_elements, get_local_data_sinks, get_local_sanitizers};
use crate::structs::{DataElement, DataSink, Sanitizer, ScanConfig};
use crate::utils::table::print_table;

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
    skip_data_element_occurrence: Vec<String>,
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
    /// Include vulnerability report in the output
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

    let scan_dir_path = match &args.dir {
        Some(path) => {
            canonicalize(&path).map_err(|e| err!("Bad directory '{}': {e}", path.display()))?
        }
        None => canonicalize(&current_dir()?)?,
    };
    let rules_dir_path = match env.hounddog_env {
        HoundDogEnv::Dev => env.home_dir_path.join("hounddog-workspace/hounddog/rules"),
        _ => PathBuf::from(&env.hounddog_rules_dir),
    };

    let mut data_elems: HashMap<String, DataElement>;
    let mut data_sinks: HashMap<Language, HashMap<String, DataSink>>;
    let mut sanitizers: Vec<Sanitizer>;

    if env.hounddog_api_key.is_empty() {
        data_elems = get_local_data_elements(&rules_dir_path)?;
        data_sinks = get_local_data_sinks(&rules_dir_path)?;
        sanitizers = get_local_sanitizers(&rules_dir_path)?;
    } else {
        print_dbg!(is_debug, "Detected HOUNDDOG_API_KEY. Authenticating ...");
        let cloud_api = HoundDogCloudApi::new(&env.hounddog_env, &env.hounddog_api_key)?;
        let user = cloud_api.get_auth_metadata()?;
        print_dbg!(is_debug, "Authenticated organization: {}", &user.org_name);

        sentry::configure_scope(|scope| {
            scope.set_tag("org_id", &user.org_id);
            scope.set_tag("org_name", &user.org_name);
        });
        data_elems = cloud_api.get_data_elements()?;
        data_sinks = get_local_data_sinks(&rules_dir_path)?;
        sanitizers = cloud_api.get_sanitizers()?;
    }
    let scan_dir_info = get_dir_info(&scan_dir_path, &env.ci_type)?;

    sentry::configure_scope(|scope| {
        scope.set_tag("git_remote_url", &scan_dir_info.git_remote_url);
        scope.set_tag("git_branch", &scan_dir_info.git_branch);
        scope.set_tag("git_commit", &scan_dir_info.git_commit);
    });

    print_header!("Files to Scan");
    print_table(
        vec!["Language", "Files", "Lines"],
        get_dir_stats_table_rows(&scan_dir_info),
    );

    // Skip data elements and data sinks.
    args.skip_data_element.iter().for_each(|id| {
        data_elems.remove(id);
    });
    args.skip_data_sink.iter().for_each(|id| {
        data_sinks.values_mut().for_each(|map| {
            map.remove(id);
        });
    });
    let scan_config = ScanConfig::new(
        &scan_dir_path,
        &scan_dir_info,
        &data_elems,
        &data_sinks,
        &sanitizers,
        &args.output_filename,
        &args.output_format,
        &args.skip_data_element,
        &args.skip_data_sink,
        &args.skip_data_element_occurrence,
        &args.skip_vulnerability,
    );
    println!();

    println!("Scanning (this might take a while) ...");
    let scan_start_time = Instant::now();
    let scan_results = scanner::run_scan(&scan_config)?;
    let scan_elapsed_time_secs = scan_start_time.elapsed().as_secs_f64();
    println!("Scan completed in {} seconds.", scan_elapsed_time_secs);

    print_scan_results_to_console(&scan_config, &scan_results)?;

    match args.output_format {
        OutputFormat::Cacilian => {
            export_cacilian_json(&scan_config, &scan_results)?;
        },
        OutputFormat::Markdown => {
            export_markdown_report(&scan_config, &scan_results)?;
        },
        OutputFormat::GitLab => {
            export_gitlab_json(&scan_config, &scan_results)?;
        },
        OutputFormat::Sarif => {
            export_sarif(&scan_config, &scan_results)?;
        },
        OutputFormat::Json => {
            let hounddog_json = generate_hounddog_json(&scan_config, &scan_results)?;
        },
        _ => {},
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
