# HoundDog.ai

## What is it?

[HoundDog.ai](https://hounddog.ai) is a source code scanner
(a [SAST](https://en.wikipedia.org/wiki/Static_application_security_testing)
command-line tool) that helps organizations with the following use cases:

- **Proactive PII Leak Prevention**: Detect PII leaks in logs, files, cookies,
  tokens, and third-party services early in the development cycle (e.g., during
  code reviews and build pipelines) to strengthen the data security posture and
  avoid costly remediation later in production.
- **Third-Party Risk Mitigation**: Track third-party application dataflows and
  detect data processing agreement violations *before* new product changes are
  released to users.
- **Automatic Data Mapping for Privacy Compliance**: Eliminate manual and
  error-prone documentation of processing activities relying on spreadsheets and
  internal surveys. Streamline the entire process and keep pace with development
  to eliminate surprises.

### Free Features

- Source code scanning with
  [standalone binary](https://github.com/hounddogai/hounddog/releases) or
  [Docker image](https://hub.docker.com/r/hounddogai/hounddog).
- Markdown reports for point-in-time views of the PII data elements in
  your codebase, along with their sensitivity levels, occurrence counts,
  file locations and code snippets.

### Starter and Enterprise Features

- Continuous monitoring on vulnerabilities exposing PII in cleartext through
  logs, files, cookies, tokens, and third-party APIs.
- Graphical visualizations displaying the flow of PII to various data sinks.
- CI/CD integration with Azure Pipelines, BitBucket Pipelines, GitHub Actions,
  GitLab CI/CD, CircleCI, Jenkins, etc.
- Security dashboard integration with GitHub Enterprise and GitLab Ultimate.
- Access to [HoundDog.ai Cloud Platform](https://app.hounddog.ai) for triaging
  issues, creating Jira tasks, generating RoPA (Record of Processing Activities)
  reports, and scan rules customization.
- (Coming soon) Automatic configuration of scan rules based on your data
  processing agreements for continuous DPA compliance and risk mitigation.

## How is it different from other scanners?

- **100% complementary with other scanners**: Our goal is not to replace CodeQL,
  Semgrep, Snyk etc., but to fill an existing gap and be the best-in-class for
  PII detection. Here are some of the common weakness enumerations covered
  extensively and uniquely by HoundDog.ai:
  [CWE-201](https://cwe.mitre.org/data/definitions/201.html),
  [CWE-209](https://cwe.mitre.org/data/definitions/209.html),
  [CWE-312](https://cwe.mitre.org/data/definitions/312.html),
  [CWE-313](https://cwe.mitre.org/data/definitions/313.html),
  [CWE-315](https://cwe.mitre.org/data/definitions/315.html),
  [CWE-532](https://cwe.mitre.org/data/definitions/532.html),
  [CWE-539](https://cwe.mitre.org/data/definitions/539.html).
- **Privacy-focused**: By default, HoundDog.ai's code scanner runs only in your
  environment and your source code never leaves your premises.
- **Blazingly fast with a tiny footprint**: HoundDog.ai's code scanner is
  written in Rust, a language well-known for its performance and memory safety.
  It can scan 1 million lines of code in under a minute on modern hardware, and
  its unzipped binary is less than 25MBs in size. We strive to keep it super
  lightweight and have minimal impact on your build pipelines.
- **High accuracy**: We maintain a carefully curated set of rules and
  definitions covering multiple domains (e.g. PII, PHI, PIFI) out of the box,
  placing the highest priority on minimizing false positives. The rules are
  continuously improved using AI workflows, reviewed by human experts and tested
  against real-world codebases.

## Requirements

- [Standalone Binary:](https://github.com/hounddogai/hounddog/releases)

    - Operating System: Linux or macOS
    - CPU Architecture: x86-64 or ARM64
    - Shell: Bash, Zsh, or Fish
    - Memory: Minimum 1GB of free memory

- [Docker Image:](https://hub.docker.com/r/hounddogai/hounddog)

    - Docker Engine on Linux or Docker Desktop on Windows/macOS
    - Memory: Minimum 1GB of free memory allocated to Docker

## Supported Languages

- C# / .NET
- Golang (coming soon)
- GraphQL
- Java
- JavaScript
- Kotlin
- OpenAPI / Swagger
- Python
- Ruby
- SQL
- TypeScript

## Installation

To install the standalone binary in your user directory
at `~/.hounddog/bin/hounddog`:

```shell
curl -fsSL https://install.hounddog.ai | bash
```

To install it system-wide at `/usr/local/bin/hounddog` (sudo required):

```shell
curl -fsSL https://install.hounddog.ai | sudo bash
```

To upgrade to the latest version, simply run the commands above again.

You can alternatively download the binary and the checksum directly from
our [releases page](https://github.com/hounddogai/hounddog/releases).

## Usage

To scan a file or directory using the
[standalone binary](https://github.com/hounddogai/hounddog/releases):

```shell
hounddog scan [path] [options]
```

To scan the current directory using the
[Docker image](https://hub.docker.com/r/hounddogai/hounddog) instead:

```shell
docker run --pull=always -it --rm -v .:/data hounddogai/hounddog:latest hounddog scan
```

To see all available command-line options:

```shell
hounddog scan --help
```

By default, HoundDog.ai respects your `.gitignore` file. To exclude additional
files and/or folders, create a `.hounddogignore` file at the root directory of
your project and specify the file patterns in it using the
[.gitignore format](https://git-scm.com/docs/gitignore/en). Here are some
examples:

```shell
# Ignore dependencies
node_modules/

# Ignore a specific file
config.js

# Ignore all files in a directory
test/*
```

Please refer to our [user documentation](https://docs.hounddog.ai/scanner) for
more information, such as generating and using
a [HoundDog.ai API key](https://docs.hounddog.ai/scanner/api-key) to
unlock paid features and integrating the scanner with your CI/CD pipelines.

## Quickstart

To demonstrate the capabilities of the scanner, HoundDog.ai provides a [test
web application](https://github.com/hounddogai/hounddog-test-healthcare-app)
with deliberate security flaws. First, clone the repository:

```shell
git clone https://github.com/hounddogai/hounddog-test-healthcare-app
```

Then scan it with the `--output-format=markdown` option to generate an offline
Markdown report:

```shell
hounddog scan hounddog-test-healthcare-app --output-format=markdown
```

Open the generated file `hounddog-test-healthcare-app/hounddog-{timestamp}.md`
on your browser. We recommend using Google Chrome and the
[Markdown Viewer](https://chromewebstore.google.com/detail/markdown-viewer/ckkdlimhmcjmikdlpkmbgfkaikojcbjk)
extension, with **mermaid** and **toc** settings enabled
(see [this](https://docs.hounddog.ai/scanner/markdown-report) for more details).

## Uninstallation

If installed in user directory at `~/.hounddog/bin/hounddog`:

```shell
rm -r ~/.hounddog
```

If installed system-wide at `/usr/local/bin/hounddog`:

```shell
sudo rm /usr/local/bin/hounddog
```

## License

View [license information](https://hounddog.ai/terms-of-service/) for
HoundDog.ai's software.

## Contact

If you need any help or would like to send us feedback, please create a [GitHub
issue](https://github.com/hounddogai/hounddog/issues) or shoot us an email
at [support@hounddog.ai](mailto:support@hounddog.ai).
