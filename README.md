# HoundDog.ai

## What is it?

[HoundDog.ai](https://hounddog.ai) is a source code scanner and SAST (Static Application Security Testing) command-line
tool that helps you with the following use cases:

- **Proactive PII Leak Prevention**: Detect PII (Personally Identifiable Information) leaks through logs, files,
  cookies, tokens, and third-party APIs early in the development cycle to strengthen the data security posture and
  avoid costly remediation in production.
- **Third-Party Risk Mitigation**: Track third-party dataflows and detect data processing agreement violations before
  changes reach users.
- **Automatic Data Mapping for Privacy Compliance**: Automate and streamline data processing documentation, replacing
  error-prone spreadsheets and surveys with continuous monitoring that keeps pace with development.

## How is it different?

- **100% complementary to other scanners**: Our goal is not to replace CodeQL, Snyk etc., but to fill a critical gap and
  be the best-in-class for PII leak detection. We extensively and uniquely cover CWEs such as
  [CWE-201](https://cwe.mitre.org/data/definitions/201.html),
  [CWE-209](https://cwe.mitre.org/data/definitions/209.html),
  [CWE-312](https://cwe.mitre.org/data/definitions/312.html),
  [CWE-313](https://cwe.mitre.org/data/definitions/313.html),
  [CWE-315](https://cwe.mitre.org/data/definitions/315.html),
  [CWE-532](https://cwe.mitre.org/data/definitions/532.html),
  [CWE-539](https://cwe.mitre.org/data/definitions/539.html).
- **Privacy-focused**: By default, the scanner runs in your environment. Your code never leaves your premises.
- **Fast and lightweight**: Written in Rust for speed, safety and portability, the scanner can go through 1 million
  lines of code in under a minute on modern hardware. The unzipped binary is less than 30MB in size.
- **Highly accurate**: We maintain a carefully curated set of rules covering multiple domains (PII, PHI, PIFI). We
  prioritize minimizing false positives and refine our rules regularly using AI-assisted workflows, human expert reviews
  and real-world testing.

## Free Features

- Source code scanning with our [standalone binary](https://github.com/hounddogai/hounddog/releases) or
  [Docker image](https://hub.docker.com/r/hounddogai/hounddog).
- Markdown reports showing point-in-time views of the PII data elements including sensitivity levels, occurrence
  counts, file locations and code snippets.

## Paid Features

- Monitoring on vulnerabilities exposing PII in cleartext (logs, files, cookies, tokens, and third-party APIs).
- Graphical PII dataflow visualizations.
- Integration with CI/CD pipelines and Jira.
- Security dashboard integration with GitHub Enterprise and GitLab Ultimate.
- Access to [HoundDog.ai Cloud Platform](https://app.hounddog.ai) for issue triage, RoPA (Record of Processing
  Activities) reports, and scanner rules customization.

## Supported Languages

- C# / .NET
- Golang (coming soon)
- Java
- JavaScript
- Kotlin
- Python
- Ruby
- TypeScript

## Requirements

For [standalone binary](https://github.com/hounddogai/hounddog/releases):

- **Operating System**: Linux, macOS, Windows
- **CPU Architecture**: AMD64 (x86-64), ARM64
- **Shell**: Bash, Zsh, Fish (Linux/macOS), or PowerShell (Windows)
- **Memory**: 2GB+ of free memory

For [Docker image](https://hub.docker.com/r/hounddogai/hounddog):

- Docker Engine (Linux) or Docker Desktop (Windows/macOS)
- Memory: 4GB+ allocated to Docker

We recommend at least 4 CPU cores and 8GB of memory for optimal performance.

## Installation

Run the commands below in your terminal to install the scanner or to upgrade to the latest version.

### Linux and macOS

To install in user directory at `~/.hounddog/bin/hounddog`:

```shell
curl -fsSL https://raw.githubusercontent.com/hounddogai/hounddog/main/install.sh | sh
```

To install system-wide at `/usr/local/bin/hounddog`:

```shell
curl -fsSL https://raw.githubusercontent.com/hounddogai/hounddog/main/install.sh | sudo sh
```

### Windows

To install the standalone executable at `%LocalAppData%\hounddog\bin\hounddog.exe` (in PowerShell):

```powershell
irm https://raw.githubusercontent.com/hounddogai/hounddog/main/install.ps1 | iex
```

### Manual Download

Download the standalone binary and checksum files directly from our
[releases page](https://github.com/hounddogai/hounddog/releases).

## Usage

To scan a directory using the standalone binary:

```shell
hounddog scan [DIRPATH] [OPTIONS]
```

To scan a directory using the Docker image:

```shell
docker run --pull=always -it --rm -v <DIRPATH>:/data hounddogai/hounddog hounddog scan [OPTIONS]
```

Use `--help` to see all available command-line options:

```shell
# For standalone binary
hounddog scan --help

# For Docker image
docker run --pull=always -it --rm hounddogai/hounddog hounddog scan --help
```

HoundDog.ai respects your `.gitignore` file. To ignore additional files or folders, create a `.hounddogignore` file
at the root of the target repository using the [.gitignore pattern format](https://git-scm.com/docs/gitignore). Please
refer to our [documentation](https://docs.hounddog.ai/scanner) for using a HoundDog API key to unlock paid features.

## Quickstart

For quick demonstration, we provide a [test application](https://github.com/hounddogai/hounddog-test-healthcare-app)
with deliberate security flaws.

First, clone the repository:

```shell
git clone https://github.com/hounddogai/hounddog-test-healthcare-app
```

Scan it with the `--output-format=markdown` option to generate an offline Markdown report:

```shell
hounddog scan hounddog-test-healthcare-app --output-format=markdown
```

Open the generated file `hounddog-test-healthcare-app/hounddog-{timestamp}.md` on your browser. We recommend using the
[Markdown Viewer](https://chromewebstore.google.com/detail/markdown-viewer/ckkdlimhmcjmikdlpkmbgfkaikojcbjk) Chrome
extension with **mermaid** and **toc** settings enabled. See [this](https://docs.hounddog.ai/scanner/markdown-report)
for more details.

## Uninstallation

### Linux and macOS

If installed in user directory at `~/.hounddog/bin/hounddog`:

```shell
rm -r ~/.hounddog
```

If installed system-wide at `/usr/local/bin/hounddog`:

```shell
sudo rm /usr/local/bin/hounddog
```

### Windows

If installed at `%LocalAppData%\hounddog\bin\hounddog.exe`:

```powershell
Remove-Item -Recurse -Force $env:LocalAppData\hounddog
```

## License

View [license information](https://hounddog.ai/terms-of-service/) for
HoundDog.ai's software.

## Contact

If you need any help or would like to send us feedback, please create a
[GitHub issue](https://github.com/hounddogai/hounddog/issues) or shoot us an email at
[support@hounddog.ai](mailto:support@hounddog.ai).
