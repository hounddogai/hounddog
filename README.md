# HoundDog.ai

## What is it?

[HoundDog.ai](https://hounddog.ai) is a state-of-the-art source code scanner
(SAST command-line tool) that helps organizations shift-left with the following
use cases:

- **Proactive PII Leak Prevention**: Stop PII leaks in logs, files, cookies,
  tokens, and third-party services early during code reviews to strengthen the
  data security posture and avoid costly remediation in production.
- **Third-Party Risk Mitigation**: Track third-party application dataflows and
  detect data processing agreement violations before they become real problems.
- **Automatic Data Mapping for Compliance**: Eliminate manual, error-prone
  documentation of processing activities relying on spreadsheets and internal
  surveys. Streamline the entire process while keeping pace with development
  and eliminate surprises from new product changes.

### Free Features

- Offline reports for point-in-time views of the sensitive data elements in
  your codebase, along with their sensitivity levels, occurrence counts, and
  relevant code snippets.

### Starter and Enterprise Features

- Continuous monitoring on vulnerable dataflows where PII is exposed in
  cleartext through various media such as logs, files, cookies, tokens, and
  third-party APIs.
- Dataflow visualization.
- CI/CD integration with GitHub Actions, GitLab CI/CD, CircleCI, Jenkins, Azure
  Pipelines, BitBucket Pipelines etc.
- Security dashboard integration with GitHub Enterprise and GitLab Ultimate.
- Access to [HoundDog.ai Cloud Platform](https://app.hounddog.ai) for triaging
  issues, creating Jira tasks, generating RoPA (Record of Processing Activities)
  reports, and customizing scan rules.
- (Coming soon) Automatic adjustments of scan rules based on your data
  processing agreements for continuous DPA compliance and risk mitigation.

## How is it different from other scanners?

- **Blazingly fast with a tiny footprint**: HoundDog.ai's code scanner is
  written in Rust, a language well-known for its performance and memory safety.
  It can scan 1 million lines of code in under a minute on modern hardware and
  the unzipped binary is less than 25MBs in size. It is lightweight with minimal
  impact on your build pipelines.
- **High accuracy**: We provide a rich and carefully curated set of rules and
  definitions covering multiple domains (e.g. PII, PHI, PIFI) out of the box.
  The rules are continuously improved using AI workflows, reviewed by human
  experts and tested against real-world codebases.
- **Privacy-focused**: By default, the scanner runs only in your environment
  and your source code never leaves your premises.
- **100% complementary with other scanners**: Our goal is not to replace
  Semgrep, Snyk, etc., but to fill an existing gap and be the best-in-class for
  PII detection. Here are some of the security categories covered extensively
  and uniquely by HoundDog.ai:
  [CWE-201](https://cwe.mitre.org/data/definitions/201.html),
  [CWE-209](https://cwe.mitre.org/data/definitions/209.html),
  [CWE-312](https://cwe.mitre.org/data/definitions/312.html),
  [CWE-313](https://cwe.mitre.org/data/definitions/313.html),
  [CWE-315](https://cwe.mitre.org/data/definitions/315.html),
  [CWE-532](https://cwe.mitre.org/data/definitions/532.html),
  [CWE-539](https://cwe.mitre.org/data/definitions/539.html).

## Requirements

- **Operating System:** Linux or macOS
- **CPU Architecture:** x86-64 or ARM64
- **Shell:** Bash, Zsh, or Fish
- **Memory:** Minimum 1GB of free RAM on the host machine

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

To upgrade, run the above installation command again. To uninstall,
see [Uninstallation](#uninstallation).

HoundDog.ai is also available as a [Docker image](https://hub.docker.com/r/hounddogai/hounddog).

## Usage

To scan a file or directory:

```shell
hounddog scan [path] [options]
```

To see all available options:

```shell
hounddog scan --help
```

## Quickstart

To demonstrate the capabilities of the scanner, HoundDog.ai offers a test
application with deliberate security flaws. First, clone the repository:

```shell
git clone https://github.com/hounddogai/hounddog-test-healthcare-app
```

Then scan it with `--output-format=markdown` to generate a Markdown report:

```shell
hounddog scan hounddog-test-healthcare-app --output-format=markdown
```

Open the generated file `hounddog-test-healthcare-app/hounddog-{timestamp}.md`
on your browser.

**Note:** We recommend using Google Chrome and the
[Markdown Viewer](https://chromewebstore.google.com/detail/markdown-viewer/ckkdlimhmcjmikdlpkmbgfkaikojcbjk)
extension, with **mermaid** and **toc** settings enabled
(see [here](https://docs.hounddog.ai/scanner/markdown-report) for more details).

## Uninstallation

If installed in user directory at `~/.hounddog/bin/hounddog`:

```shell
rm -r ~/.hounddog
```

If installed system-wide at `/usr/local/bin/hounddog`:

```shell
sudo rm /usr/local/bin/hounddog
```

## Documentation

Please refer to our [user documentation](https://docs.hounddog.ai/scanner) for
detailed information on using the code scanner, and the cloud web application
for paid users.

## License

View [license information](https://hounddog.ai/terms-of-service/) for
HoundDog.ai's software.

## Contact

If you need any help or would like to send us feedback, please create a [GitHub
issue](https://github.com/hounddogai/hounddog/issues) or shoot us an email
at [support@hounddog.ai](mailto:support@hounddog.ai).
