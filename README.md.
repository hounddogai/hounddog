# HoundDog.ai - Modern Privacy Code Scanner

[HoundDog.ai](https://hounddog.ai) is an ultra-fast privacy scanner that detects sensitive data flows and leaks in your
code.

**It answers questions such as:**

- What data is processed? (e.g., personal data, financial data, health data)
- Where is data stored? (e.g., logs, files, databases)
- Who is data shared with? (e.g., AWS, Stripe, internal microservices)

**It is useful for:**

- Early prevention of data leaks during development.
- Automated and evidence-based data mapping for privacy compliance (e.g., GDPR, HIPAA).
- Reducing engineering fatigue, stale data inventories, and regulatory fines.

**HoundDog.ai in action:**

![Demo GIF](https://raw.githubusercontent.com/hounddogai/hounddog/main/demo.gif)

**Its technical highlights:**

- Runs as a standalone binary on your machine. Your code never leaves your environment by default.
- Fast and ready for large codebases. It can scan 1 million+ lines of code in seconds on modern laptops.
- Supports 100s of [data elements](./data-elements.md) and [sinks](./data-sinks.md) out of the box.

Check out the [sample Markdown report](./sample-report.md) and [FAQ](#faq) for more information.

## Installation

### Linux and macOS

```shell
curl -fsSL https://raw.githubusercontent.com/hounddogai/hounddog/main/install.sh | sh
```

### Windows

```shell
irm https://raw.githubusercontent.com/hounddogai/hounddog/main/install.ps1 | iex
```

Alternatively, you can download the binary directly from the [releases](https://github.com/hounddogai/hounddog/releases)
page.

### Uninstallation

```shell
# Linux and macOS
rm -rf ~/.hounddog

# Windows
Remove-Item -Recurse -Force "$env:LocalAppData\hounddog"
```

## Usage

```shell
hounddog scan [OPTIONS] [PATH]
```

For a quick demonstration, you can scan our [test repository][test-repository]:

[test-repository]: https://github.com/hounddogai/hounddog-test-python-app

```shell
# Clone the test repository
git clone https://github.com/hounddogai/hounddog-test-python-app

# Scan the test repository
hounddog scan hounddog-test-python-app
```

By default, only *risky* dataflows are shown to minimize noise. Use `--all-dataflows` to see everything:

```shell
hounddog scan hounddog-test-python-app --all-dataflows
```

Use `--trace` to see detailed dataflow traces (one of our coolest features and useful for debugging):

```shell
hounddog scan hounddog-test-python-app --trace
```

Use `--output-format=markdown` to generate a Markdown report:

```shell
hounddog scan hounddog-test-python-app --output-format=markdown --output-file=report.md
```

We recommend the [Markdown Viewer][md-viewer-ext] Chrome extension for viewing it (see [setup][md-viewer-doc]
and [sample report](./sample-report.md)).

[md-viewer-doc]: https://docs.hounddog.ai/scanner/markdown-report

[md-viewer-ext]: https://chromewebstore.google.com/detail/markdown-viewer/ckkdlimhmcjmikdlpkmbgfkaikojcbjk

To see the up-to-date list of supported data elements in HTML format:

```shell
hounddog data-elements
```

To see the up-to-date list of supported data sinks in HTML format:

```shell
hounddog data-sinks
```

Use `--help` to see all subcommands and options:

```shell
hounddog [SUBCOMMAND] --help
```

## Features

|                     | Free                                                        | Enterprise                                                  |
|---------------------|-------------------------------------------------------------|-------------------------------------------------------------|
| Supported Languages | Python, JavaScript, TypeScript                              | Languages in Free + C#, Go, Java, SQL, GraphQL, OpenAPI     |
| Usage Options       | CLI, IDE                                                    | CLI, IDE, GitHub Integration (Automated Scans, PR Reviews)  |
| IDE Plugins         | [VS Code][vscode], [JetBrains][jetbrains], [Cursor][cursor] | [VS Code][vscode], [JetBrains][jetbrains], [Cursor][cursor] |
| Dataflow Detection  | Limited Coverage                                            | Full Coverage                                               |
| Rule Customization  | No                                                          | Custom Data Element and Data Sink Rules                     |
| Privacy Reports     | No                                                          | RoPA, PIA, DPIA                                             |
| Cloud Platform      | No                                                          | Issue Tracking, Alerts, SSO, RBAC, Audit Logs               |
| On-Prem Deployment  | No                                                          | Included                                                    |
| Support             | GitHub Issues + Email                                       | Priority Support with SLA + Dedicated Slack Channel         |

[vscode]: https://marketplace.visualstudio.com/items?itemName=hounddog.hounddog-scanner

[jetbrains]: https://plugins.jetbrains.com/plugin/25684-hounddog-ai

[cursor]: https://open-vsx.org/extension/hounddog/hounddog-scanner

## FAQ

### How can I trust your scanner?

Visit our [Trust Center](https://security.hounddog.ai/) to view our latest SOC2 report, penetration testing results,
and SBOM details.

### Does your scanner send my code to external servers?

No. Scans run locally. Your code never leaves your machine.

### Does your scanner use AI?

AI is used to generate and update data detection rules for scaling coverage, but scans themselves run on a deterministic
static analysis engine. This keeps scans fast, cheap, and free of hallucinations.

### Why should I use your scanner instead of a large-language model?

LLMs can discover issues that traditional SAST tools miss, but they are slow, expensive, and non-deterministic. SAST
tools are faster, cheaper, and predictable, but require high-effort rule maintenance and suffer from high false positive
rates.

HoundDog.ai’s vision is to combine the strengths of both approaches. Our scanning engine is fully rule-based and
deterministic, with a rule specification expressive enough to model real-world code at compiler-level accuracy. AI is
used selectively to scale coverage across thousands of code patterns without sacrificing performance, reliability, and
trust.

### How is your scanner different from secrets scanning tools like GitLeaks or TruffleHog?

Secrets scanning tools look for credentials that are hardcoded directly in code, such as API keys, passwords, or tokens.
For example:

```python
exposed_api_key = "sk-proj-1234567890-abcdefghijklmnopqrstuvwxyz"
```

HoundDog.ai, on the other hand, focuses on how sensitive data actually flows through code. It tracks values across
various code paths such as assignment statements and transformations. For example:

```python
import logging
import os

logger = logging.getLogger(__name__)

# HoundDog.ai detects that `foo` is an authentication token.
foo = os.environ.get("MY_API_KEY")

# HoundDog.ai traces values through various code paths.
bar = {"message": f"api_key={foo}".strip()}

# HoundDog.ai detects that `bar` contains an authentication token (tainted) and is leaked to a log.
logger.info("data=%s", bar)
```

### How is your scanner different from Semgrep or CodeQL?

DIY SAST tools like Semgrep and CodeQL are powerful and highly customizable, but their rules need significant upfront
investment to learn and maintain.

HoundDog.ai is a turnkey solution that provides broad, high-quality coverage of data elements and sinks out of the box,
greatly reducing the rule authoring burden. It is designed specifically for dataflow analysis, scaling efficiently to
large codebases, and detecting complex data flows that general-purpose solutions miss.

### Your scanner missed a dataflow!

Our rules are constantly evolving, and we are working hard on improving them. Please let us know any false positives or
negatives, and we will be happy to address them.

## License

View [license information](https://hounddog.ai/terms-of-service/) for HoundDog.ai's software.

## Contact

If you have any questions or feedback, please create a [GitHub issue](https://github.com/hounddogai/hounddog/issues) or
email us at [support@hounddog.ai](mailto:support@hounddog.ai).
