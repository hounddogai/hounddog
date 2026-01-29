# HoundDog.ai — Modern Privacy Code Scanner

HoundDog.ai is a fast, lightweight scanner that detects sensitive data flows and potential leaks in your source code.

**It answers questions such as:**

- What data is processed? (e.g., personal data, financial data, health data)
- Where is data stored? (e.g., logs, files, databases)
- Who is data shared with? (e.g., AWS, Stripe, internal microservices)

**It is useful for:**

- Early prevention of data leaks during development
- Automated and evidence-based data mapping for privacy compliance (e.g., GDPR, HIPAA)
- Reducing engineering fatigue, stale data inventories, and regulatory fines

![Demo GIF](https://raw.githubusercontent.com/hounddogai/hounddog/main/demo.gif)

Here is an [example scan output](./hounddog-sample-report.md) and the complete list
of [data elements](./hounddog-data-elements.md) and [data sinks](./hounddog-data-sinks.md) supported.

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
hounddog scan [PATH] [OPTIONS]
```

For a quick demonstration, you can scan a public [test repository][test-repository] with baked in data flows:

[test-repository]: https://github.com/hounddogai/hounddog-test-healthcare-app

```shell
# Clone
git clone https://github.com/hounddogai/hounddog-test-healthcare-app

# Scan
hounddog scan hounddog-test-healthcare-app
```

You can also scan with the `--output-format=markdown` flag to generate a Markdown report:

```shell
hounddog scan hounddog-test-python-app --output-format=markdown
```

We recommend using the [Markdown Viewer][md-viewer-ext] Chrome extension with **mermaid** and **toc** options enabled.
See [instructions][md-viewer-doc] and a [sample report](./hounddog-sample-report.md) for more information.

[md-viewer-doc]: https://docs.hounddog.ai/scanner/markdown-report

[md-viewer-ext]: https://chromewebstore.google.com/detail/markdown-viewer/ckkdlimhmcjmikdlpkmbgfkaikojcbjk

To see all available commands, run `hounddog --help`.

## Features

|                         | Free                                                        | Enterprise                                                  |
|-------------------------|-------------------------------------------------------------|-------------------------------------------------------------|
| Supported Languages     | Python, JavaScript/TypeScript                               | Languages in Free + C#, Go, Java, SQL, GraphQL, OpenAPI     |
| Usage Options           | CLI, IDE                                                    | CLI, IDE, GitHub Integration (Automated Scans, PR Reviews)  |
| IDE Plugins             | [VS Code][vscode], [JetBrains][jetbrains], [Cursor][cursor] | [VS Code][vscode], [JetBrains][jetbrains], [Cursor][cursor] |
| Data Flow Detection     | Limited Coverage                                            | Full Coverage                                               |
| Data Flow Visualization | Limited Coverage                                            | Full Coverage                                               |
| Rule Customization      | No                                                          | Custom Data Element and Data Sink Rules                     |
| Privacy Reports         | No                                                          | RoPA, PIA, DPIA                                             |
| Cloud Platform          | No                                                          | Issue Tracking, Alerts, SSO, RBAC, Audit Logs               |
| On-Prem Deployment      | No                                                          | Included                                                    |
| Support                 | GitHub Issues + Email                                       | Priority Support with SLA + Dedicated Slack Channel         |

[vscode]: https://marketplace.visualstudio.com/items?itemName=hounddog.hounddog-scanner

[jetbrains]: https://plugins.jetbrains.com/plugin/25684-hounddog-ai

[cursor]: https://open-vsx.org/extension/hounddog/hounddog-scanner

## FAQ

### How can I trust your scanner?

Visit our [Trust Center](https://security.hounddog.ai/) to view our latest SOC2 report, penetration testing results,
and SBOM details.

### Does the scanner send my code to a server?

No. Scans run locally. Your code never leaves your machine unless you are on a paid plan and explicitly configure the
`HOUNDDOG_API_KEY` environment variable.

### Does the scanner use AI?

AI is used to generate and update rules for scaling coverage, but scans themselves run on a deterministic static
analysis engine. This keeps scans fast and free of hallucinations.

### Why should I use your scanner instead of a large-language model?

LLMs can discover issues that rigid pattern-matching misses, but they are slow, expensive, and often non-deterministic.
Traditional SAST tools are faster, cheaper and predictable, but require high effort rule maintenance, struggle to keep
up with fast changing codebases, and suffer from high false positive rates.

HoundDog.ai’s vision is to combine the strengths of both approaches. The scanning engine is fully rule-based and
deterministic, with a rule specification expressive enough to model real-world code at compiler-level accuracy. AI is
used selectively to scale coverage across thousands of code patterns without sacrificing performance, repeatability, or
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
investment to learn and maintain, especially as the target codebases evolve.

HoundDog.ai is a turnkey solution that provides broad, high-quality coverage of data elements and sinks out of the box,
greatly reducing the rule authoring burden. It is designed specifically for inter-file data flow analysis, scaling
efficiently to large codebases, and detecting complex data flows that general-purpose solutions miss.

### The scanner missed a data flow!

Our rules are constantly evolving, and we are working hard on improving them. Please let us know any false positives or
negatives, and we will be happy to address them.

## License

View [license information](https://hounddog.ai/terms-of-service/) for HoundDog.ai's software.

## Contact

If you need help or have feedback, please create a [GitHub issue](https://github.com/hounddogai/hounddog/issues) or
email us at [support@hounddog.ai](mailto:support@hounddog.ai).
