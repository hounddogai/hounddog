# HoundDog.ai - Privacy Code Scanner and Dataflow Context Engine

[HoundDog.ai](https://hounddog.ai) is an ultra-fast, deterministic context engine that scans source code and provides 
your AI agents where sensitive data flows, and how your APIs and services connect.

## Two capabilities, one scan

### Privacy Code Scanner

Detects sensitive data flows and leaks in your code, mapping 100+ sensitive data elements across 800+ data sinks.

**It answers questions such as:**

- What data is processed? (e.g., personal data, financial data, health data)
- Where is data stored? (e.g., logs, files, databases)
- Who is data shared with? (e.g., AWS, Stripe, internal microservices)

**It is useful for:**

- Early prevention of data leaks during development.
- Automated and evidence-based data mapping for privacy compliance (e.g., GDPR, HIPAA).
- Reducing engineering fatigue, stale data inventories, and regulatory fines.

### Dataflow Context Engine

Builds a live, cross-repo catalog of every gRPC and Apache Thrift connections, so AI coding agents have reliable context
instead of rediscovering it on every prompt.

**It answers questions such as:**

- What gRPC/Thrift services exist, and which methods do they expose?
- Where is each service defined, and who calls it? (file, line, branch, commit)
- What breaks across repositories if I change or remove a field or an RPC?

**It is useful for:**

- Giving AI coding agents deterministic, up-to-date context to reason about API and service changes.
- Reducing wasted tokens and time spent re-analyzing the codebase on every prompt.
- Keeping a service catalog accurate at the speed of development, with no manual upkeep.

**HoundDog.ai in action:**

[![Demo GIF](https://raw.githubusercontent.com/hounddogai/hounddog/main/demo.gif)](https://raw.githubusercontent.com/hounddogai/hounddog/main/demo.gif)

**Technical highlights:**

- Runs as a standalone binary on your machine. Your code never leaves your environment by default. For
  organization-wide, in-network deployment,
  see [self-hosted installation](https://github.com/hounddogai/hounddog/tree/main/self-hosted).
- Fast and ready for large codebases. It can scan 1 million+ lines of code in seconds on modern laptops.
- Deterministic static analysis. The same commit produces the same result, every time.
- Supports 100s of [data elements](https://github.com/hounddogai/hounddog/blob/main/data-elements.md)
  and [sinks](https://github.com/hounddogai/hounddog/blob/main/data-sinks.md) out of the box.

Check out the [sample Markdown report](https://github.com/hounddogai/hounddog/blob/main/sample-report.md)
and [FAQ](#faq) for more information.

## Installation

Install HoundDog.ai on a developer machine using the commands below. To run it across your organization inside your own
network, see the [self-hosted installation guide](https://github.com/hounddogai/hounddog/tree/main/self-hosted).

### Linux and macOS

```
curl -fsSL https://raw.githubusercontent.com/hounddogai/hounddog/main/install.sh | sh
```

To install a specific version:

```
curl -fsSL https://raw.githubusercontent.com/hounddogai/hounddog/main/install.sh | sh -s -- --version 1.2.3
```

### Windows

```
irm https://raw.githubusercontent.com/hounddogai/hounddog/main/install.ps1 | iex
```

To install a specific version:

```
$env:HOUNDDOG_VERSION = '1.2.3'; irm https://raw.githubusercontent.com/hounddogai/hounddog/main/install.ps1 | iex
```

Alternatively, you can download the binary directly from the [releases](https://github.com/hounddogai/hounddog/releases)
page.

### Self-Hosted (Organization-Wide)

To deploy HoundDog.ai across your organization inside your own network, with SCM integration, automated scans, and a
centralized dataflow and API context catalog, follow the
[self-hosted installation guide](https://github.com/hounddogai/hounddog/tree/main/self-hosted).

### Uninstallation

```
# Linux and macOS
rm -rf ~/.hounddog

# Windows
Remove-Item -Recurse -Force "$env:LocalAppData\hounddog"
```

## Usage

```
hounddog scan [OPTIONS] [PATH]
```

A single scan produces both the privacy dataflow map and the API/service context for the target codebase.

### Privacy Code Scanner

For a quick demonstration, scan our [Python test repository](https://github.com/hounddogai/hounddog-test-python-app):

```
# Clone the test repository
git clone https://github.com/hounddogai/hounddog-test-python-app

# Scan the test repository
hounddog scan hounddog-test-python-app
```

By default, only *risky* dataflows are shown to minimize noise. Use `--severity=all` to see everything:

```
hounddog scan hounddog-test-python-app --severity=all
```

Use `--trace` to see detailed dataflow traces (one of our coolest features and useful for debugging):

```
hounddog scan hounddog-test-python-app --trace
```

Use `--output-format=markdown` to generate a Markdown report:

```
hounddog scan hounddog-test-python-app --output-format=markdown --output-path=report.md
```

We recommend
the [Markdown Viewer](https://chromewebstore.google.com/detail/markdown-viewer/ckkdlimhmcjmikdlpkmbgfkaikojcbjk) Chrome
extension for viewing it (see [setup](https://docs.hounddog.ai/scanner/markdown-report)
and [sample report](https://github.com/hounddogai/hounddog/blob/main/sample-report.md)).

### Dataflow Context Engine

To see the API and service context across a polyglot codebase, scan our
[monorepo test repository](https://github.com/hounddogai/hounddog-test-monorepo), which spans gRPC and Thrift services
in Python, TypeScript, C#, Java, Go, and Rust:

```
# Clone the test repository
git clone https://github.com/hounddogai/hounddog-test-monorepo

# Scan the test repository
hounddog scan hounddog-test-monorepo
```

Alongside the dataflow map, the scan prints a service catalog for each protocol. It resolves every service, its method
definitions, and the servers and clients that implement and consume it, down to the file, line, branch, and commit.
Across a whole organization, the
[self-hosted deployment](https://github.com/hounddogai/hounddog/tree/main/self-hosted) unifies these per-repo catalogs
into a single cross-repo catalog and refreshes it in CI on every pull request. A HoundDog.ai MCP server that will expose
this context directly to AI coding agents is coming soon.

### More Options

To see the up-to-date list of supported data elements in HTML format:

```
hounddog data-elements
```

To see the up-to-date list of supported data sinks in HTML format:

```
hounddog data-sinks
```

Use `--help` to see all subcommands and options:

```
hounddog [SUBCOMMAND] --help
```

## Features

HoundDog.ai has two capability pillars. Both run from the same `hounddog scan` and are available in a free tier on a
developer machine or across your organization via
[self-hosted installation](https://github.com/hounddogai/hounddog/tree/main/self-hosted).

### Privacy Code Scanner

|                     | Free                                                                                                                                                                                                                              | Enterprise                                                                                                                                                                                                                        |
|---------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Supported Languages | Python, JavaScript, TypeScript                                                                                                                                                                                                    | Languages in Free + C#, Go, Java, SQL, OpenAPI                                                                                                                                                                                    |
| Usage Options       | CLI, IDE                                                                                                                                                                                                                          | CLI, IDE, GitHub Integration (Automated Scans, PR Reviews)                                                                                                                                                                        |
| IDE Plugins         | [VS Code](https://marketplace.visualstudio.com/items?itemName=hounddog.hounddog-scanner), [JetBrains](https://plugins.jetbrains.com/plugin/25684-hounddog-ai), [Cursor](https://open-vsx.org/extension/hounddog/hounddog-scanner) | [VS Code](https://marketplace.visualstudio.com/items?itemName=hounddog.hounddog-scanner), [JetBrains](https://plugins.jetbrains.com/plugin/25684-hounddog-ai), [Cursor](https://open-vsx.org/extension/hounddog/hounddog-scanner) |
| Dataflow Detection  | Limited Coverage                                                                                                                                                                                                                  | Full Coverage                                                                                                                                                                                                                     |
| Rule Customization  | No                                                                                                                                                                                                                                | Custom Data Element and Data Sink Rules                                                                                                                                                                                           |
| Privacy Reports     | No                                                                                                                                                                                                                                | RoPA, PIA, DPIA                                                                                                                                                                                                                   |
| Cloud Platform      | No                                                                                                                                                                                                                                | Issue Tracking, Alerts, SSO, RBAC, Audit Logs                                                                                                                                                                                     |
| On-Prem Deployment  | No                                                                                                                                                                                                                                | [Included](https://github.com/hounddogai/hounddog/tree/main/self-hosted)                                                                                                                                                          |
| Support             | GitHub Issues + Email                                                                                                                                                                                                             | Priority Support with SLA + Dedicated Slack Channel                                                                                                                                                                               |

### Dataflow Context Engine

|                     | Local (Free)                                                                                                            | Centralized (Enterprise)                                                                                          |
|---------------------|-------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| Supported Protocols | gRPC, Thrift (REST on the roadmap)                                                                                      | gRPC, Thrift (REST on the roadmap)                                                                                |
| Supported Languages | Python, JavaScript, TypeScript, C#, Go, Java, Rust                                                                      | Python, JavaScript, TypeScript, C#, Go, Java, Rust                                                                |
| Scope               | Whatever code is checked out locally                                                                                    | Every selected repository across the organization, no local checkout required                                     |
| Catalog Contents    | Per-scan service catalog: services, method definitions, servers, and clients resolved to file, line, branch, and commit | Same, unified into one cross-repo catalog across the entire estate                                                |
| Refresh             | On demand, per scan                                                                                                     | Automatically in CI on every pull request                                                                         |
| Agent Access        | Structured JSON output today; local MCP server coming soon                                                              | API and web UI today; centralized MCP server coming soon                                                          |
| SCM Integration     | No                                                                                                                      | GitHub, GitLab, Bitbucket                                                                                         |
| Deployment          | Runs on the developer's machine                                                                                         | Cloud or [on-prem, self-hosted in your own network](https://github.com/hounddogai/hounddog/tree/main/self-hosted) |
| Access Controls     | No                                                                                                                      | SSO, RBAC, Audit Logs                                                                                             |
| Support             | GitHub Issues + Email                                                                                                   | Priority Support with SLA + Dedicated Slack Channel                                                               |

## FAQ

### How can I trust your scanner?

Visit our [Trust Center](https://security.hounddog.ai/) to view our latest SOC2 report, penetration testing results, and
SBOM details.

### Does your scanner send my code to external servers?

Not by default. Scans run locally, and your code never leaves your machine. For organization-wide use, the
[self-hosted deployment](https://github.com/hounddogai/hounddog/tree/main/self-hosted) runs entirely inside your own
network, so code and the resulting catalog stay within your infrastructure. If your organization explicitly enables the
optional Enterprise AI review, HoundDog.ai sends the relevant finding, trace, and source context directly to the AI
provider your organization configured.

### Does your scanner use AI?

Scans themselves run on a deterministic static analysis engine. Nothing from your scan is sent to an AI provider unless
your organization explicitly enables the optional Enterprise AI review. This keeps scans fast, cheap, and free of
hallucinations. It applies to both pillars: the privacy data map and the API/service context are both produced
deterministically.

HoundDog.ai uses AI internally to help generate and update data detection rules before those rules are shipped with the
scanner. Customer code and scan results are not used for this process.

Separately, the [Enterprise](#features) offering (both cloud
and [on-prem, self-hosted](https://github.com/hounddogai/hounddog/tree/main/self-hosted))
includes an optional AI integration layered on top of the static findings. Your organization chooses and configures its
own AI provider, AWS Bedrock, Anthropic, OpenAI, Google Gemini, or Microsoft Foundry, using its own API key. When
enabled, HoundDog.ai sends the relevant finding, trace, and source context directly to that provider under the DPA and
other terms your organization holds with the provider. HoundDog.ai does not use customer code, findings, prompts, or
responses to train AI models. This optional layer auto-closes false positives, adjusts severities, and adds context to
the findings the scanner already produced. The deterministic scan continues to run within your CI environment on
inexpensive CPU with negligible impact on CI time.

### What is the Dataflow Context Engine, and how does it help AI coding agents?

Standards like OpenAPI, protobuf, and Thrift IDLs describe what an API is, but not which services consume it, which
fields are actually used, or what breaks when something changes. Without that context, an AI coding agent rediscovers it
on every prompt by grepping repositories and generating throwaway scripts, which is slow, expensive, and often
incomplete.

HoundDog.ai builds this context deterministically from your code: every service, method, and client call site, resolved
to a file, line, branch, and commit. The catalog is available today through structured JSON output and the Enterprise
API Catalog. A HoundDog.ai MCP server that will expose this context directly to agents is coming soon. This matters most
for smaller or self-hosted models, which are weaker at cross-repo dependency discovery and benefit most from being
handed accurate context. For organization-wide, cross-repo context refreshed in CI, see the
[self-hosted installation guide](https://github.com/hounddogai/hounddog/tree/main/self-hosted).

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
email us at <support@hounddog.ai>.
