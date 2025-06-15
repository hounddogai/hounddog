# HoundDog.ai - Privacy-by-Design Code Scanner

## What is it?

[HoundDog.ai](https://hounddog.ai/) is a privacy-by-design code scanner that catches unintentional developer (or AI-generated) mistakes that expose sensitive data such as Personally Identifiable Information (PII), Protected Health Information (PHI), Cardholder Data (CHD), and authentication tokens across risky mediums such as logs, files, local storage, and cookies.

HoundDog.ai secures AI applications by enforcing guardrails around the types of sensitive data embedded in prompts sent to LLMs, and by detecting leaks in prompt logs, temporary files, and other AI-specific risky mediums. Rather than relying on reactive DLP tools or post-deployment sanitization, HoundDog.ai enables proactive data minimization from the very first line of code.

Our scanner can be used as a CLI that installs locally to scan cloned code repositories, or as IDE plugins that flag sensitive data leak issues as code is being written. The IDE plugins are available for [VSCode](https://marketplace.visualstudio.com/items?itemName=hounddog.hounddog-scanner), [JetBrains](https://plugins.jetbrains.com/plugin/25684-hounddog-ai), and [Eclipse](https://marketplace.eclipse.org/content/hounddogai). The HoundDog.ai Cloud Platform (offered as part of the paid plan) also provides Source Code Management Platform Integrations - connecting directly to GitHub, GitLab, and Bitbucket (both cloud and enterprise versions) to automatically scan code, block PRs, and leave actionable PR comments.

## Features (Free vs. Paid)

|   | Free | Paid |
| ---- | ---- | ---- |
| Supported Languages  | **Python**, **TypeScript**  | <p>Languages covered in the free plan +<br><br> **Java**, **C#**, **Kotlin**, **Ruby**, **Go**, **OpenAPI**, **GraphQL**, **SQL**</p> |
| Data Elements  | **100+ sensitive data elements** with extensive coverage of auth tokens, PII, PHI, and CHD  | <p>Data elements covered in the free plan + </p><ul><li>**User-defined data elements** - add custom patterns to detect sensitive data unique to your organization.</li><li> *[Coming Soon]* **AI-detected data elements**, enabled through integration with any LLM model running in your environment.</li></ul> |
| Data Sinks  | Risky Mediums in Traditional Apps:<br><ul><li>**Logs**</li><li>**Files**</li><li>**JWT tokens**</li><li>**Local storage**</li><li>**Cookies**</li></ul>Privacy Risks in AI Applications:<br><ul><li>**Prompt analysis** – tracking the types of sensitive data exposed in OpenAI, Anthropic, and Gemini prompts</li><li>**Prompt logging**</li><li>Saving prompts to **temporary files**</li></ul> | <p>Data sinks in the free plan +</p><ul><li>**Other Third-Party Integrations (SDK + API)** – more than 100 integrations covering monitoring, sales/marketing, web analytics, etc.</li><li>*[Coming Soon]* **AI-detected data sinks** leveraging an integration with any LLM model running within your environment</li></ul> |
| Features   | <p>**Sensitive Data Leak Vulnerabilities**<br>Identify when sensitive data is exposed in risky mediums, often due to entire user objects or tainted variables leaking into sinks. Includes AI-specific cases like LLM prompts capturing excessive data.</p><p>**Sensitive Data Map**<br>View all sensitive data elements detected in the scanned codebase, along with their sensitivity levels and number of occurrences.</p><p><strong>IDE Plugins</strong><br>Detect sensitive data leak issues as code is being written. Available for VS Code, JetBrains, and Eclipse.</p> | <p>**Data Flow Intelligence**<ul><li>Visualize the flow of sensitive data across all storage mediums and third-party integrations providing evidence-based data mapping that eliminates guesswork and minimizes errors.</li></ul></p><p>**Automated Privacy Compliance**<ul><li>Automate the creation of Records of Processing Activities (RoPA), Privacy Impact Assessments (PIA), and Data Protection Impact Assessments (DPIA) reports all pre-populated with data flows and privacy risks detected by the scanner.</li><li>Catch data processing agreement (DPA) violations caused by sensitive data oversharing with third-party integrations early avoiding costly production issues.</li><li>Get real-time alerts when new types of sensitive data elements are introduced to the codebase, categorized by sensitivity level.</li></ul></p><p>**Developer Workflow Integration**<ul><li>Integrate with GitHub, GitLab, Bitbucket (Cloud & Enterprise).</li><li>Automatically scan code, block non-compliant PRs, and get actionable comments.</li></ul><p>**Enterprise-Ready Platform**<ul><li>SAML/SSO (Okta, Entra ID, Google).</li><li>Email & Slack alerting, Jira integration, and SIEM-compatible audit logs.</li><li>SOC 2-Compliant platform.</li></ul></p> |

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

### Free Version

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
at the root of the target repository using the [.gitignore pattern format](https://git-scm.com/docs/gitignore).

### Paid Version

To use the paid features, export the API key (generated from the HoundDog.ai Cloud Platform) before running the hounddog scan command.

```shell
export HOUNDDOG_API_KEY="your_hounddog_api_key_here"
```

If you are using the Docker image, you must provide the -e option in the docker run command to pass the environment variable from your host to the Docker container:

```shell
docker run -v <path>:/data -e HOUNDDOG_API_KEY=$HOUNDDOG_API_KEY hounddogai/hounddog hounddog scan
```

Please refer to our [documentation](https://docs.hounddog.ai/scanner) for using a HoundDog API key to unlock paid features.

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

## Use Cases

<details>

### Early prevention of sensitive data leaks in logs (and other risky mediums)

**Sponsoring Team**
- Data Security
- Privacy

**Team Owning the Solution**
- Application Security (given their role in managing other code scanners in the CI pipelines)

**The Challenge**

When sensitive data leaks into logs (or other risky mediums), it’s a clear violation of:
- GDPR, CCPA, and similar privacy laws for PII
- HIPAA for PHI
- PCI DSS for CHD

Relying on DLP is reactive, unreliable, and painfully slow. Teams often spend weeks scrubbing logs, tracing exposure across downstream systems, and patching the code after the fact.

**The Solution**

- HoundDog.ai analyzes code early in the development lifecycle to catch sensitive data exposure in risky mediums such as logs, files, local storage, and cookies. Most issues are caused by entire user objects or tainted variables leaking into risky data sinks, often due to unintentional developer mistakes or AI-generated code.
- For AI applications, the scanner also detects leaks in AI-specific mediums like prompt logs, temporary files, and LLM prompts that capture more sensitive data than intended. This proactive approach reduces dependence on reactive tools like DLP or downstream sanitization of LLM inputs and outputs.
- Enables data minimization from the earliest stages of development, preventing issues before they reach production.


### Evidence-based data mapping for all internally-built applications

**Sponsoring Team**
- Privacy

**Team Owning the Solution**
- Application Security (given their role in managing other code scanners in the CI pipelines)

**The Challenge**

- Data mapping, documenting all types of data collected, processed, and shared, is the cornerstone of all major privacy frameworks.
- Today, many companies rely on manual surveys and spreadsheets for data collection, leading to incomplete and outdated data maps that fail to reflect the latest code changes.
- Data privacy platforms still rely on reactive data collection, with discovery mechanisms that depend heavily on sampling and surface-level scans, making them prone to missing critical data flows.
- These platforms require prior knowledge of all third-party tools in use, making them blind to shadow third-party integrations introduced directly in the code by developers.
- Operating post-deployment and disconnected from code-level changes, these tools create a significant lag in identifying and mitigating risks.

**The Solution**

- HoundDog.ai analyzes code early to deliver evidence-based data mapping at the speed of development.
- Privacy teams can accurately document sensitive data flows across all storage mediums (e.g., logs, files, local storage, databases) and third-party integrations (APIs and SDKs).
- Real-time alerts notify teams when new sensitive data elements are introduced in the code, allowing time to review and address issues before they reach production.
- Seamless integration across the development lifecycle (IDE, CI/CD) enables privacy by design at scale.
- Automates the generation of RoPA, PIA, and DPIA reports, pre-populated with detected data flows and privacy risks—eliminating manual data collection via surveys and spreadsheets.

</details>

## Sensitive Data Leak Prevention: Tool Comparison

| Methods | Pros & Cons | Typical Coverage |
| ---- | ---- | ---- |
| HoundDog.ai | <p>**Pros**:<ul><li>Early detection across all stages of development from IDE to CI.</li><li>Extensive out-of-the-box coverage with support for 100+ sensitive data types (PII, PHI, PIFI, CHD, etc.), risky data sinks (hundreds of third-party SDKs), and sanitization gaps (flags only unsanitized data to reduce noise).</li><li>Deep coverage of AI-specific flows, including unsanitized inputs to and outputs from LLMs.</li><li>Highly extensible with custom data types and granular allowlists to enforce data policies and uphold DPAs.</li><li> *[Coming Soon]* AI-powered and integrated with any LLM running within the environment to extend coverage with minimal tuning.</li></ul></p><p>**Cons**:<ul><li>May miss data generated only at runtime</li></ul></p> | <p>**Traditional Risky Mediums**:<ul><li>Logs</li><li>Files</li><li>Local Storages</li><li>Cookies</li><li>Third-Party (API + SDK)</li></ul></p><p>**AI-Specific Risky Mediums**:<ul><li>Prompt Logs</li><li>Temp Files</li><li>Prompt I/O</li></ul></p> |
| DIY SAST | <p>**Pros**:<ul><li>Customizable - rules can be tailored to specific data types</li></ul></p><p>**Cons**:<ul><li>Very time consuming, as it requires significant effort to create and maintain rules.</li><li>Brittle RegEx patterns are hard to scale and need frequent updates as the codebase evolves.</li><li>Lacks context around data sensitivity and sanitization.</li><li>Poor at tracking data sinks - typically limited to logs.</li><li>Fails to scale effectively across large or complex environments.</li></ul></p> | <p>**Traditional Risky Mediums**:<ul><li>Logs</li><li>Rarely covers other mediums</li></ul></p><p>**AI-Specific Risky Mediums**:<ul><li>Prompt Logs (with effort)</li></ul></p> |
| DLP | <p>**Pros**:<ul><li>Detects sensitive data in transit or at rest across network and storage layers.</li></ul></p><p>**Cons**<ul><li>Reactive rather than preventative - typically catches issues after data exposure has occurred.</li><li>Remediation is slow and operationally intensive, often taking weeks: teams must scrub logs or storage, stop data ingestion, and work backward to trace the source of the leak with little context.</li><li>Lacks code-level visibility, making it difficult to pinpoint the exact logic or source responsible.</li><li>Limited insight into business logic, SDKs, or AI-specific data handling.</li></ul></p> |<p>**Traditional Risky Mediums**:<ul><li>Logs</li><li>Files</li></ul></p><p>**AI-Specific Risky Mediums**:<ul><li>None</li></ul></p> |

## License

View [license information](https://hounddog.ai/terms-of-service/) for
HoundDog.ai's software.

## Contact

If you need any help or would like to send us feedback, please create a
[GitHub issue](https://github.com/hounddogai/hounddog/issues) or shoot us an email at
[support@hounddog.ai](mailto:support@hounddog.ai).