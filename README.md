# Central Jenkins AI CVE Remediation Pipeline

This repository is the **central pipeline workspace**. Application repositories do not need this Jenkinsfile or these scripts. Jenkins checks out this repository as the job definition, then checks out the selected application repository into `app/` using job parameters.

## What it does

1. Checks required tools and parameters.
2. Checks out the chosen app repository and branch.
3. Runs a baseline build/test for Maven, Gradle, Node.js, Python, or a generic app.
4. Generates a CycloneDX SBOM with Syft and scans it with Trivy for Critical/High vulnerabilities.
5. Optionally sends bounded finding metadata and selected text files to a configured LiteLLM endpoint to propose a unified diff.
6. Requires a Jenkins approval before applying the proposal when `REQUIRE_DEVELOPER_APPROVAL=true`.
7. Applies the patch only in the job workspace, runs tests, generates a second SBOM/scan and a comparison report.
8. Archives reports. It **does not commit, push, create a PR, merge, or deploy**.

This is a starter implementation, not a guarantee of safe remediation. Review and test the scripts in a non-production repository before enabling broadly.

## Repository layout

- `Jenkinsfile` — reusable parameterized pipeline.
- `scripts/ai_fix.py` — LiteLLM proposal generation.
- `scripts/validate_patch.py` — basic path and patch validation.
- `scripts/summarize_findings.py` — Critical/High summary.
- `scripts/compare_cves.py` — before/after comparison.
- `config/severity-policy.yml` — policy reference.
- `prompts/remediation.txt` — remediation guidance.
- `tests/` — basic script tests.

## Prerequisites on Jenkins agent

Install and make available on the agent:

- Git
- Python 3.10+
- Syft
- Trivy
- Maven, Gradle, Node/npm, or Python build tools as appropriate for your applications
- Jenkins Pipeline and Git plugins

Use a disposable/isolated agent. The pipeline executes application build scripts and tests, so do not run untrusted application code on a privileged Jenkins controller or an agent with production credentials. The agent must be able to reach the configured LiteLLM endpoint.

## Jenkins credentials

Create these credentials under **Manage Jenkins → Credentials** (folder credentials are preferred where possible):

1. `app-scm-readonly` — Username/password or supported Git credential for checking out application repositories. For SSH URLs, configure the appropriate SSH private-key credential and set the parameter to that credential ID.
2. `litellm-api-key` — Secret text containing the LiteLLM API key.

Do not store credentials in this repository or in Jenkinsfile parameters. The default credential IDs can be overridden in the job.

## Create the central Git repository

1. Create a private Git repository, for example `ai-cve-remediation`.
2. Upload/push the contents of this ZIP to the repository root (the `Jenkinsfile` must be at the root).
3. Protect the default branch and restrict write access. Anyone who can modify a Jenkinsfile used by a job may be able to execute code on its agent.

## Configure Jenkins job

1. Select **New Item → Pipeline** and give it a name such as `Central-AI-CVE-Remediation`.
2. In **Pipeline**, choose **Pipeline script from SCM**.
3. SCM: **Git**. Set the central repository URL, credentials, and protected pipeline branch (e.g. `main`).
4. Script Path: `Jenkinsfile`.
5. Save and run **Build with Parameters**.
6. Enter the application repository URL and branch; choose `APP_TYPE` or use `AUTO`.
7. Configure `LITELLM_BASE_URL` and `LITELLM_MODEL` to match your deployment. The base URL should normally end in `/v1`; the script appends `/chat/completions`.
8. Keep `REQUIRE_DEVELOPER_APPROVAL` enabled for the first rollout.

## First test run

Use a non-production test repository and a read-only checkout credential. Confirm that the build, SBOM, Trivy JSON and summary are archived. If there are Critical/High findings and AI remediation is enabled, confirm that the patch is reviewed before validation. Inspect `ai-remediation.patch`, `findings-before.md`, `findings-after.md` and `cve-comparison.md`.

## Security and operational limitations

- **AI data disclosure:** selected repository files and vulnerability metadata are sent to the configured LiteLLM endpoint. Confirm your organization's data-handling policy first. The file filter is a precaution, not a complete secret scanner.
- **AI output is untrusted:** a human approval is required before the patch is applied when the parameter is enabled. Patch validation is basic and is not a security sandbox.
- **Build commands vary:** adapt test commands for your project. Node test scripts differ; Python needs pytest configured; generic projects have no automated tests in this starter.
- **Image scanning:** this starter scans the generated SBOM. If the deployed runtime is a container image, add a separate image scan of the exact image digest.
- **Remediation proof:** a finding disappearing from the next scan is not proof by itself. Validate dependency resolution, lockfiles/BOMs, transitive ownership and runtime artifacts.
- **PR/merge:** no Git push, PR creation, merge or deployment is implemented. The validated patch and reports are artifacts for the normal code-review process.
- **Credentials:** the sample Jenkinsfile uses a string parameter for the SCM credential ID and a secret-text credential for LiteLLM. Restrict job configuration/build permissions.

## Local smoke tests

Run `python3 -m unittest discover -s tests -v` from this repository root.
