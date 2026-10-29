pipeline {
  agent any
  options {
    timestamps()
    disableConcurrentBuilds()
    timeout(time: 90, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }
  parameters {
    string(name: 'APP_REPO_URL', defaultValue: '', description: 'Application Git clone URL (HTTPS or SSH)')
    string(name: 'APP_BRANCH', defaultValue: 'main', description: 'Application branch to scan')
    string(name: 'SCM_CREDENTIALS_ID', defaultValue: 'app-scm-readonly', description: 'Jenkins credential ID for application checkout')
    choice(name: 'APP_TYPE', choices: ['AUTO', 'MAVEN', 'GRADLE', 'NODE', 'PYTHON', 'GENERIC'], description: 'Build/test type')
    booleanParam(name: 'ENABLE_AI_FIX', defaultValue: true, description: 'Ask LiteLLM to propose a patch for selected findings')
    booleanParam(name: 'REQUIRE_DEVELOPER_APPROVAL', defaultValue: true, description: 'Require approval before applying/testing the proposed patch')
    string(name: 'LITELLM_BASE_URL', defaultValue: 'https://litellm.example.com/v1', description: 'LiteLLM OpenAI-compatible API base URL')
    string(name: 'LITELLM_MODEL', defaultValue: 'your-model-alias', description: 'Configured LiteLLM model alias')
    string(name: 'MAX_FINDINGS_FOR_AI', defaultValue: '10', description: 'Maximum Critical/High findings sent to AI')
  }
  environment {
    REPORT_DIR = 'reports'
    APP_DIR = 'app'
    SBOM_FILE = 'reports/sbom.json'
    TRIVY_JSON = 'reports/trivy-before.json'
    AI_PATCH = 'reports/ai-remediation.patch'
  }
  stages {
    stage('Validate parameters and tools') {
      steps {
        script {
          if (!params.APP_REPO_URL?.trim()) error('APP_REPO_URL is required.')
          if (!params.APP_BRANCH?.trim()) error('APP_BRANCH is required.')
          if (!(params.MAX_FINDINGS_FOR_AI ==~ /[1-9][0-9]{0,2}/)) error('MAX_FINDINGS_FOR_AI must be between 1 and 999.')
        }
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          mkdir -p "$REPORT_DIR"
          for tool in git syft trivy python3; do
            command -v "$tool" >/dev/null || { echo "Missing required tool: $tool"; exit 2; }
          done
          git --version; syft version; trivy --version | head -n 1; python3 --version
        '''
      }
    }
    stage('Checkout application') {
      steps {
        dir('app') {
          deleteDir()
          script {
            checkout([$class: 'GitSCM', branches: [[name: "*/${params.APP_BRANCH}"]],
              userRemoteConfigs: [[url: params.APP_REPO_URL, credentialsId: params.SCM_CREDENTIALS_ID]],
              extensions: [[$class: 'CloneOption', shallow: true, depth: 50, noTags: true, timeout: 20]]])
          }
          sh 'git status --short && git rev-parse HEAD'
        }
      }
    }
    stage('Build and test baseline') {
      steps {
        dir('app') {
          script {
            def kind = params.APP_TYPE
            if (kind == 'AUTO') {
              if (fileExists('pom.xml')) kind = 'MAVEN'
              else if (fileExists('build.gradle') || fileExists('build.gradle.kts')) kind = 'GRADLE'
              else if (fileExists('package.json')) kind = 'NODE'
              else if (fileExists('pyproject.toml') || fileExists('requirements.txt')) kind = 'PYTHON'
              else kind = 'GENERIC'
            }
            env.DETECTED_APP_TYPE = kind
          }
          sh '''#!/usr/bin/env bash
            set -euo pipefail
            case "${DETECTED_APP_TYPE}" in
              MAVEN) command -v mvn >/dev/null; mvn -B -ntp test ;;
              GRADLE) if [ -x ./gradlew ]; then ./gradlew test; else command -v gradle >/dev/null; gradle test; fi ;;
              NODE) command -v npm >/dev/null; if [ -f package-lock.json ]; then npm ci; else npm install; fi; npm test -- --runInBand || npm test ;;
              PYTHON) python3 -m venv .venv; . .venv/bin/activate; python -m pip install --upgrade pip; if [ -f requirements.txt ]; then pip install -r requirements.txt; fi; if [ -f pyproject.toml ]; then pip install -e .; fi; python -m pytest -q || { echo 'pytest failed or is not configured'; exit 1; } ;;
              GENERIC) echo 'No build/test command configured for GENERIC. Configure APP_TYPE or extend Jenkinsfile.' ;;
              *) echo "Unsupported app type: ${DETECTED_APP_TYPE}"; exit 2 ;;
            esac
          '''
        }
      }
    }
    stage('Generate SBOM and scan') {
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          syft "dir:${APP_DIR}" -o cyclonedx-json="${SBOM_FILE}"
          set +e
          trivy sbom --scanners vuln --severity CRITICAL,HIGH --format json --output "$TRIVY_JSON" "$SBOM_FILE"
          rc=$?
          set -e
          if [ "$rc" -gt 1 ]; then echo "Trivy failed with exit code $rc"; exit "$rc"; fi
          python3 scripts/summarize_findings.py "$TRIVY_JSON" reports/findings-before.md
          cat reports/findings-before.md
        '''
        archiveArtifacts artifacts: 'reports/sbom.json,reports/trivy-before.json,reports/findings-before.md', allowEmptyArchive: false
      }
    }
    stage('Generate AI remediation proposal') {
      when { expression { return params.ENABLE_AI_FIX } }
      steps {
        withCredentials([string(credentialsId: 'litellm-api-key', variable: 'LITELLM_API_KEY')]) {
          sh '''#!/usr/bin/env bash
            set -euo pipefail
            python3 scripts/ai_fix.py \
              --findings "$TRIVY_JSON" \
              --repo "$APP_DIR" \
              --output "$AI_PATCH" \
              --base-url "$LITELLM_BASE_URL" \
              --model "$LITELLM_MODEL" \
              --max-findings "$MAX_FINDINGS_FOR_AI"
          '''
        }
        script {
          env.PATCH_AVAILABLE = (fileExists(env.AI_PATCH) && sh(script: "test -s '${env.AI_PATCH}'", returnStatus: true) == 0) ? 'true' : 'false'
        }
        archiveArtifacts artifacts: 'reports/ai-remediation.patch', allowEmptyArchive: true
      }
    }
    stage('Developer approval') {
      when { expression { return params.ENABLE_AI_FIX && params.REQUIRE_DEVELOPER_APPROVAL } }
      steps {
        script {
          if (!fileExists(env.AI_PATCH) || sh(script: "test -s '${env.AI_PATCH}'", returnStatus: true) != 0) {
            echo 'No AI patch was generated; skipping approval and patch validation.'
            env.PATCH_AVAILABLE = 'false'
          } else {
            env.PATCH_AVAILABLE = 'true'
            input message: 'Review reports/ai-remediation.patch and approve testing this proposed patch. This does not merge or push code.', ok: 'Approve patch for validation', submitterParameter: 'APPROVED_BY'
          }
        }
      }
    }
    stage('Validate patch and retest') {
      when { expression { return params.ENABLE_AI_FIX && env.PATCH_AVAILABLE == 'true' } }
      steps {
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          python3 scripts/validate_patch.py --repo "$APP_DIR" --patch "$AI_PATCH"
        '''
        dir('app') {
          sh '''#!/usr/bin/env bash
            set -euo pipefail
            case "${DETECTED_APP_TYPE}" in
              MAVEN) mvn -B -ntp test ;;
              GRADLE) if [ -x ./gradlew ]; then ./gradlew test; else gradle test; fi ;;
              NODE) npm test -- --runInBand || npm test ;;
              PYTHON) . .venv/bin/activate; python -m pytest -q ;;
              GENERIC) echo 'No generic test command configured; patch was applied but automated tests are not available.' ;;
              *) exit 2 ;;
            esac
          '''
        }
        sh '''#!/usr/bin/env bash
          set -euo pipefail
          syft "dir:${APP_DIR}" -o cyclonedx-json=reports/sbom-after.json
          set +e
          trivy sbom --scanners vuln --severity CRITICAL,HIGH --format json --output reports/trivy-after.json reports/sbom-after.json
          rc=$?
          set -e
          if [ "$rc" -gt 1 ]; then echo "Trivy failed with exit code $rc"; exit "$rc"; fi
          python3 scripts/summarize_findings.py reports/trivy-after.json reports/findings-after.md
          python3 scripts/compare_cves.py --before "$TRIVY_JSON" --after reports/trivy-after.json --output reports/cve-comparison.md
          cat reports/cve-comparison.md
        '''
        archiveArtifacts artifacts: 'reports/sbom-after.json,reports/trivy-after.json,reports/findings-after.md,reports/cve-comparison.md', allowEmptyArchive: true
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
      echo 'This pipeline does not push, merge, or deploy changes. Review the patch and reports, then use your normal code-review process.'
    }
  }
}
