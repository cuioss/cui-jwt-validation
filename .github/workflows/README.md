# GitHub Workflows

This directory contains GitHub Actions workflow configurations for the cui-jwt-validation project.

## Workflows

### Scorecard Supply-Chain Security (`scorecards.yml`)

This workflow runs the [OSSF Scorecard](https://github.com/ossf/scorecard) tool to analyze the project's supply chain security practices. It runs weekly and on branch protection rule changes.

### JMH Benchmark (`benchmark.yml`)

This workflow runs the JMH benchmarks and visualizes the results on the cuioss.github.io site.

#### Triggers

- Runs on pushes to the main branch
- Runs on version tag pushes (e.g., v1.2.3)
- Can be triggered manually via the GitHub Actions UI

#### Features

1. **Benchmark Execution**: Runs all JMH benchmarks in the project with JSON output format
2. **Result Storage**: Stores benchmark results as GitHub artifacts with 90-day retention
3. **Visualization**: Generates an interactive visualization of benchmark results using Chart.js
4. **External Repository Deployment**: Deploys the visualization to cuioss.github.io
5. **Performance Badges**: Creates dynamic badges showing key performance metrics

#### Viewing Results

Once the workflow has run successfully, benchmark results can be viewed at:
`https://cuioss.github.io/cui-jwt-validation/benchmarks/`

#### Performance Badges

The workflow generates performance badges that can be included in the project's README or other documentation. The badge markdown is available in the deployment under `badge-markdown.txt`.

Example badge:
```markdown
[![Access Token Validation](https://img.shields.io/endpoint?url=https://cuioss.github.io/cui-jwt-validation/benchmarks/validator-badge.json)](https://cuioss.github.io/cui-jwt-validation/benchmarks/)
```

#### Manual Trigger

To manually trigger the benchmark workflow:
1. Go to the "Actions" tab in the GitHub repository
2. Select "JMH Benchmark" from the workflows list
3. Click "Run workflow"
4. Select the branch to run on and click "Run workflow"

## Security Considerations

All GitHub Actions in this directory follow security best practices:
- Actions are pinned by commit hash (uses: `...@<commit-sha>`)
- Default permissions are set to read-only
- The step-security/harden-runner action is used to audit outbound calls
