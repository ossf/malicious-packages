# Contribution guidelines

Thank you for your interest in contributing to the repository! Since PRs repo and are reviewed by humans, it’s critical for the report to have high quality. 

## Human-First Collaboration & Responsible AI Use

We do not specifically prohibit or discourage using LLMs or AI tools to assist in drafting reports, formatting data, or analysing payloads. However, the maintainers reviewing your PRs are humans, and we want your contributions to be aimed at us. :)

If you use AI assistance, please keep the following in mind:

- Don’t be a ["meat proxy"](https://gruhn.me/blog/2026-08-03/). What makes your contribution valuable is your analysis, validation, and judgment. If maintainers ask questions during review, we are asking for your direct insight, not a relayed chat prompt. 
- Verify that all required fields are accurate for each malicious package:
  - `package name`
  - `ecosystem`
  - `affected version ranges`
- Prioritise clarity: LLM output tends to be overly verbose, which consumes human review time and effort. Please be concise and clear! Pay extra attention to descriptions and additional metadata like `iocs` that LLMs tend to inflate.

## What Makes a Great Submission
A high-quality malicious package report is concise, and balances clarity and evidence.

0. We prefer PRs over Issues.

1. Clear, Short Human-Readable Details
Explain the malicious package report briefly (in 2-4 sentences).
Clearly describe why the package is malicious, what it does, and the impact it may have. Avoid unnecessary filler, especially AI boilerplate, or intricate explanations. State clearly why this package is malicious rather than just buggy, low-quality, or a security research proof-of-concept (PoC).

2. Accurate & Sufficient Metadata
Provide the essential package ids (ecosystem, name, versions).
The schema for additions is specified [here](https://github.com/ossf/malicious-packages/blob/main/docs/schema_additions.md). Avoid over-inflating reports with vague or speculative metadata. If available, populate `IOCs` with correct and not overly generic data. Link directly to malicious source files, commit diffs, or sandbox runs when available.


Here are a couple of examples of good PRs: [#1433](https://github.com/ossf/malicious-packages/pull/1433), [#1340](https://github.com/ossf/malicious-packages/pull/1340), [#1006](https://github.com/ossf/malicious-packages/pull/1006).

## PR Checklist
Before submitting your PR, check:

[ ] Have I read and verified the report myself?

[ ] Are all required fields present and accurate?

[ ] Do all tests and formatting checks pass?

[ ] Is there a PR summary and is it written in clear, concise language?

[ ] Have I removed generic AI fluff, redundant disclaimers, or excessive details?

[ ] Am I prepared to answer review feedback directly?

