# bellybutton threat model

## Overview

Bellybutton is a Python command-line linter driven by project .bellybutton.yml rules. It walks or selects Python files, reads source into memory, converts source into an XML AST for XPath rules, applies regular-expression rules, and reports line failures. init writes a configuration file and normally refuses an existing one. modified_only fetches origin and computes Git differences through shell commands. Configuration uses yaml.FullLoader with custom constructors; FullLoader-created Python-name callables can reach lint_file’s callable branch and execute selected source under the linter’s authority.

| Component | Source |
| --- | --- |
| CLI initialization and lint | bellybutton/cli.py:77 |
| Configuration parsing | bellybutton/parsing.py:174 |
| AST/regex lint engine | bellybutton/linting.py:45 |
| File cache | bellybutton/caching.py:10 |

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |
| Lint | Rule configuration | project_directory joined with .bellybutton.yml and made absolute | &lt;absolute project_directory&gt;/.bellybutton.yml | Project config writer; linter runtime | FullLoader, custom parsing checks and settings validation | bellybutton/cli.py:163 |
| Lint | Source contents | Selected filepaths; FileManager reads and caches | Selected local Python files in process memory | Operator/CI process; diagnostics consumer | Filesystem permissions and include/exclude matching | bellybutton/caching.py:14 |
| Modified-only lint | Git/network/subprocess capability | project_directory interpolated into shell=True Git commands | git fetch origin and diff in selected repository; returned relative names are then made absolute against the process working directory | Shell/Git under invoking user; configured remote | Host and Git credentials; shell quoting is a code boundary, but selected-repository read confinement is not enforced: a different working directory can select an unrelated same-named Python file or a missing path. Resolve diff names against the selected repository and verify containment | bellybutton/cli.py:114-128 |
| Init | Configuration write | project_directory/.bellybutton.yml, force overrides existence guard | Requested project .bellybutton.yml; symlink resolution can instead create/write an external target | Invoking process writes | exists follows symlinks: a dangling project config symlink passes the no-force guard and open(..., w) follows it. Requires a planted link and writable target/parent under invoker authority. Reject links and create through a non-following, containment-safe strategy; protect against replacement races | bellybutton/cli.py:79-92 |

## Threat Model, Trust Boundaries, and Assumptions

Protect the developer/CI process, filesystem read scope, report correctness, and build availability. Python source is parsing input; config-defined regexes and XPath expressions are policy inputs with computational power. A contributor able to change source may not be authorized to change the linter policy or read host files. The CLI runs with the invoker’s authority and is not a sandbox for arbitrary repositories. A library caller passing a callable rule already grants Python execution, so callable execution alone is not an escalation. For YAML configs, this is a concrete authority transfer: FullLoader resolves python/name references such as builtins.exec, parse_rule accepts the callable as expr, and lint_file invokes it on the file contents after AST parsing. An attacker controlling accepted config and selected valid Python source can execute that source even if conversion of exec’s None result later fails (bellybutton/parsing.py:133-170; bellybutton/parsing.py:176; bellybutton/linting.py:55-74). It does not require a parser vulnerability. Ignore markers are honored only where rule settings permit them.

This model uses the repository’s own source and generic host/caller obligations. No private deployment facts, observed exploitation, or inferred tenant relationships are included. Source review establishes the operations below; it does not establish every dependency’s implementation or the permissions of an actual installation. The operator must distinguish a deliberately granted capability from a lower-trust input gaining a new one.

Actual installed dependencies and privileged CI use remain unverified, but PyYAML 6.0.3 source within the allowed >=4.0,<7.0 range confirms FullLoader inherits FullConstructor, registers python/name and resolves existing builtins names. This supports the config-to-callable path without assuming a vulnerable release; the selected source must parse and the rule settings must select it. Other astpath/lxml/regex properties remain separate questions (setup.py:15; dependency PyYAML 6.0.3 yaml/loader.py:21-29, yaml/constructor.py:540-570, yaml/constructor.py:709-711).

## Attack Surface, Mitigations, and Attacker Stories

These are prioritized hypotheses for investigation, not validated findings. Priority reflects plausible capability gain; each prerequisite must hold before assigning a deployment-specific severity.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| P1 | A hostile project-directory string is interpreted by the shell in modified-only mode. | Victim passes attacker-influenced directory text and invokes that mode. | Command execution with linter process authority. | Only modified-only Git path uses this shown shell construction; source text is not automatically executed. | Use subprocess argument arrays and explicit cwd instead of interpolated shell strings. | bellybutton/cli.py:117 |
| P2 | Pathological regex, XPath, or source shape consumes excessive CPU/memory during lint. | Untrusted rules/source and a shared or time-sensitive CI job. | Availability loss for checks. | Include/exclude filters limit files; no per-rule execution budget shown. | Keep policy trusted and bound job time, file sizes and input volume. | bellybutton/linting.py:57 |
| P1 | An accepted YAML rule resolves builtins.exec and executes the selected Python file during linting. | Attacker controls accepted config with a callable expr and valid matching Python source; required settings/description exist and optional example/instead clauses do not reject the rule; victim runs lint. | Code execution with invoking developer/CI authority before any later result-conversion error. | FullLoader and rule syntax/settings checks do not restrict expr to regex/XPath; this path exists in supported PyYAML 6 without a vulnerable dependency. | Use an explicit safe loader with only required constructors and reject YAML-origin callables; separately authorize any trusted library-callable API. Keep untrusted repository config outside privileged lint authority. | bellybutton/parsing.py:128-176; bellybutton/linting.py:55-74; setup.py:15 |
| P3 | A contributor suppresses violations using permitted ignore comments and a consumer mistakes that for enforced security policy. | allow_ignore is enabled and downstream gate trusts lint outcome alone. | Missed rule violations; security impact requires a meaningful downstream rule. | Ignore application explicitly checks rule.settings.allow_ignore. | Disable ignores for mandatory policy and keep security checks independent. | bellybutton/linting.py:78 |

## Severity Calibration (Critical, High, Medium, Low)

Critical needs demonstrated privileged execution and a broad consequential environment, not simply the presence of YAML.

High fits verified shell injection into a privileged consuming CI process.

Medium fits repeatable shared-check exhaustion or unauthorized sensitive filesystem access with actual input reachability.

Low fits a linter crash, permitted ignore marker, or erroneous line report. Parsing a Python AST does not inherently execute that source.

Confidence in the source-described data flow is separate from confidence in exploitability. A finding requires a concrete lower-trust entry, an effective control failure, and a consequential new capability. Host compromise assumed at the outset, deliberate operator authority, and self-only errors do not supply that missing evidence.

Repository: github.com/mathspace/bellybutton

Version: cfcfa88192b53981ef3c0e74f0fa25d2afd39518
