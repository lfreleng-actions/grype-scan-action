<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# 🔎 Grype Scan Action

Scans SBOMs, container images or directories for known vulnerabilities
with [Grype](https://github.com/anchore/grype), renders the findings as
a table in the job step summary, and decides whether they gate the
workflow.

Replaces the Grype shell that each workflow family carried
separately. A fix or an improvement now lands once.

## Why the summary matters

A failing scan used to report a bare count, leaving the affected
packages in the job log. This action puts the findings on the run
page, sorted by severity then risk:

## Grype Vulnerability Scan: alpine:3.10

🔴 Critical: 8  🟠 High: 67  🟡 Medium: 42  🔵 Low: 4

<!-- markdownlint-disable MD013 MD060 -->

| Severity    | Package      | Version   | Type | Vulnerability  | Fix       | EPSS   | Risk  |
| ----------- | ------------ | --------- | ---- | -------------- | --------- | ------ | ----- |
| 🔴 Critical | libcrypto1.1 | 1.1.1k-r0 | apk  | CVE-2021-3711  | unknown   | 87.82% | 77.5  |
| 🔴 Critical | zlib         | 1.2.11-r1 | apk  | CVE-2022-37434 | -         | 17.85% | 16.78 |
| 🔴 Critical | apk-tools    | 2.10.6-r0 | apk  | CVE-2021-36159 | 2.10.7-r0 | 2.64%  | 2.39  |

<!-- markdownlint-enable MD013 MD060 -->

EPSS is the probability of exploitation in the next 30 days; Risk is
Grype's combined score. The **Fix** column distinguishes a finding you
can act on (a version) from one you cannot (`not-fixed`, `unknown`).

## Usage

Scan an SBOM:

<!-- markdownlint-disable MD046 -->

```yaml
- uses: lfreleng-actions/grype-scan-action@v1
  with:
    sbom: "sbom-cyclonedx.json"
    fail-on: "medium"
```

Scan a set of SBOMs, one report each, worst result deciding:

```yaml
- uses: lfreleng-actions/grype-scan-action@v1
  with:
    sbom: "sbom-cyclonedx-*.json"
```

Scan an image or directory directly:

```yaml
- uses: lfreleng-actions/grype-scan-action@v1
  with:
    target: "registry:alpine:3.20"
    name: "base image"
```

<!-- markdownlint-enable MD046 -->

## Unblocking a pull request

A published advisory with no available fix can block every pull request
in a repository until upstream ships a patch. There are three ways out,
in order of preference. Where the problem is the timing rather than any
individual finding, see [gating only when dependencies
change](#gating-only-when-dependencies-change) instead.

### 1. Gate on what a bump can fix

`only-fixed: "true"` reports every finding but gates those with a
fix available. A CVE nobody can action stops blocking merges, while a
missed dependency bump still fails.

The action applies this itself rather than passing `--only-fixed` to
Grype, which would drop unfixable findings from the report altogether.
Measured against `alpine:3.10`: all 121 findings stay in the summary
and the counts, while 1 fixable finding decides the verdict. Use
`ignore-states` where filtering the report itself is what you want.

### 2. Approve a bypass for one vulnerability

Open an issue titled `BYPASS: CVE-2026-12345`, then have a maintainer
apply the `cve-bypass` label. The action suppresses that vulnerability
and records the suppression in the summary, linking the issue.

The **label is the trust boundary**, not the issue author. Applying a
label needs triage or write permission, so an outside contributor
cannot approve their own bypass, while anyone may still request one.

The label authorises a **revision**, not the issue. An author can edit
their own title at any time, so an approved `BYPASS: CVE-2026-0001`
could otherwise become a critical, unfixed CVE after review. The action
reads identifiers from the title as it stood when the label last went
on, reconstructed from the issue's rename events. Editing the title
afterwards changes nothing; a maintainer re-applies the label to
approve the new wording. Where that title cannot be established, the
bypass does not apply.

Authorship plays no part, by design. GitHub's `author_association`
reports `CONTRIBUTOR` rather than `MEMBER` when organisation membership
is private, and the value changes with the token used to read it. That
makes it unsafe as an authorisation signal.

This works where repository variables do not. Pull requests from forks
and Dependabot runs get a read-only token and no Actions secrets,
but reading labelled issues on a public repository needs neither.

Point a group of repositories at one bypass list for organisation-wide
suppression:

<!-- markdownlint-disable MD046 -->

```yaml
- uses: lfreleng-actions/grype-scan-action@v1
  with:
    sbom: "sbom-cyclonedx.json"
    bypass-repository: "lfreleng-actions/.github"
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

<!-- markdownlint-enable MD046 -->

Bypasses expire. `bypass-max-age-days` (90 by default) makes the action
ignore stale issues, which stops suppressions accumulating unnoticed.
Close the issue to revoke one at once.

A failed lookup, for any reason, applies no bypasses and leaves the
gate closed.

Checking the approved revision costs at least one extra API call per
unexpired bypass issue, and up to ten where the issue has a long
event history. Pass `github-token` where the list is long enough for
unauthenticated rate limits to bite.

### 3. Report without gating

`permit-fail: "true"` reports findings and passes regardless. Wire it
to a repository variable to keep the existing escape hatch:

<!-- markdownlint-disable MD046 -->

```yaml
permit-fail: ${{ vars.NO_BLOCK_AUDIT_FAIL == 'true' }}
```

<!-- markdownlint-enable MD046 -->

A composite action cannot read the `vars` context itself, so the caller
passes the value.

## Gating only when dependencies change

The three escape hatches above act on individual findings. This acts on
the run: `gate-when: "dependencies-changed"` reports findings as
warnings unless the change under review touched the dependency chain.

The reasoning is that a CVE published upstream today has nothing to do
with the change under review, and most changes never touch a dependency
at all. Blocking them makes the gate a tax on unrelated work rather than
a control on the thing that introduced the risk. When a maintainer does
visit the dependencies, the gate applies in full — which is the point at
which they can act on it.

<!-- markdownlint-disable MD046 -->

```yaml
- uses: lfreleng-actions/grype-scan-action@<sha>
  with:
    sbom: 'sbom-cyclonedx.json'
    gate-when: 'dependencies-changed'
    dependencies-changed: ${{ needs.sbom.outputs.deps_changed }}
```

<!-- markdownlint-enable MD046 -->

**The scan always runs.** Findings are always reported, annotated and
uploaded; only the verdict changes. This is deliberately not the same as
skipping the job, which would stop surfacing new advisories altogether.

Where the caller cannot pass the signal directly — a matrix job, say,
where job outputs collapse to a single value — write a sidecar beside
the SBOM instead and point `dependency-change-manifest` at it:

<!-- markdownlint-disable MD046 -->

```json
{ "changed": true }
```

<!-- markdownlint-enable MD046 -->

The explicit input wins when both are present. The manifest is excluded
from the `sbom` glob before scanning, so a sidecar may safely share the
SBOM's naming pattern — `sbom-cyclonedx-deps.json` alongside
`sbom: 'sbom-cyclonedx-*.json'` scans the SBOM and reads the sidecar,
rather than trying to scan both.

Pair this with `dependency-policy: "declared"` below, or failing that
with `only-fixed: "true"`. When a change *does* touch the dependency
chain the full gate applies, so without one of them a maintainer
bumping a single library can find themselves blocked by the project's
whole accumulated backlog — which makes dependency maintenance the most
expensive change to make, and discourages the work most worth doing.

This narrows when the gate applies, so it needs a counterweight: run a
scheduled or default-branch scan with `gate-when: "always"`. Without
one, findings accumulate with no owner, and the next maintainer to touch
a dependency inherits the whole backlog at once.

## Gating only what the project declared

`dependency-policy: "declared"` gates findings in packages the project
asked for, and reports findings in packages it merely inherited.

A project can act on a dependency it declared: bump it, pin it, replace
it. A package pulled in three levels down by something else offers no
such route, and blocking a merge on it asks a team to fix something
they do not control.

<!-- markdownlint-disable MD046 -->

```yaml
- uses: lfreleng-actions/grype-scan-action@<sha>
  with:
    sbom: 'sbom-cyclonedx.json'
    dependency-policy: 'declared'
    transitive-fail-on: 'critical'
```

<!-- markdownlint-enable MD046 -->

`transitive-fail-on` sets the severity at which an inherited package
gates — an independent bar rather than a filter layered on `fail-on`,
and either may be the lower of the two. Declared packages answer to
`fail-on`; an inherited one gates when it reaches `transitive-fail-on`,
is reported as a warning when it reaches `fail-on` but not that, and
is reported without a warning when it reaches neither.

It defaults to `none`, meaning an inherited package never gates.
`critical` is the more defensible setting for most projects, since a
critical in a transitive package is still worth stopping for.

### Where the answer comes from

CycloneDX records the dependency graph, and Grype preserves each
component's `bom-ref` as `artifact.id` — so the graph arrives inside
the SBOM this action already scans. No checkout, no extra job wiring.

Two document shapes classify, both measured against real generators:

<!-- markdownlint-disable MD013 -->

| Shape       | Producer                           | Anchor                                   |
| ----------- | ---------------------------------- | ---------------------------------------- |
| Single root | `cyclonedx-py --pyproject`         | `metadata.component` and its `dependsOn` |
| Reactor     | `cyclonedx-maven makeAggregateBom` | the unscoped module components           |

<!-- markdownlint-enable MD013 -->

Both rules read conventions rather than guarantees, so both are
restricted to a document that names one of those generators in
`metadata.tools`. CycloneDX does not say whether a first-level
dependency is a third-party package or a module of the project, and it
leaves `scope` optional throughout — read either signal from an
unmeasured producer and a declared package can be mistaken for an
inherited one, which is the direction that loses the gate. Adding a
generator is a one-line change once its output has been checked.

The reactor case needs the extra care. The aggregator names itself in
`metadata.component` but depends on nothing, and a module that a
sibling module depends on looks exactly like a third-party library.
`scope` separates them: cyclonedx-maven marks third-party components
`required` and leaves modules unscoped. The rule also requires the
named root to be part of the graph, which Syft's never is — it names
the scanned directory rather than the project.

The graph is read from **CycloneDX JSON only**. An XML SBOM carries
the same graph but needs a separate parser, so it resolves to no
classifier and every finding stays declared. Where `sbom_format` is
`xml`, request `both` to get the benefit.

Where the graph cannot answer — Syft emits none at all for Go, and
`cyclonedx-py` leaves a lock-file project's graph unrooted — supply the
answer directly with `declared-dependencies`, a list of purls or names,
one per line. That list must be complete: a package missing from it
counts as inherited. An empty file counts as *no* list rather than as
"this project declares nothing" — otherwise a producer that truncated
it could mark every package inherited and quietly disable the gate.
Like the change sidecar, the list stays out of the `sbom` glob, so it
may safely sit beside the SBOM.

`declared-source` chooses between them. `auto` prefers the list and
falls back to the graph.

Classification runs whatever `dependency-policy` is set to, so
`direct-matches`, `transitive-matches` and `provenance-source` report
accurately on a project still using `all` — which is how to see what
switching to `declared` would change before switching.

### What happens when it cannot tell

Everything unclassifiable counts as **declared**, and so gates.
An SBOM with no graph, an unrooted graph, a root outside the graph, an
unreadable file, a finding matching no component — each one keeps the
finding blocking.

That is the whole safety argument for this feature: a lane whose SBOM
carries no usable graph loses the *leniency*, never the *gate*, and
behaves exactly as it did before. `provenance-source` reports which
classifier answered for each scanned artefact, so a lane silently
getting no benefit is visible rather than mysterious.

## Failing closed

A pattern matching no SBOM fails the step by default. Scanning nothing
looks identical to scanning something clean, so a mistyped path, or an
earlier step that failed to produce its SBOM, would otherwise pass a
security gate in silence. Set `fail-on-missing-sbom: "false"` where an
absent SBOM is a valid outcome, such as a build permitted to fail.

The same principle governs the bypass lookup: an API error applies no
bypasses rather than assuming approval, and so does an issue whose
approved title cannot be reconstructed.

The dependency-change signal fails closed too, and for the same reason.
An absent, unreadable or malformed sidecar, or a value that is not
exactly `true` or `false`, leaves the signal unresolved — and an
unresolved signal gates. Downgrading a real finding to a warning is a
decision that has to be positively established, never inferred from a
missing file.

Dependency provenance follows the same rule: anything that cannot be
classified counts as declared, and gates.

## Inputs

<!-- markdownlint-disable MD013 -->

### Scan target

<!-- markdownlint-disable MD013 -->

| Name                 | Default | Description                                                 |
| -------------------- | ------- | ----------------------------------------------------------- |
| sbom                 | ""      | Path or glob for SBOM file(s); the action scans every match |
| fail-on-missing-sbom | true    | Fail when the pattern matches no file                       |
| target               | ""      | Grype target reference, used instead of `sbom`              |
| name                 | ""      | Label for this scan in the summary and annotations          |

<!-- markdownlint-enable MD013 -->

Provide one of `sbom` or `target`, not both.

### Scan behaviour

<!-- markdownlint-disable MD013 -->

| Name             | Default | Description                                                |
| ---------------- | ------- | ---------------------------------------------------------- |
| fail-on          | medium  | Lowest gating severity, or `none` to report without gating |
| only-fixed       | false   | Report vulnerabilities that have a fix                     |
| ignore-states    | ""      | Fix states to ignore: fixed, not-fixed, unknown, wont-fix  |
| by-cve           | false   | Orient results by CVE rather than the original ID          |
| sort-by          | risk    | risk, severity, epss, kev, package or vulnerability        |
| scope            | ""      | Layers to analyse for image targets                        |
| platform         | ""      | Platform specifier for image targets                       |
| distro           | ""      | Distro to match against                                    |
| exclude          | ""      | Comma-separated globs to exclude                           |
| add-cpes-if-none | false   | Generate CPEs for packages that have none                  |
| vex              | ""      | Comma-separated VEX documents to apply                     |
| config           | ""      | Grype configuration file                                   |
| extra-args       | ""      | Raw arguments appended to the Grype call                   |
| grype-version    | ""      | Grype version to install                                   |
| cache-db         | true    | Database cache mode: `true`, `false` or `restore-only`     |

<!-- markdownlint-enable MD013 -->

### Reporting

<!-- markdownlint-disable MD013 -->

| Name               | Default                  | Description                                   |
| ------------------ | ------------------------ | --------------------------------------------- |
| output-formats     | json,table,sarif         | Formats to write; must include `json`         |
| output-prefix      | grype-results            | Filename prefix for reports                   |
| summary            | true                     | Write the findings table to the step summary  |
| summary-title      | Grype Vulnerability Scan | Heading for the summary section               |
| summary-max-rows   | 50                       | Row cap per artefact; the summary caps at 1MB |
| summary-on-success | true                     | Write a summary when nothing gates            |
| upload-artifact    | true                     | Upload reports as a workflow artefact         |
| artifact-name      | grype-scan-results       | Artefact name                                 |
| retention-days     | 90                       | Artefact retention                            |

<!-- markdownlint-enable MD013 -->

### Gating and bypasses

<!-- markdownlint-disable MD013 -->

| Name                       | Default    | Description                                                            |
| -------------------------- | ---------- | ---------------------------------------------------------------------- |
| gate-when                  | always     | `always`, or `dependencies-changed` to warn on unrelated runs          |
| dependencies-changed       | ""         | `true`, `false`, or empty to read the sidecar                          |
| dependency-change-manifest | ""         | Path to a `{"changed": bool}` sidecar beside the SBOM                  |
| dependency-policy          | all        | `all`, or `declared` to warn on inherited packages                     |
| transitive-fail-on         | none       | Severity at which an inherited package gates, independent of `fail-on` |
| declared-source            | auto       | `auto`, `sbom-graph`, `file` or `none`                                 |
| declared-dependencies      | ""         | Path to a list of declared purls or names, one per line                |
| permit-fail                | false      | Report findings and pass the step                                      |
| bypass-enabled             | true       | Honour maintainer-approved bypass issues                               |
| bypass-repository          | ""         | Repository holding bypass issues; empty uses the caller                |
| bypass-label               | cve-bypass | Label that makes a bypass effective                                    |
| bypass-title-prefix        | BYPASS:    | Issue title prefix identifying a bypass                                |
| bypass-max-age-days        | 90         | Ignore bypass issues older than this; 0 disables expiry                |
| github-token               | ""         | Token for reading bypass issues                                        |

<!-- markdownlint-enable MD013 -->

## Concurrency and the database cache

The action caches Grype's vulnerability database between runs, keyed on
the Grype version, the database source **and the database build time**:

```text
grype-db-v0.110.0-c912200d9d02-20260903T063055Z
```

Restores match on the `grype-db-<version>-<source>-` prefix and return
the most recently **created** entry under it. With one job writing that
prefix — the arrangement described under *Concurrent jobs* below — that
is the newest build; where two jobs write it, creation order and build
order can disagree, which is why the single-writer rule matters. A save
happens only when the run brings in a build the cache does not already
hold, always under a key no entry holds yet.

The source segment is a hash of the database update URL Grype actually
resolves, so it accounts for every way the feed can be repointed — the
`config` input, `GRYPE_DB_UPDATE_URL`, or a `.grype.yaml` picked up
automatically from the repository. Grype always resolves *some* URL; on
the rare occasion it cannot be read, caching is skipped rather than
falling back to a shared namespace, since an unidentifiable feed is
exactly the case that most needs isolating. Without that segment, two
jobs in one repository could share a key while scanning against
different feeds — and since Grype decides whether to update by comparing
build times, a newer database from the wrong feed survives the update
and the scan silently uses it.

That rotation matters because Actions cache entries are immutable. A key
fixed on the Grype version alone can never be refreshed: once written,
the entry is restored on every later run, fails to be overwritten, and
is kept alive past normal inactivity eviction by the restores that read
it. The cached database then grows steadily more stale for as long as the
Grype version stays put, and each run reports:

```text
Failed to save: Unable to reserve cache with key grype-db-v0.110.0,
another job may be creating this cache
```

Despite its wording, that message covers "this key already exists" as
well as a genuine race.

### Modes

<!-- markdownlint-disable MD013 -->

| `cache-db`     | Restores | Saves                    | Use for                           |
| -------------- | -------- | ------------------------ | --------------------------------- |
| `true`         | yes      | if build not yet cached  | the default; a lone scan job      |
| `restore-only` | yes      | never                    | concurrent jobs, e.g. matrix legs |
| `false`        | no       | no                       | disabling the cache entirely      |

<!-- markdownlint-enable MD013 -->

### When caching is skipped

The cache never takes precedence over a correct scan. Where an entry
would be unsafe or meaningless, the action warns and scans without it
rather than failing:

- **`db.auto-update` is false.** The database is pinned or preloaded,
  not fetched from the feed the key names. Restoring would overwrite
  what the caller deliberately put there, and a database already on the
  runner gains nothing from being cached.
- **`db.cache-dir` is unsuitable** — not an absolute POSIX path, or one
  containing a directory the run keeps its own files in (a home
  directory, the workspace, the runner temp). That path is archived on
  save and written back over on restore, so a broad one would sweep in
  unrelated files. Symlinked components are resolved first, so a link
  cannot hide where the cache would point.
- **The database update URL cannot be read**, so entries could not be
  namespaced by feed. An unidentifiable feed is the case that most
  needs isolating, so caching stops rather than falling back to a
  shared namespace.
- **`extra-args` carries a `-c`, `--config` or `--profile` flag.** That
  is raw argv appended to the scan, which the cache steps cannot see,
  leaving them to key one configuration while the scan reads another.
  Passing configuration that way is legal, so the scan is left exactly
  as asked and only the cache is dropped — use the `config` input
  instead to keep both.
- **Grype does not report its resolved configuration.** `grype config
  --load` postdates some releases `grype-version` can still pin, and
  those scan perfectly well.

Saving alone is skipped, with the restore still applied, when the
update leaves the build unchanged: either the entry just restored
already holds it, or the database was already on the runner and this
run cannot say which feed produced it.

### Concurrent jobs

Rotation removes the stale-entry problem but not simultaneity:
concurrent jobs that all refresh the same new build would race to write
the same new key, and the losers report the message above.

Give exactly one job the job of writing:

<!-- markdownlint-disable MD046 -->

```yaml
jobs:
  warm-grype-db:
    runs-on: ubuntu-latest
    # One writer per source means one across concurrent runs too, not
    # merely one within each. Two overlapping runs would otherwise
    # save out of order and leave the older database as the newest
    # entry, exactly as below.
    concurrency:
      group: grype-db-warm
      cancel-in-progress: false
    steps:
      - uses: lfreleng-actions/grype-scan-action@v1
        # On the step, not the job. Job-level continue-on-error keeps
        # the workflow green but still marks the job failed, and the
        # scans below would then be skipped for a failed dependency -
        # a green run that scanned nothing. Here the job succeeds and
        # the scans always run, cache or no cache.
        continue-on-error: true
        with:
          target: 'registry:alpine:3.22'
          fail-on: 'none'
          upload-artifact: 'false'
          summary: 'false'
          cache-db: 'true'

  scan:
    needs: [warm-grype-db]
    # The scan must not depend on the warm-up having run. A third
    # overlapping run cancels the older *pending* warm-up, because a
    # concurrency group holds only one queued job, and 'needs' skips a
    # dependent job whose dependency was cancelled - a green run that
    # scanned nothing. '!cancelled()' lets the scan proceed with
    # whatever the cache already holds, while still honouring a
    # genuine cancellation of the whole run.
    if: ${{ !cancelled() }}
    strategy:
      matrix:
        component: [client, server, bridge]
    runs-on: ubuntu-latest
    steps:
      - uses: lfreleng-actions/grype-scan-action@v1
        with:
          sbom: sbom-${{ matrix.component }}.json
          cache-db: 'restore-only'
```

<!-- markdownlint-enable MD046 -->

The matrix legs restore what the warm-up wrote and never write
themselves, so no leg can enter the race.

Note the two separate protections against a warm-up problem silently
skipping the scans, which cover different failures: `continue-on-error`
on the warm-up *step* handles a warm-up that fails, and `!cancelled()`
on the scan job handles a warm-up that is cancelled while queued. A
cache is an optimisation, so neither should ever be able to turn a
scan into a no-op that still reports green.

**Use exactly one writer per source**, across concurrent runs as well as
within each. `restore-keys` returns the most recently *created* matching
entry, not the one with the highest build timestamp, so two jobs writing
the same prefix can leave an older database as the newest entry if it
happens to be saved second. Later runs then restore that older database,
update locally, and cannot re-save — its timestamped key already exists
— so the stale entry stays the restore choice until the Grype version or
the feed changes. A repository-wide `concurrency` group on the warm-up
job, as above, makes the ordering moot.

Note the ordering cost: `scan` waits for `warm-grype-db`, so the warm-up
sits on the critical path. Where the surrounding workflow has independent
work — building images, generating SBOMs — a warm-up job that depends on
nothing runs alongside that instead and finishes before the scans need
it, at no cost to the run.

One caveat: a database published between the warm-up and the scans is
not picked up straight away. Grype records when it last checked for an
update, and that state travels in the cache, so a restored database
suppresses further checks until `max-update-check-frequency` elapses —
two hours by default. The legs keep scanning the previous build until a
later check or the next warm-up refreshes it. No error and no race; the
cache trails the newest publication by up to that window.

Refreshing in the warm-up job is also best-effort: if the feed is
unreachable it warns and scans against whatever was restored, rather
than failing. A scan with slightly older data beats no scan, but during
an outage the entry can trail the feed by more than that window. Set
`cache-db: false` to remove the cache from the picture entirely, at the
cost of a download per run.

## Outputs

<!-- markdownlint-disable MD013 -->

| Name               | Description                                                |
| ------------------ | ---------------------------------------------------------- |
| gating             | "true" when findings gate the workflow                     |
| total-matches      | Total matches across all scanned artefacts                 |
| gating-matches     | Matches in the gating bucket; 0 when the gate is unarmed   |
| advisory-matches   | Matches reported as warnings rather than blocking          |
| direct-matches     | Matches in packages the project declares                   |
| transitive-matches | Matches in packages the project inherited                  |
| provenance-source  | JSON map of artefact to classifier: sbom-graph, file, none |
| gate-active        | "true" when findings could block, before permit-fail       |
| gate-reason        | Why the gate is or is not armed; policy, not outcome       |
| bypassed-matches   | Matches suppressed by an approved bypass                   |
| bypassed-ids       | Comma-separated vulnerability IDs bypassed                 |
| severity-counts    | JSON object of counts by severity                          |
| report-files       | Newline-separated list of report files written             |

<!-- markdownlint-enable MD013 -->

## Notes

The gate is computed from the JSON report rather than from Grype's
`--fail-on` exit code, because bypasses have to be subtracted from the
findings first. An exit code cannot express "these would gate, but a
maintainer suppressed two of them". Deriving the table, the counts and
the verdict from one source keeps them consistent.

A Grype configuration file taken from a pull request head is
attacker-controlled: a contributor can add ignore rules to their own
branch. Prefer bypass issues, which live outside the branch under
review. Trust `config` when it comes from the base repository.
