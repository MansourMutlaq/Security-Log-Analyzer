# Engineering Notes

## Purpose

This document records the main implementation problems, engineering decisions, trade-offs, and production considerations behind the Infrastructure Security Analytics project.

## 1. Heterogeneous Log Formats

**Problem:** AWS CloudTrail, Linux authentication logs, and Cisco IOS syslog use different schemas, timestamp formats, and identity fields.

**Decision:** Each source uses an isolated parser that converts vendor-specific records into one validated `SecurityEvent` model.

**Result:** Detection, scoring, correlation, reporting, and indexing operate on normalized events rather than raw source formats.

## 2. Ambiguous Syslog Timestamps

**Problem:** Traditional syslog records may omit the year, making parsing dependent on the current system date.

**Decision:** The Linux parser receives an explicit reference year and creates a timezone-aware timestamp before event processing.

**Result:** Parsing is deterministic and reproducible, including leap-day cases.

## 3. Normalization and Detection

**Problem:** Equivalent concepts such as principal, source address, action, and outcome appear under different field names.

**Decision:** The pipeline uses validated internal models and ECS-style exported documents. Deterministic rules assign risk scores from 0 to 100 and map them to severity levels.

**Result:** Identical input produces consistent findings that are testable and explainable during investigation.

## 4. Cross-Source Correlation

**Problem:** A single event may be benign, while related activity across cloud, Linux, and network telemetry may indicate compromise.

**Decision:** Correlation evaluates time windows, identities, source addresses, event types, and infrastructure domains.

**Result:** The pipeline produces investigation-ready findings instead of treating every raw event as an independent alert.

## 5. Report Path Disclosure

**Problem:** Generated reports could expose Windows or WSL usernames and absolute development paths.

**Decision:** Reports render sanitized source labels and filenames. Regression tests reject local path disclosure in HTML output.

**Result:** Published reports and screenshots are portable and safer to share.

## 6. OpenSearch Integration

**Problem:** Making OpenSearch mandatory would cause the complete analysis to fail when the search platform is unavailable.

**Decision:** OpenSearch export is opt-in and failure-isolated. Local HTML, JSON, and CSV reports are generated independently.

**Result:** Live validation indexed 15 normalized events and 10 correlated alerts while preserving local outputs.

**Trade-off:** The current exporter uses synchronous indexing. Bulk operations, retry policies, mappings, and lifecycle policies remain future production work.

## 7. JSON-Safe Serialization

**Problem:** Alerts contain Pydantic models, enums, UUIDs, timestamps, paths, lists, and nested mappings that cannot always be sent directly as JSON.

**Decision:** The exporter recursively converts supported values into JSON-compatible representations.

**Result:** Events and alerts can be indexed without coupling the exporter to every individual model field.

## 8. Quality and Security Controls

The repository enforces:

- 47 automated tests
- 92.98% statement coverage
- an 80% minimum CI coverage gate
- Ruff static analysis
- Bandit security scanning
- dependency consistency checks
- GitHub Actions continuous integration
- CLI, exporter, and path-disclosure regression tests

## 9. Production Boundaries

Docker Compose provides a reproducible single-node OpenSearch environment for local validation. The security plugin is disabled only for local development.

A production deployment requires TLS, authentication, authorization, private networking, managed secrets, monitoring, index templates, lifecycle policies, and an appropriate shard and replica strategy.

## 10. Current Limitations

- Processing is batch-oriented rather than real-time.
- Sample telemetry is synthetic and intentionally small.
- Detection thresholds require organization-specific tuning.
- The local OpenSearch environment is not production hardened.
- The project does not include case-management workflows.
- The project is not intended to replace a managed SIEM platform.

## 11. Future Engineering Work

1. OpenSearch bulk indexing and retry handling
2. Index templates and explicit mappings
3. Amazon S3 and AWS Security Lake ingestion
4. Amazon Kinesis or Apache Kafka streaming
5. Sigma-compatible detection rules
6. Windows Event Log and firewall parsers
7. Threat-intelligence enrichment
8. Detection suppression and allowlists
9. Terraform-based AWS deployment
10. Pipeline observability and performance testing

Roadmap items are kept separate from implemented functionality so planned work is not presented as completed capability.
