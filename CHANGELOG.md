# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project scaffold: typed package skeleton, technical requirements, architecture and setup
  docs, CI, and test scaffolding.
- AuthZEN 1.0 pydantic models (single + batch evaluation).
- Provider-aware tool-call adapters (OpenAI / Anthropic / LangChain).
- `ScannerConfig` (pydantic) with secure defaults; exception hierarchy.
- `AuthZENScanner` public constructor and signatures.

### Not yet implemented
- The scan pipeline, AuthZEN client transport, mapping policy and decision cache
  (`scan()`/client/cache currently raise `NotImplementedError`).
- Example PDP deployments (OpenFGA / Cedar / mock) and the behavioural test suite.

## [0.0.1a0]
- Initial pre-alpha scaffold.
