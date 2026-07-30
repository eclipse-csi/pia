# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-07-29

### Added
* `sync` and `create-dt-projects` CLI (#68, #76, #82)
* Local CLI e2e test setup (#72, #77)

### Removed
* `add-workload` and `add-dt-project` CLI (#69)

### Fixed
* DB connection loss (#65)
* DB uniqueness constraints - DependencyTrack product names must be unique
  within EF projects (#73, #80)
* Block PRs on zizmor findings (#83)
* Match Jenkins issuer against registered workloads (#84)

## [0.5.0] - 2026-07-03

### Changed
* Uncouple db migration from app deployment (#61)

## [0.4.0] - 2026-07-01

### Fixed
* Validate issuer/URL by scheme and host instead of string prefix (#62)

## [0.3.0] - 2026-06-29

### Added
* Database CLI (#45)

### Changed
* Re-design model and replace projects.yaml with postgres database (#40, #58)
* Add verbose logging (#32)
* Separate authentication and API endpoint logic (#41)
* Strengthen GitHub authentication (#51)
* Change `/upload/sbom` response (#47)
* Misc CI improvements (#48, #50)

### Fixed
* Use correct DependendencyTrack HTTP request method (#30)
* Escape unverified JWT `iss` claim in log output (#60)

## [0.2.1] - 2026-03-10
* Include /livez endpoint

## [0.2.0] - 2026-03-05

### Added
* Support `isLatest` DependencyTrack post parameter

### Fixed
* Changed application port in Dockerfile

## [0.1.0] - 2026-01-21

### Added

- Initial release of PIA (Project Identity Authority)
- OIDC-based authentication broker for SBOM uploads to DependencyTrack
- FastAPI-based REST API
- Support for GitHub Actions OIDC tokens
- Support for Jenkins OIDC tokens
- Project configuration via `projects.yaml`
