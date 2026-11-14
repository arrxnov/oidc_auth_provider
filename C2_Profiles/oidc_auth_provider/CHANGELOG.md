# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support for mutual TLS and custom CA trust using files uploaded to Mythic's
  operation file store (`oidc_mtls_client.pem`, `oidc_mtls_client.key`,
  `oidc_mtls_ca.pem`), with periodic certificate rotation checks.

## [1.0.0] - 12 April 2026

### Changed

- Initial implementation
  
