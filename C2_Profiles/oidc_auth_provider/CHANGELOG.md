# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support for mutual TLS and custom CA trust using certificate files uploaded
  through the auth container's file browser. Filenames are configured with
  `mtls_cert_file`, `mtls_key_file`, and `mtls_ca_file` in `config.json`.

## [1.0.0] - 12 April 2026

### Changed

- Initial implementation
  
