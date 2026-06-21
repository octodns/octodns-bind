# Developer Agent Guide for octoDNS BIND Provider

This repository contains the BIND provider and source modules for octoDNS. It supports local zone file parsing and generation, zone transfers (AXFR), and dynamic DNS updates via the RFC 2136 protocol.

> [!IMPORTANT]
> **Core Workflow and Guidelines**
>
> All agents working on this repository must read and follow the general instructions and workflow guidelines defined in the core octoDNS `AGENTS.md` file.
> - **Local check**: Look for the file at `../octodns/AGENTS.md`.
> - **Remote check**: If the local file is not available, fetch it from GitHub: [octoDNS Core AGENTS.md](https://github.com/octodns/octodns/raw/refs/heads/main/AGENTS.md).
>
> You must align your code structure, style, pull request guidelines, and overall development workflows with the instructions specified there.

## Repository & Module Information

### Key Components

All classes are implemented in the package root: [octodns_bind/__init__.py](file:///home/ross/octodns/octodns-bind/octodns_bind/__init__.py).

- **Zone File Provider**: [ZoneFileProvider](file:///home/ross/octodns/octodns-bind/octodns_bind/__init__.py#L99-L382) (aliased as `ZoneFileSource`) reads and writes RFC-compliant BIND-style zone files locally on disk. Supports custom serial generation and SOA fields (refresh, retry, expire, nxdomain, default_ttl).
- **AXFR Source**: [AxfrSource](file:///home/ross/octodns/octodns-bind/octodns_bind/__init__.py#L493-L494) performs zone transfers from a remote DNS server to populate records. Supports TSIG transaction signatures for secure transfers.
- **RFC 2136 Provider**: [Rfc2136Provider](file:///home/ross/octodns/octodns-bind/octodns_bind/__init__.py#L506-L549) (aliased as [BindProvider](file:///home/ross/octodns/octodns-bind/octodns_bind/__init__.py#L550)) sends dynamic DNS updates to BIND servers using the standard RFC 2136 protocol over TCP. Batches changes into updates configured by `update_batch_size`.
- **Authentication**: Supports TSIG keys via `key_name`, `key_secret`, and `key_algorithm` configuration variables.

### Key Workflows & Features

1. **Supported Record Types**: `A`, `AAAA`, `CAA`, `CNAME`, `DS`, `HTTPS`, `LOC`, `MX`, `NAPTR`, `NS`, `PTR`, `SPF`, `SRV`, `SSHFP`, `SVCB`, `TLSA`, `TXT`.
2. **Root Name Server Support**: Fully supported (`SUPPORTS_ROOT_NS=True`).
3. **Idempotence**: `ZoneFileProvider` can optionally load existing zone file states on disk (`read_existing=True`) to make re-runs idempotent, preventing unnecessary serial bumps.
4. **Dynamic Routing**: Not supported (`SUPPORTS_DYNAMIC=False`, `SUPPORTS_GEO=False`).
5. **Dynamic Subnets**: Not supported (`SUPPORTS_DYNAMIC_SUBNETS=False`).
6. **Pool Value Status**: Not supported (`SUPPORTS_POOL_VALUE_STATUS=False`).

## Development & Testing

- **Setup Script**: Run `./script/bootstrap` to create a virtual environment, install dependencies (including `dnspython`, `black`, `isort`, `pyflakes`, and `pytest`), and configure pre-commit hooks.
- **Test Suite**: Run unit tests using `pytest` via `./script/test` (or `pytest tests/`). Test files are located in [tests/](file:///home/ross/octodns/octodns-bind/tests).
- **Code Coverage**: Verify code coverage using `./script/coverage`.

## Key Constraints & Behaviors

- **Python Version**: Targets Python `>=3.9`.
- **Formatting**: Code formatting is enforced via `black` (version `>=26.0.0,<27.0.0`) and `isort`.
