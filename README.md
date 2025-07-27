# MITRE Caldera Plugin: Sandcat Agent
[![Basic Agent Build](https://github.com/mitre/sandcat/actions/workflows/go.yml/badge.svg)](https://github.com/mitre/sandcat/actions/workflows/go.yml)
[![Agent Extensions Build](https://github.com/mitre/sandcat/actions/workflows/sandcatextensions.yml/badge.svg)](https://github.com/mitre/sandcat/actions/workflows/sandcatextensions.yml)

A plugin supplying a default agent to be used in a Caldera operation.

## Environment Variables

Several runtime options can be configured using environment variables instead of
command line flags:

- `SANDCAT_SERVER` – server address
- `SANDCAT_GROUP` – agent group
- `SANDCAT_PAW` – initial paw value
- `SANDCAT_C2NAME` – communication channel name
- `SANDCAT_C2KEY` – C2 key
- `SANDCAT_LISTEN_P2P` – enable peer receivers (`true`/`false`)
- `SANDCAT_HTTP_PROXY` – HTTP proxy gateway URL

These values are read at startup and override the built‑in defaults. Command
line flags still take precedence over environment variables.

[Read the full docs](https://caldera.readthedocs.io/en/latest/Plugin-library.html#sandcat)
