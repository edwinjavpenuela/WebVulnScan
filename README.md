# WebVulnScan

WebVulnScan is a defensive Python CLI for running reproducible Nmap profiles against web targets you are explicitly authorized to assess. It keeps the workflow simple, but adds the pieces expected from a professional script: argument parsing, input validation, safe command construction, dry-run support, structured reports, timeouts, and testable functions.

## Features

- Non-interactive CLI suitable for repeatable local assessments.
- Target validation for domains, IP addresses, CIDR ranges, and URLs.
- Built-in scan profiles: `quick`, `standard`, `web`, `deep`, and `low-noise`.
- Explicit authorization gate with `--confirm-authorized`.
- `--dry-run` mode to inspect the exact Nmap command before executing it.
- Text and JSON reports, with optional file output.
- Configurable timeout and port override.
- Standard-library implementation; Nmap is the only runtime tool required.

## Requirements

- Python 3.10 or newer.
- Nmap installed and available in `PATH`.

Check the requirements:

```bash
python --version
nmap --version
```

## Usage

Run directly from the repository:

```bash
python analisis_vulnerabilidades.py --help
```

Or install a local CLI command:

```bash
python -m pip install -e .
webvulnscan --help
```

List available profiles:

```bash
python analisis_vulnerabilidades.py --list-profiles
```

Preview a scan without executing Nmap:

```bash
python analisis_vulnerabilidades.py example.com --profile standard --dry-run
```

Run a standard authorized scan:

```bash
python analisis_vulnerabilidades.py example.com --profile standard --confirm-authorized
```

Focus on common web ports and save a JSON report:

```bash
python analisis_vulnerabilidades.py https://example.com/login \
  --profile web \
  --format json \
  --output reports/example-web.json \
  --confirm-authorized
```

Override ports when you need a narrower assessment:

```bash
python analisis_vulnerabilidades.py 192.168.1.10 --ports 80,443,8080 --confirm-authorized
```

## Scan Profiles

- `quick`: service detection on the 100 most common ports.
- `standard`: balanced profile with service detection and default Nmap scripts.
- `web`: common HTTP/HTTPS and alternate web service ports.
- `deep`: broad all-port assessment with Nmap aggressive detection. This can take a long time.
- `low-noise`: slower, conservative scan over fewer common ports. This may require privileged execution because it uses SYN scanning.

Legacy aliases such as `sigiloso` and `agresivo` are still accepted and mapped to professional profile names.

## Local Development

Run the tests:

```bash
python -m unittest discover -s tests
```

Compile-check the script:

```bash
python -m py_compile analisis_vulnerabilidades.py
```

## Responsible Use

Use WebVulnScan only against systems where you have explicit authorization. Unauthorized scanning may be illegal and harmful. The tool intentionally requires `--confirm-authorized` before running Nmap so accidental execution is less likely.
