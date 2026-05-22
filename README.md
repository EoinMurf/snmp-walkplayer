# SNMP Walk Player

A lightweight web app that turns a customer's `snmpwalk` output into a live simulated SNMP device — letting you replay their exact hardware in a local lab environment and collect real metrics with Datadog NDM.

## What it does

1. **Drop a walk file** — drag and drop any `snmpwalk` text file into the browser
2. **Auto-detects the device** — reads `sysDescr`, `sysObjectID`, device name, and OID count
3. **Matches a Datadog profile** — finds the right SNMP profile based on the device's `sysObjectID`
4. **Simulates the device** — starts a local SNMP agent on `127.0.0.1:1162` serving the exact walk data
5. **Updates the Datadog Agent** — writes `conf.yaml` with the matched profile and restarts the agent
6. **Metrics flow into Datadog** — within ~1 minute, real customer metrics appear in NDM

![screenshot placeholder](docs/screenshot.png)

## Prerequisites

- Python 3.8+
- [Datadog Agent](https://docs.datadoghq.com/agent/) with SNMP check enabled *(optional — the simulator runs without it)*

## Installation

```bash
git clone https://github.com/EoinMurf/snmp-walkplayer.git
cd snmp-walkplayer
pip install -r requirements.txt
```

## Usage

```bash
python3 snmp-walkplayer.py
```

Then open **http://localhost:7374** in your browser.

### Getting a walk file from a customer device

Run this on a machine with SNMP access to the device:

```bash
snmpwalk -v2c -c <community> <device-ip> . > customer-device.txt
```

Drop `customer-device.txt` onto the app. The walk file can be any size — the app streams it without loading it all into memory.

## How profile matching works

The app reads the `sysObjectID` from the walk (e.g. `1.3.6.1.4.1.9.1.1745`) and scans every YAML file in your Datadog Agent's profile directories looking for a matching `sysobjectid:` entry. Wildcard OIDs (e.g. `1.3.6.1.4.1.9.1.*`) are supported.

If a match is found it's shown with a green badge in the UI and automatically written to `conf.yaml`. If no match is found, the simulation still runs — you just need to set the profile manually.

## Configuration

All settings can be overridden with environment variables:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `7374` | Web UI port |
| `SNMP_PORT` | `1162` | UDP port for the simulated device |
| `DD_SNMP_CONF` | auto-detected | Path to `conf.d/snmp.d/conf.yaml` |
| `DD_DEFAULT_PROFILES` | auto-detected | Path to agent's `default_profiles/` directory |
| `DD_USER_PROFILES` | auto-detected | Path to agent's custom `profiles/` directory |

The agent path is auto-detected at these locations:
- **macOS**: `/opt/datadog-agent` (standard pkg install)
- **Linux**: `/etc/datadog-agent` (apt/yum install)

## Supported walk formats

The parser handles standard `snmpwalk` output:

```
.1.3.6.1.2.1.1.1.0 = STRING: "Cisco IOS Software..."
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.9.1.1745
.1.3.6.1.2.1.2.2.1.3.1 = INTEGER: 6
.1.3.6.1.2.1.2.2.1.5.1 = Gauge32: 1000000000
.1.3.6.1.4.1.9.9.91.1.1.1.1.4.1 = INTEGER: 35
```

Supported SNMP types: `INTEGER`, `STRING`, `OID`, `IpAddress`, `Counter32`, `Gauge32`, `TimeTicks`, `Counter64`, `Hex-STRING`, `BITS`.

## Stopping the simulation

Click **Stop** in the UI, or press `Ctrl+C` in the terminal.

## Using without the Datadog Agent

The SNMP simulator runs independently. You can point any SNMP poller at `127.0.0.1:1162` (community `public`) to query the simulated device — no Datadog Agent required.

```bash
snmpwalk -v2c -c public 127.0.0.1:1162 .
```
