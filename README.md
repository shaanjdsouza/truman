# Truman

Truman is a small CLI toolkit for network scanning and packet tracing.

## Install

Install directly from the project folder:

```bash
pip install .
```

Or install from GitHub:

```bash
pip install git+https://github.com/shaanjdsouza/truman.git
```

This installs the `truman` command and the required Python packages listed in `requirements.txt`.

On Windows, packet capture with Scapy also requires Npcap to be installed separately.

## Usage

Show all available tools:

```bash
truman
```

Scan a local network:

```bash
truman scan -t 192.168.1.0/24
```

Trace ICMP packets to a target:

```bash
truman trace -t 8.8.8.8
```
