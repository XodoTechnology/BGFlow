# Installing BGFlow

## Option 1: install script (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/XodoTechnology/BGFlow/main/install.sh | sudo bash
```

This downloads the latest release binary for your platform, installs it to
`/usr/local/bin/bgflowd`, creates the `bgflow` user and `/var/lib/bgflow`
data directory, installs the systemd unit, and drops a starter config at
`/etc/bgflow/bgflow.toml`.

Environment overrides:

```bash
BGFLOW_VERSION=v0.1.0       # pin a version
BGFLOW_INSTALL_DIR=/opt/bgflow
```

Then:

```bash
sudoedit /etc/bgflow/bgflow.toml
sudo systemctl enable --now bgflowd
```

## Option 2: Docker

```bash
git clone https://github.com/XodoTechnology/BGFlow.git
cd BGFlow
docker compose up -d --build
```

Or with an explicit compose file / image:

```bash
docker build -t bgflow .
docker run -d --name bgflow \
  -p 8080:8080 -p 2055:2055/udp \
  -v bgflow-data:/var/lib/bgflow \
  -v /path/to/bgflow.toml:/etc/bgflow/bgflow.toml:ro \
  bgflow
```

The container listens on UDP 2055 (flow input) and TCP 8080 (UI/API) by
default; override with `BGFLOW_HTTP_LISTEN` / your own config mount.

## Option 3: from source

```bash
git clone https://github.com/XodoTechnology/BGFlow.git
cd BGFlow
cargo build --release -p bgflowd
sudo install -m755 target/release/bgflowd /usr/local/bin/
sudo mkdir -p /etc/bgflow /var/lib/bgflow
sudo cp bgflow.example.toml /etc/bgflow/bgflow.toml
sudoedit /etc/bgflow/bgflow.toml
```

Then install the systemd unit (see `deploy/bgflowd.service`) or run
`bgflowd --config /etc/bgflow/bgflow.toml` directly.

## Pointing exporters at it

Any NetFlow/IPFIX/sFlow exporter can target BGFlow:

- **Host**: `bgflowd` host IP
- **Port**: whatever `[[inputs]] listen` is set to (default UDP 2055)
- **Protocol**: `auto` handles all supported formats on the same port

Example router config (Cisco-ish):

```
flow exporter BGflow
 export destination 10.0.0.5 2055
 transport udp 2055
 version 9
!
flow monitor BM
 record netflow ipv4 original-input octets
 exporter BGflow
!
```

## Verifying

```bash
curl http://localhost:8080/api/v1/health        # ok
curl http://localhost:8080/api/v1/status       # storage stats
curl http://localhost:8080/metrics | head      # prometheus
open http://localhost:8080                     # UI
```

Try the built-in demo while learning the UI:

```bash
bgflowd --demo 127.0.0.1:2055 --demo-pps 20 --demo-secs 300
```

## Uninstall

```bash
sudo systemctl disable --now bgflowd
sudo rm /etc/systemd/system/bgflowd.service /usr/local/bin/bgflowd
sudo rm -rf /etc/bgflow          # config (data kept in /var/lib/bgflow)
```
