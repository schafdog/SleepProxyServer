# Running Sleep Proxy Server Without Installation

## Prerequisites
Install system dependencies:
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv avahi-daemon

# RHEL/CentOS/Fedora
sudo dnf install python3 python3-pip python3-venv avahi

# Arch Linux
sudo pacman -S python python-pip avahi
```

## Method 1: Virtual Environment (Recommended)

```bash
# Clone and setup
git clone https://github.com/rcloran/SleepProxyServer.git
cd SleepProxyServer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install dnslib netifaces scapy dbus-python

# Run directly
sudo ./scripts/sleepproxyd --verbose

# Or with Python
sudo python3 scripts/sleepproxyd --verbose
```

## Method 2: System Python (No venv)

```bash
# Install dependencies system-wide
pip3 install --user dnslib netifaces scapy dbus-python

# Run from source directory
cd SleepProxyServer
sudo python3 scripts/sleepproxyd --verbose
```

## Method 3: Docker Container

```bash
# Create Dockerfile in project root
cat > Dockerfile << EOF
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    avahi-daemon \\
    dbus \\
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Install Python dependencies
RUN pip install dnspython netifaces scapy dbus-python

# Expose UDP port
EXPOSE 3535/udp

# Run the service
CMD ["python3", "scripts/sleepproxyd", "--verbose"]
EOF

# Build and run
docker build -t sleepproxy .
docker run --network host --privileged sleepproxy
```

## Method 4: Portable Script

Create a launcher script:

```bash
#!/bin/bash
# save as: run_sleepproxy.sh

# Set script directory as Python path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"

# Check dependencies
python3 -c "
import sys
missing = []
for module in ['dns', 'netifaces', 'scapy', 'dbus']:
    try:
        __import__(module)
    except ImportError:
        missing.append(module if module != 'dns' else 'dnspython')
        
if missing:
    print('Missing dependencies:', ', '.join(missing))
    print('Install with: pip3 install --user ' + ' '.join(missing))
    sys.exit(1)
print('All dependencies found ✓')
"

# Run the server
sudo python3 "$SCRIPT_DIR/scripts/sleepproxyd" "$@"
```

## Method 5: Development Mode

```bash
# Install in development mode (editable)
cd SleepProxyServer
pip3 install --user -e .

# Now you can run from anywhere
sleepproxyd --verbose
```

## Quick Start Commands

```bash
# One-liner setup and run
git clone https://github.com/rcloran/SleepProxyServer.git && cd SleepProxyServer && python3 -m venv venv && source venv/bin/activate && pip install dnspython netifaces scapy dbus-python && sudo ./scripts/sleepproxyd --verbose
```

## Troubleshooting

### Permission Issues
- Sleep Proxy needs root for raw sockets (ARP spoofing)
- Use `sudo` when running

### Missing dbus-python
```bash
# If pip fails to install dbus-python
sudo apt-get install python3-dev libdbus-1-dev libdbus-glib-1-dev
pip install dbus-python
```

### Avahi Not Running
```bash
sudo systemctl start avahi-daemon
sudo systemctl enable avahi-daemon
```

### Firewall Issues
```bash
# Allow mDNS traffic
sudo ufw allow 5353/udp
sudo ufw allow 3535/udp
```

## Stopping the Server
- Ctrl+C to stop
- Or send SIGTERM: `sudo pkill -f sleepproxyd`

## Testing
```bash
# Check if service is advertising
avahi-browse _sleep-proxy._udp

# Monitor logs
sudo ./scripts/sleepproxyd --verbose
```