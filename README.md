# CoT Logger

A lightweight, standalone diagnostic tool for logging Cursor on Target (CoT) messages from TAK servers.

## Overview

`cotlogger` is a purpose-built tool that connects to Team Awareness Kit (TAK) servers and captures all CoT message traffic in real-time. It's designed for network diagnostics, traffic analysis, debugging, and operational monitoring of TAK environments.

## Key Features

- **🔌 Multiple Connection Modes**: TCP and SSL/TLS support
- **📦 Embedded Certificates**: Bundle certs directly in binary for zero-config deployment
- **📝 Multiple Output Formats**: Human-readable, raw, and JSON formats
- **⚡ Real-time Logging**: Immediate disk writes with automatic flushing
- **🔄 Auto-Reconnection**: Robust connection handling with configurable retry intervals
- **🛡️ Production Ready**: Thread-safe, graceful shutdown, comprehensive error handling
- **🔍 Zero Dependencies**: Uses only Go standard library

## Quick Start

```bash
# Clone and build
git clone https://github.com/NERVsystems/cotlogger.git
cd cotlogger
go build

# Basic usage - TCP connection
./cotlogger -host your-tak-server.com -port 8089 > messages.log

# SSL connection with certificates
./cotlogger -host secure-tak.mil -protocol ssl -cert client.crt -key client.key -ca ca.crt > secure-messages.log

# JSON output for analysis tools
./cotlogger -format json -verbose > data.json
```

## Installation

### From Source
```bash
git clone https://github.com/NERVsystems/cotlogger.git
cd cotlogger
go build -o cotlogger
```

### With Version Info
```bash
go build -ldflags "-X main.version=$(git describe --tags)" -o cotlogger
```

### Using Make
```bash
make build              # Local build
make build-all          # Cross-platform builds  
make install            # Install to /usr/local/bin
```

## Usage Examples

### Basic TCP Monitoring
```bash
./cotlogger -host tak.example.com -port 8089 -verbose > messages.log
```

### Secure SSL Connection
```bash
./cotlogger \
  -host secure-tak.mil \
  -protocol ssl \
  -cert /path/to/client.crt \
  -key /path/to/client.key \
  -ca /path/to/ca.crt \
  > secure-messages.log
```

### JSON Output for Analysis
```bash
./cotlogger -format json -verbose > cot-data.json
```

### High-Volume Production Monitoring
```bash
./cotlogger \
  -host production-tak.mil \
  -protocol ssl \
  -embedded-certs \
  -format raw \
  -reconnect 5s \
  > /var/log/tak/cot-$(date +%Y%m%d).log
```

## Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-host` | `localhost` | TAK server hostname |
| `-port` | `8089` | TAK server port |
| `-protocol` | `tcp` | Connection protocol (`tcp` or `ssl`) |
| `-embedded-certs` | `false` | Use embedded certificates |
| `-cert` | | Client certificate file (SSL mode) |
| `-key` | | Client private key file (SSL mode) |
| `-ca` | | CA certificate file (SSL mode) |
| `-format` | `formatted` | Output format (`raw`, `formatted`, `json`) |
| `-reconnect` | `30s` | Reconnection interval |
| `-read-timeout` | `30s` | Socket read timeout |
| `-write-timeout` | `30s` | Socket write timeout |
| `-verbose` | `false` | Enable verbose logging |
| `-version` | `false` | Show version information |

## Output Formats

### Formatted (Default)
Human-readable format with clear timestamps and XML formatting:
```
=== 2025-01-30T15:08:22Z - INCOMING ===
<?xml version="1.0" encoding="UTF-8"?>
<event version="2.0" uid="ANDROID-abc123" type="a-f-G-U-C" how="m-g" time="2025-01-30T15:08:22Z">
  <point lat="19.87145" lon="99.821362" hae="365.443"/>
  <detail>
    <contact callsign="BRAVO-6" endpoint="*:-1:stcp"/>
  </detail>
</event>
```

### Raw
Pipe-delimited format optimized for parsing and analysis:
```
2025-01-30T15:08:22Z|<?xml version="1.0"?><event version="2.0" uid="ANDROID-abc123"...
```

### JSON
Structured JSON format for programmatic analysis:
```json
{"timestamp":"2025-01-30T15:08:22Z","message":"<?xml version=\"1.0\"?><event..."}
```

## Embedded Certificates

For zero-config deployment, embed certificates directly in the binary:

1. **Edit `main.go`** and replace the certificate constants:
```go
const (
    embeddedCert = `-----BEGIN CERTIFICATE-----
MIIFoTCCA4mgAwIBAgIUJ1...your-actual-certificate...
-----END CERTIFICATE-----`

    embeddedKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w...your-actual-private-key...
-----END PRIVATE KEY-----`

    embeddedCA = `-----BEGIN CERTIFICATE-----
MIIFdTCCA12gAwIBAgIUK2...your-actual-ca-cert...
-----END CERTIFICATE-----`
)
```

2. **Build and deploy**:
```bash
go build -o cotlogger-embedded
./cotlogger-embedded -host tak.server.mil -protocol ssl -embedded-certs
```

## Security Considerations

- **Certificate Validation**: Performs full certificate chain validation in SSL mode
- **Hostname Verification**: Skipped for development flexibility (configurable)
- **File Permissions**: Creates logs with 0644, directories with 0755 permissions
- **Embedded Certs**: Keep binaries secure and rotate certificates regularly
- **Network Security**: Always use SSL mode in production environments

## Operational Features

- **Real-time Logging**: Messages are immediately written and flushed to disk
- **Memory Efficient**: ~8KB buffer size, minimal memory footprint
- **Connection Resilience**: Automatic reconnection with configurable backoff
- **Graceful Shutdown**: Clean resource cleanup on SIGINT/SIGTERM
- **Thread Safety**: Concurrent-safe message logging with proper mutex protection
- **Structured Logging**: Built-in slog integration for operational visibility

## Use Cases

### Network Diagnostics
Monitor TAK traffic patterns, connection issues, and message flow:
```bash
./cotlogger -verbose -read-timeout 5s -reconnect 5s
```

### Security Analysis
Capture traffic for security auditing and threat analysis:
```bash
./cotlogger -format json -verbose > audit-$(date +%Y%m%d).json
```

### Performance Testing
Monitor high-volume environments:
```bash
./cotlogger -format raw -verbose > perf-test.log
```

### Development & Debugging
Debug TAK integrations and protocol issues:
```bash
./cotlogger -host localhost -protocol tcp -format formatted -verbose
```

## Build Targets

```bash
make build              # Current platform
make build-all          # Linux, macOS, Windows
make build-linux        # Linux AMD64
make build-darwin       # macOS AMD64/ARM64
make build-windows      # Windows AMD64
make clean              # Clean artifacts
make install            # Install to system PATH
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Documentation**: See the `docs/` directory for detailed documentation
- **Examples**: Check the `examples/` directory for usage examples

## Related Projects

- [nerv-tak](https://github.com/NERVsystems/nerv-tak) - AI-powered TAK assistant (where this tool originated)
- [TAK Server](https://tak.gov/) - Official TAK Server documentation

