#!/bin/bash
# Basic usage examples for cotlogger

echo "=== CoT Logger Usage Examples ==="
echo

# Build first
echo "Building cotlogger..."
make build
echo

echo "1. Basic TCP connection:"
echo "./cotlogger -host localhost -port 8089 -output test-tcp.log -verbose"
echo

echo "2. SSL connection with certificate files:"
echo "./cotlogger -host secure-tak.mil -protocol ssl -cert client.crt -key client.key -ca ca.crt -output test-ssl.log"
echo

echo "3. JSON output for analysis:"
echo "./cotlogger -format json -output test.json -verbose"
echo

echo "4. Raw output with custom reconnect interval:"
echo "./cotlogger -format raw -output test-raw.log -reconnect 10s -verbose"
echo

echo "5. High-volume monitoring with embedded certs:"
echo "./cotlogger -protocol ssl -embedded-certs -format raw -output production.log"
echo

echo "Run any of these commands after updating the hostnames and certificate paths!"
echo "Press Ctrl+C to stop logging when running."
