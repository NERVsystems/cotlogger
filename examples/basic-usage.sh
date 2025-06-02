#!/bin/bash
# Basic usage examples for cotlogger

echo "=== CoT Logger Usage Examples ==="
echo

# Build first
echo "Building cotlogger..."
make build
echo

echo "1. Basic TCP connection:"
echo "./cotlogger -host localhost -port 8089 -verbose > test-tcp.log"
echo

echo "2. SSL connection with certificate files:"
echo "./cotlogger -host secure-tak.mil -protocol ssl -cert client.crt -key client.key -ca ca.crt > test-ssl.log"
echo

echo "3. JSON output for analysis:"
echo "./cotlogger -format json -verbose > test.json"
echo

echo "4. Raw output with custom reconnect interval:"
echo "./cotlogger -format raw -reconnect 10s -verbose > test-raw.log"
echo

echo "5. High-volume monitoring with embedded certs:"
echo "./cotlogger -protocol ssl -embedded-certs -format raw > production.log"
echo

echo "Run any of these commands after updating the hostnames and certificate paths!"
echo "Press Ctrl+C to stop logging when running."
