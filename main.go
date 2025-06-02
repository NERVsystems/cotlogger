// Package main provides a lightweight CoT message logger for TAK servers
//
// cotlogger is a diagnostic tool that connects to a TAK server and logs
// all Cursor on Target (CoT) messages to a file. It supports various output
// formats and includes embedded certificates for easy deployment.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Build-time variables
var (
	version   = "dev"
	buildTime = "unknown"
	goVersion = "unknown"
)

// Embedded certificate data - update these with your actual certificates
const (
	embeddedCert = `-----BEGIN CERTIFICATE-----
// Replace with your actual client certificate
-----END CERTIFICATE-----`

	embeddedKey = `-----BEGIN PRIVATE KEY-----
// Replace with your actual private key
-----END PRIVATE KEY-----`

	embeddedCA = `-----BEGIN CERTIFICATE-----
// Replace with your actual CA certificate
-----END CERTIFICATE-----`

	// Minimal hello message sent after connecting. Adjust as needed for
	// your TAK server's expected handshake.
	helloMessage = `<hello version="1.0" uid="cotlogger"/>\n`
)

// Config holds connection configuration
type Config struct {
	Host              string
	Port              int
	Protocol          string // tcp or ssl
	UseEmbeddedCerts  bool
	CertFile          string
	KeyFile           string
	CAFile            string
	ReconnectInterval time.Duration
	WriteTimeout      time.Duration
	ReadTimeout       time.Duration
	OutputFormat      string // raw, formatted, json
	Verbose           bool
}

// CoTLogger represents the main logger instance
type CoTLogger struct {
	config       Config
	logger       *slog.Logger
	conn         net.Conn
	reader       *bufio.Reader
	mu           sync.RWMutex
	done         chan struct{}
	outputMu     sync.Mutex
	messageCount int64
}

// Event represents a basic CoT event structure for parsing
type Event struct {
	XMLName xml.Name `xml:"event"`
	Version string   `xml:"version,attr"`
	UID     string   `xml:"uid,attr"`
	Type    string   `xml:"type,attr"`
	How     string   `xml:"how,attr"`
	Time    string   `xml:"time,attr"`
	Start   string   `xml:"start,attr"`
	Stale   string   `xml:"stale,attr"`
}

func main() {
	// Parse command line flags
	var (
		host              = flag.String("host", "localhost", "TAK server hostname")
		port              = flag.Int("port", 8089, "TAK server port")
		protocol          = flag.String("protocol", "tcp", "Connection protocol (tcp or ssl)")
		useEmbeddedCerts  = flag.Bool("embedded-certs", false, "Use embedded certificates")
		certFile          = flag.String("cert", "", "Client certificate file (for SSL)")
		keyFile           = flag.String("key", "", "Client private key file (for SSL)")
		caFile            = flag.String("ca", "", "CA certificate file (for SSL)")
		outputFormat      = flag.String("format", "formatted", "Output format: raw, formatted, json")
		reconnectInterval = flag.Duration("reconnect", 30*time.Second, "Reconnection interval")
		readTimeout       = flag.Duration("read-timeout", 30*time.Second, "Read timeout")
		writeTimeout      = flag.Duration("write-timeout", 30*time.Second, "Write timeout")
		verbose           = flag.Bool("verbose", false, "Enable verbose logging")
		showVersion       = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	// Show version if requested
	if *showVersion {
		fmt.Printf("cotlogger %s\n", version)
		fmt.Printf("Built: %s\n", buildTime)
		fmt.Printf("Go: %s\n", goVersion)
		return
	}

	// Setup logging
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true,
	}))

	// Create configuration
	config := Config{
		Host:              *host,
		Port:              *port,
		Protocol:          *protocol,
		UseEmbeddedCerts:  *useEmbeddedCerts,
		CertFile:          *certFile,
		KeyFile:           *keyFile,
		CAFile:            *caFile,
		ReconnectInterval: *reconnectInterval,
		WriteTimeout:      *writeTimeout,
		ReadTimeout:       *readTimeout,
		OutputFormat:      *outputFormat,
		Verbose:           *verbose,
	}

	// Validate configuration
	if config.Protocol == "ssl" && !config.UseEmbeddedCerts {
		if config.CertFile == "" || config.KeyFile == "" || config.CAFile == "" {
			logger.Error("SSL mode requires certificate files or --embedded-certs flag")
			os.Exit(1)
		}
	}

	// Create CoT logger
	cotLogger, err := NewCoTLogger(config, logger)
	if err != nil {
		logger.Error("failed to create CoT logger", "error", err)
		os.Exit(1)
	}
	defer cotLogger.Close()

	// Handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("received shutdown signal")
		cancel()
	}()

	// Start logging
	logger.Info("starting CoT logger",
		"version", version,
		"host", config.Host,
		"port", config.Port,
		"protocol", config.Protocol,
		"format", config.OutputFormat)

	if err := cotLogger.Run(ctx); err != nil {
		logger.Error("CoT logger error", "error", err)
		os.Exit(1)
	}

	logger.Info("CoT logger stopped gracefully")
}

// NewCoTLogger creates a new CoT logger instance
func NewCoTLogger(config Config, logger *slog.Logger) (*CoTLogger, error) {
	cotLogger := &CoTLogger{
		config: config,
		logger: logger,
		done:   make(chan struct{}),
	}

	return cotLogger, nil
}

// Run starts the CoT logger main loop
func (c *CoTLogger) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := c.connect(ctx); err != nil {
				c.logger.Error("connection failed", "error", err)
				c.logger.Info("retrying connection", "interval", c.config.ReconnectInterval)
				time.Sleep(c.config.ReconnectInterval)
				continue
			}

			// Start message processing
			if err := c.processMessages(ctx); err != nil {
				c.logger.Error("message processing error", "error", err)
				c.handleConnectionError(err)
				time.Sleep(c.config.ReconnectInterval)
				continue
			}
		}
	}
}

// connect establishes connection to TAK server
func (c *CoTLogger) connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return nil // Already connected
	}

	var conn net.Conn
	var err error

	if c.config.Protocol == "ssl" {
		conn, err = c.connectSSL()
	} else {
		c.logger.Warn("using insecure TCP connection")
		conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", c.config.Host, c.config.Port))
	}

	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.conn = conn
	c.reader = bufio.NewReader(conn)
	if err := c.sendHello(); err != nil {
		conn.Close()
		c.conn = nil
		c.reader = nil
		return fmt.Errorf("failed to send hello: %w", err)
	}
	c.logger.Info("connected to TAK server",
		"host", c.config.Host,
		"port", c.config.Port,
		"protocol", c.config.Protocol)

	return nil
}

// connectSSL establishes SSL connection to TAK server
func (c *CoTLogger) connectSSL() (net.Conn, error) {
	var cert tls.Certificate
	var caCertPool *x509.CertPool
	var err error

	if c.config.UseEmbeddedCerts {
		// Use embedded certificates
		cert, err = tls.X509KeyPair([]byte(embeddedCert), []byte(embeddedKey))
		if err != nil {
			return nil, fmt.Errorf("failed to load embedded certificate: %w", err)
		}

		caCertPool = x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM([]byte(embeddedCA)); !ok {
			return nil, fmt.Errorf("failed to parse embedded CA certificate")
		}
	} else {
		// Load certificates from files
		cert, err = tls.LoadX509KeyPair(c.config.CertFile, c.config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}

		caCert, err := os.ReadFile(c.config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool = x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   c.config.Host,
		MinVersion:   tls.VersionTLS12,
		// For development: skip hostname verification but verify cert chain
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				Roots:         caCertPool,
				CurrentTime:   time.Now(),
				Intermediates: x509.NewCertPool(),
			}

			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}

			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}

	tlsConn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", c.config.Host, c.config.Port), tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to establish SSL connection: %w", err)
	}

	// Ensure TLS handshake is complete
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return tlsConn, nil
}

// sendHello sends the initial handshake message after connecting.
func (c *CoTLogger) sendHello() error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return fmt.Errorf("connection is nil")
	}
	if c.config.WriteTimeout > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout)); err != nil {
			return fmt.Errorf("failed to set write deadline: %w", err)
		}
	}
	_, err := conn.Write([]byte(helloMessage))
	return err
}

// processMessages handles the message processing loop
func (c *CoTLogger) processMessages(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			return nil
		default:
			rawMsg, err := c.readMessage()
			if err != nil {
				if err == io.EOF {
					return err
				}
				if isTimeout(err) {
					c.logger.Debug("read timeout, continuing")
					continue
				}
				return fmt.Errorf("failed to read message: %w", err)
			}

			// Log the message
			if err := c.logMessage(rawMsg); err != nil {
				c.logger.Error("failed to log message", "error", err)
				continue
			}

			count := atomic.AddInt64(&c.messageCount, 1)
			c.logger.Debug("logged message",
				"count", count,
				"size", len(rawMsg),
				"type", c.extractType(rawMsg))
		}
	}
}

// readMessage reads a single message from the connection
func (c *CoTLogger) readMessage() (string, error) {
	c.mu.RLock()
	conn := c.conn
	reader := c.reader
	c.mu.RUnlock()

	if conn == nil || reader == nil {
		return "", fmt.Errorf("connection is nil")
	}

	if c.config.ReadTimeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout)); err != nil {
			return "", fmt.Errorf("failed to set read deadline: %w", err)
		}
	}

	data, err := reader.ReadBytes('\n')
	if err != nil {
		return "", err
	}

	data = bytes.TrimRight(data, "\x00\r\n")
	data, err = decompressIfNeeded(data)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// logMessage logs a CoT message according to the configured format
func (c *CoTLogger) logMessage(rawMsg string) error {
	c.outputMu.Lock()
	defer c.outputMu.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	var logEntry string

	switch c.config.OutputFormat {
	case "raw":
		logEntry = fmt.Sprintf("%s|%s\n", timestamp, rawMsg)
	case "json":
		logEntry = c.formatAsJSON(timestamp, rawMsg)
	case "formatted":
		fallthrough
	default:
		logEntry = fmt.Sprintf("\n=== %s - INCOMING ===\n%s\n", timestamp, rawMsg)
	}

	if _, err := fmt.Fprint(os.Stdout, logEntry); err != nil {
		return fmt.Errorf("failed to write log entry: %w", err)
	}

	// Flush immediately for real-time logging
	os.Stdout.Sync()

	return nil
}

// formatAsJSON formats the message as JSON
func (c *CoTLogger) formatAsJSON(timestamp, rawMsg string) string {
	// Simple JSON formatting - could be enhanced with proper JSON marshaling
	escapedMsg := strings.ReplaceAll(rawMsg, `"`, `\"`)
	escapedMsg = strings.ReplaceAll(escapedMsg, "\n", "\\n")
	escapedMsg = strings.ReplaceAll(escapedMsg, "\r", "\\r")

	return fmt.Sprintf(`{"timestamp":"%s","message":"%s"}`+"\n", timestamp, escapedMsg)
}

// decompressIfNeeded decompresses zlib or gzip encoded data if detected.
func decompressIfNeeded(data []byte) ([]byte, error) {
	if len(data) >= 2 {
		// gzip header
		if data[0] == 0x1f && data[1] == 0x8b {
			r, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			defer r.Close()
			return io.ReadAll(r)
		}

		// zlib header
		if data[0] == 0x78 && (data[1] == 0x9c || data[1] == 0x01 || data[1] == 0xda) {
			r, err := zlib.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			defer r.Close()
			return io.ReadAll(r)
		}
	}
	return data, nil
}

// extractType extracts the message type from raw XML
func (c *CoTLogger) extractType(raw string) string {
	var event Event
	if err := xml.Unmarshal([]byte(raw), &event); err != nil {
		return "unknown"
	}
	return event.Type
}

// handleConnectionError handles connection errors
func (c *CoTLogger) handleConnectionError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	c.logger.Warn("connection error, will reconnect", "error", err)
}

// Close closes the CoT logger and cleans up resources
func (c *CoTLogger) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	close(c.done)

	var errs []error

	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close connection: %w", err))
		}
		c.conn = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}

	c.logger.Info("CoT logger closed", "total_messages", c.messageCount)
	return nil
}

// isTimeout checks if an error is a timeout error
func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}
