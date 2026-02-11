# CLAUDE.md — fingerprintx

## Operating Principles (Non-Negotiable)

- **Correctness over cleverness**: Prefer boring, readable solutions that are easy to maintain.
- **Smallest change that works**: Minimize blast radius; don't refactor adjacent code unless it meaningfully reduces
  risk or complexity.
- **Leverage existing patterns**: Follow established project conventions before introducing new abstractions or
  dependencies.
- **Prove it works**: "Seems right" is not done. Validate with tests/build/lint and/or a reliable manual repro.
- **Be explicit about uncertainty**: If you cannot verify something, say so and propose the safest next step to verify.

---

## Workflow Orchestration

### 1. Plan Mode Default

- Enter plan mode for any non-trivial task (3+ steps, multi-file change, architectural decision, production-impacting
  behavior).
- Include verification steps in the plan (not as an afterthought).
- If new information invalidates the plan: **stop**, update the plan, then continue.
- Write a crisp spec first when requirements are ambiguous (inputs/outputs, edge cases, success criteria).

### 2. Subagent Strategy (Parallelize Intelligently)

- Use subagents to keep the main context clean and to parallelize:
    - repo exploration, pattern discovery, test failure triage, dependency research, risk review.
- Give each subagent **one focused objective** and a concrete deliverable:
    - "Find where X is implemented and list files + key functions" beats "look around."
- Merge subagent outputs into a short, actionable synthesis before coding.

### 3. Incremental Delivery (Reduce Risk)

- Prefer **thin vertical slices** over big-bang changes.
- Land work in small, verifiable increments:
    - implement → test → verify → then expand.
- When feasible, keep changes behind:
    - feature flags, config switches, or safe defaults.

### 4. Verification Before "Done"

- Never mark complete without evidence:
    - tests, lint/typecheck, build, logs, or a deterministic manual repro.
- Compare behavior baseline vs changed behavior when relevant.
- Ask: "Would a staff engineer approve this diff and the verification story?"

### 5. Demand Elegance (Balanced)

- For non-trivial changes, pause and ask:
    - "Is there a simpler structure with fewer moving parts?"
- If the fix is hacky, rewrite it the elegant way **if** it does not expand scope materially.
- Do not over-engineer simple fixes; keep momentum and clarity.

---

## Project Overview

**fingerprintx** is a network service fingerprinting tool written in Go. Given a host:port, it identifies what service is running by sending protocol-specific probes and analyzing responses. It supports 33+ protocols (HTTP, SSH, MySQL, RDP, Redis, etc.) via a plugin architecture.

Originally forked from [Praetorian Security's fingerprintx](https://github.com/praetorian-inc/fingerprintx), now maintained at `github.com/chrizzn/fingerprintx`.

**Key design decisions:**
- Plugin-based architecture — each protocol is a self-contained plugin
- TLS-first connection strategy — always tries TLS before raw TCP
- Sequential scanning (concurrency was removed intentionally)
- Usable both as a CLI tool and as a Go library

**License:** Apache 2.0

## Repository Structure

```
fingerprintx/
├── cmd/fingerprintx/fingerprintx.go  # CLI entry point → runner.Execute()
├── pkg/
│   ├── plugins/                       # Plugin system core
│   │   ├── types.go                   # Plugin interface, Service, Target, FingerprintConn, CreateServiceFrom()
│   │   ├── plugins.go                 # Plugin registry (global map + RegisterPlugin())
│   │   ├── connection.go              # Connect() — TLS-first, then raw TCP/UDP
│   │   ├── shared/                    # Shared utilities for plugins
│   │   │   ├── requests.go            # Send/Recv/SendRecv/RecvAll/SendRecvAll
│   │   │   ├── error.go              # Custom error types (ReadError, WriteError, etc.)
│   │   │   └── ntlm/                 # NTLM auth utilities (used by SMB, MSSQL, etc.)
│   │   └── services/                  # 33 protocol plugins (one directory each)
│   │       ├── http/                  # HTTP — priority 0, uses wappalyzer + favicon hashing
│   │       ├── ssh/                   # SSH — priority 2, full key exchange + auth check
│   │       ├── mysql/                 # MySQL/MariaDB
│   │       ├── redis/                 # Redis
│   │       ├── dns/                   # DNS (TCP + UDP plugins in one package)
│   │       ├── rdp/                   # RDP
│   │       ├── smb/                   # SMB
│   │       ├── smtp/                  # SMTP
│   │       ├── ftp/                   # FTP
│   │       ├── postgres/              # PostgreSQL
│   │       ├── mssql/                 # MS SQL Server
│   │       ├── kafka/                 # Kafka
│   │       ├── ldap/                  # LDAP
│   │       ├── mqtt/                  # MQTT (v3/v5)
│   │       ├── modbus/               # Modbus
│   │       ├── vnc/                   # VNC
│   │       ├── telnet/               # Telnet
│   │       ├── pop3/                  # POP3
│   │       ├── imap/                  # IMAP
│   │       ├── ntp/                   # NTP (UDP)
│   │       ├── snmp/                  # SNMP (UDP)
│   │       ├── jdwp/                  # Java Debug Wire Protocol
│   │       ├── oracledb/             # Oracle Database
│   │       ├── rtsp/                  # RTSP
│   │       ├── rsync/                # Rsync
│   │       ├── openvpn/              # OpenVPN (UDP)
│   │       ├── ipsec/                # IPSec (UDP)
│   │       ├── stun/                  # STUN (UDP)
│   │       ├── dhcp/                  # DHCP (UDP)
│   │       ├── ipmi/                  # IPMI (UDP)
│   │       ├── netbios/              # NetBIOS
│   │       ├── linuxrpc/             # Linux RPC
│   │       ├── echo/                  # Echo protocol
│   │       └── msrpc/                # Microsoft RPC
│   ├── runner/                        # CLI layer (Cobra)
│   │   ├── root.go                    # Cobra commands, flags, Execute()
│   │   ├── target.go                  # ParseTarget(), readTargets()
│   │   ├── report.go                  # Output formatting (JSON/default)
│   │   ├── types.go                   # cliConfig struct
│   │   └── utils.go                   # Config validation, createScanConfig()
│   ├── scan/                          # Scan orchestration
│   │   ├── api.go                     # Scan() — main library entry point
│   │   ├── runner.go                  # RunTargetScan(), runPlugin(), fallback()
│   │   ├── plugin_matrix.go           # PluginMatrix — plugin sorting/selection by priority
│   │   ├── plugin_list.go             # Side-effect imports that trigger plugin init()
│   │   └── types.go                   # scan.Config struct
│   └── test/
│       └── testutil.go                # Docker-based integration test framework
├── examples/scan.go                   # Library usage example
├── third_party/cryptolib/ssh/         # Forked Go crypto/ssh (unexported internals for SSH plugin)
├── Dockerfile                         # Two-stage Alpine build
├── go.mod / go.sum
└── README.md
```

## Code Architecture

### Execution Flow

```
CLI: main() → runner.Execute() → readTargets() → scan.Scan() → Report()
Lib: scan.Scan(targets, config)

scan.Scan() iterates targets sequentially:
  → config.RunTargetScan(target)
    → NewPluginMatrix() (sorts plugins by priority)
    → FastMode: GetPluginByTarget(port) → single plugin
    → BruteForce: iterate all plugins by priority, stop on first match
      → plugins.Connect(target) — TLS first, then raw
      → plugin.Run(conn, timeout, target)
      → match found → return Service
    → FallBack: return "unknown" service with TLS info
```

### Plugin Interface (`pkg/plugins/types.go`)

```go
type Plugin interface {
    Run(*FingerprintConn, time.Duration, Target) (*Service, error)
    Name() string        // e.g. "ssh", "http", "redis"
    Type() Protocol      // TCP or UDP
    Priority() int       // Lower = tried first (HTTP=0, SSH=2, Redis=413)
    Ports() []uint16     // Default ports (used in FastMode)
}
```

### Key Types

- **`Target`** — `{Address: netip.AddrPort, Host: string, Transport: Protocol}`
- **`Service`** — Result: `{Host, IP, Port, Protocol, Transport, SSL, Metadata}`
- **`FingerprintConn`** — Wraps `net.Conn`, adds `TLS()` and `Upgrade()` methods
- **`scan.Config`** — `{FastMode, FallBack, DefaultTimeout, Verbose}`
- **`PluginMatrix`** — Holds TCP/UDP plugin lists sorted by priority

### Plugin Registration

Plugins self-register via `init()` → `plugins.RegisterPlugin(&Plugin{})`.
All plugins are imported via side-effect imports in `pkg/scan/plugin_list.go`.
**When adding a new plugin, you must add its import to `plugin_list.go`.**

### Connection Strategy (`pkg/plugins/connection.go`)

1. Try TLS connection first (with all cipher suites, InsecureSkipVerify=true, min SSLv3)
2. If TLS fails, try raw TCP/UDP
3. Hardcoded 2-second dial timeout
4. `FingerprintConn.TLS()` returns `*tls.ConnectionState` if connection is TLS
5. `FingerprintConn.Upgrade()` upgrades raw TCP to TLS (for STARTTLS protocols)

### Scan Modes

- **Default (BruteForce):** Tries all plugins for the target's transport, sorted by priority. Stops on first match. Creates a new connection per plugin attempt.
- **FastMode (`-f`):** Looks up which plugin owns that port via `Ports()`, runs only that plugin.
- **FallBack (`-b`):** If no plugin matches, returns `protocol="unknown"` with any TLS info.

### SSL/TLS Fingerprinting

Uses `github.com/ChriZzn/sslx` to extract certificate details, cipher suites, and TLS version info from connections. Automatically included when the connection is TLS.

## Build & Run

```bash
# Build
go build ./cmd/fingerprintx

# Run
./fingerprintx -t example.com:443
echo "example.com:443" | ./fingerprintx
./fingerprintx -l targets.txt --json

# Run tests (requires Docker)
go test ./...

# Run a specific plugin's test
go test ./pkg/plugins/services/redis/...

# Docker
docker build -t fingerprintx .
docker run --rm fingerprintx -t example.com:443

# Install from source
go install ./cmd/fingerprintx
```

**Go version:** 1.24.4+ (toolchain 1.24.5)

**Test requirements:** Docker must be running (tests spin up real service containers).

## CLI Interface

```
fingerprintx [flags]

Flags:
  -t, --targets string[]   Target(s): HOST:PORT or IP:PORT (comma-separated)
  -l, --list string        Input file with targets (one per line)
  -o, --output string      Output file path
      --json               JSON output format
      --csv                CSV output format
  -f, --fast               Fast mode (only check default plugin for port)
  -b, --fallback           Return "unknown" if no service matched
  -v, --verbose            Verbose logging to stderr
  -w, --timeout int        Timeout in milliseconds (default 2000)

Subcommands:
  plugins                  List all available plugins with priority/ports

Target format: HOST:PORT or HOST:PORT/TCP or HOST:PORT/UDP
Default transport: TCP
```

**Input methods:** stdin pipe, `-l` file, `-t` flag (can combine file + flag).

**Output formats:**
- Default: `protocol://host:port (ip)` or `protocol://ip:port`
- JSON (`--json`): One JSON object per line:
  ```json
  {"ip":"1.2.3.4","port":443,"protocol":"http","transport":"tcp","metadata":{...},"ssl":{...}}
  ```

### Library Usage

```go
import (
    "github.com/chrizzn/fingerprintx/pkg/plugins"
    "github.com/chrizzn/fingerprintx/pkg/scan"
)

config := scan.Config{DefaultTimeout: 2 * time.Second, FastMode: false}
ip, _ := netip.ParseAddr("1.2.3.4")
targets := []plugins.Target{{
    Address:   netip.AddrPortFrom(ip, 443),
    Transport: plugins.TCP,
}}
results, err := scan.Scan(targets, config)
```

## Development Conventions

### Adding a New Plugin

1. Create directory: `pkg/plugins/services/<name>/`
2. Create `type.go` with the service metadata struct:
   ```go
   package myservice
   type ServiceMyService struct {
       SomeField string `json:"someField,omitempty"`
   }
   ```
3. Create `<name>.go` with the plugin implementation:
   ```go
   package myservice
   import (
       "github.com/chrizzn/fingerprintx/pkg/plugins"
       "github.com/chrizzn/fingerprintx/pkg/plugins/shared"
       "time"
   )
   type Plugin struct{}
   const MYSERVICE = "myservice"

   func init() {
       plugins.RegisterPlugin(&Plugin{})
   }

   func (p *Plugin) Run(conn *plugins.FingerprintConn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
       // 1. Send probe: shared.Send(conn, data, timeout)
       // 2. Receive response: shared.Recv(conn, timeout) or shared.SendRecv(conn, data, timeout)
       // 3. Validate response (return nil, nil if not this service)
       // 4. Parse metadata
       // 5. Return: plugins.CreateServiceFrom(target, p.Name(), metadata, conn.TLS())
   }

   func (p *Plugin) Name() string     { return MYSERVICE }
   func (p *Plugin) Type() Protocol   { return plugins.TCP }  // or plugins.UDP
   func (p *Plugin) Priority() int    { return 500 }          // higher = tried later
   func (p *Plugin) Ports() []uint16  { return []uint16{1234} }
   ```
4. **Add import to `pkg/scan/plugin_list.go`:**
   ```go
   _ "github.com/chrizzn/fingerprintx/pkg/plugins/services/myservice"
   ```
5. Create `<name>_test.go` with Docker-based integration test:
   ```go
   func TestMyService(t *testing.T) {
       testcases := []test.Testcase{{
           Description: "myservice",
           Port:        1234,
           Protocol:    plugins.TCP,
           Expected:    func(res *plugins.Service) bool { return res != nil },
           RunConfig:   dockertest.RunOptions{Repository: "some/image"},
       }}
       for _, tc := range testcases {
           t.Run(tc.Description, func(t *testing.T) {
               t.Parallel()
               test.RunTest(t, tc, &Plugin{})
           })
       }
   }
   ```

### Plugin Conventions

- Plugin `Name()` returns a lowercase string matching the protocol name
- `Run()` returns `(nil, nil)` when the service doesn't match (not an error)
- `Run()` returns `(nil, error)` for actual errors (connection failures, etc.)
- Empty response from `Recv()` means the service didn't respond → return `nil, nil`
- Use `shared.Send/Recv/SendRecv` for all network I/O (handles timeouts + deadlines)
- Use `shared.RecvAll/SendRecvAll` for multi-line protocols (FTP-style responses)
- Use `plugins.CreateServiceFrom()` to build the result (handles SSL + JSON metadata)
- Each plugin package has a `type.go` for its metadata struct (JSON-tagged)

### Error Handling

- Custom error types in `pkg/plugins/shared/error.go` for network operations
- Timeout errors and connection refused are silently treated as "not this service" in `shared.Recv()`
- Plugin errors in brute force mode are logged only when verbose; scanning continues
- `shared.InvalidResponseError{Service: "name"}` for protocol mismatch
- `shared.InvalidResponseErrorInfo{Service: "name", Info: "details"}` with extra info

### Code Style

- Standard Go conventions (gofmt)
- Package-level constants for service names: `const SSH = "ssh"`
- Protocol probes defined as byte slices or hex literals
- No global logger — uses `log.Printf` with verbose gating
- JSON struct tags use `omitempty` on optional fields

### Protocols Supporting Both TCP and UDP

Some services (DNS, etc.) register two separate plugins (one TCP, one UDP) from the same `init()`. See `pkg/plugins/services/dns/` for the pattern — shared logic in `root.go`, transport-specific wrappers in `tcp.go` and `udp.go`.

## Common Patterns & Idioms

### Network I/O Pattern

Every plugin follows: send probe → receive response → validate → return.
```go
response, err := shared.SendRecv(conn, probe, timeout)
if err != nil { return nil, err }
if len(response) == 0 { return nil, nil }  // no response = not this service
// validate + parse response
```

### HTTP Plugin Special Handling

The HTTP plugin creates a full `http.Client` that reuses the existing `FingerprintConn`:
```go
client := HTTPClient(conn, timeout)  // wraps conn in http.Transport
resp, err := client.Get(baseURL + "/")
```
This avoids opening a new connection. Also does wappalyzer fingerprinting and favicon hash (murmur3).

### Favicon Hashing

`CalcMMH3Hash()` in `http/favicon.go` — base64-encodes favicon bytes, inserts newlines every 76 chars, then computes murmur3 hash. Compatible with Shodan's favicon hash format.

### TLS Detection

`conn.TLS()` returns `*tls.ConnectionState` if the connection is TLS, `nil` otherwise. Plugins don't need to handle TLS themselves — the connection layer does it.

### STARTTLS Support

For protocols with STARTTLS (SMTP, POP3, IMAP, LDAP), use `conn.Upgrade()` to upgrade a raw connection to TLS mid-protocol.

## Key Files Quick Reference

| File | Purpose |
|------|---------|
| `cmd/fingerprintx/fingerprintx.go` | CLI entry point |
| `pkg/plugins/types.go` | Plugin interface, Service, Target, FingerprintConn, CreateServiceFrom |
| `pkg/plugins/plugins.go` | Plugin registry (RegisterPlugin, global Plugins map) |
| `pkg/plugins/connection.go` | Connect() — TLS-first connection strategy |
| `pkg/scan/api.go` | `Scan()` — main library entry point |
| `pkg/scan/runner.go` | `RunTargetScan()` — plugin execution logic |
| `pkg/scan/plugin_matrix.go` | Plugin sorting by priority, port-based lookup |
| `pkg/scan/plugin_list.go` | Side-effect imports (add new plugins here) |
| `pkg/scan/types.go` | `scan.Config` struct |
| `pkg/runner/root.go` | Cobra CLI setup, flags, `Execute()` |
| `pkg/runner/target.go` | Target parsing (HOST:PORT/TRANSPORT) with DNS resolution |
| `pkg/runner/report.go` | Output formatting (JSON/default) |
| `pkg/plugins/shared/requests.go` | Send/Recv/SendRecv network helpers |
| `pkg/plugins/shared/error.go` | Custom error types |
| `pkg/test/testutil.go` | Docker-based integration test framework |
| `examples/scan.go` | Library usage example |

## Key Dependencies

| Dependency | Purpose |
|-----------|---------|
| `github.com/spf13/cobra` | CLI framework |
| `github.com/ChriZzn/sslx` | SSL/TLS certificate + cipher suite extraction |
| `github.com/projectdiscovery/wappalyzergo` | HTTP technology fingerprinting |
| `github.com/spaolacci/murmur3` | Favicon hash (Shodan-compatible) |
| `github.com/jedib0t/go-pretty/v6` | Table output for `plugins` subcommand |
| `github.com/ory/dockertest/v3` | Integration testing with Docker containers |
| `github.com/stretchr/testify` | Test assertions |
| `golang.org/x/crypto` | Crypto primitives (SSH plugin) |
| `golang.org/x/net` | HTML parsing (HTTP plugin title extraction, favicon) |

## Gotchas

- **No concurrency** — targets are scanned sequentially. This is intentional.
- **BruteForce mode opens a new connection per plugin** — each plugin attempt gets a fresh `Connect()` call.
- **TLS is tried first** on every connection, even for known plaintext ports. This is by design (detects unexpected TLS).
- **`plugin_list.go` must be updated** when adding a new plugin, or it won't be registered.
- **Plugin `Run()` returning `(nil, nil)` is normal** — means "this isn't my protocol."
- **Recv timeout = no service**, not an error. `shared.Recv()` returns `([]byte{}, nil)` on timeout.
- **SSH plugin uses a forked `crypto/ssh`** from `third_party/` to access unexported internals for key exchange analysis.
- **`Report()` in `report.go` has a potential nil deref** — `writeFile` can be nil when writing to stdout, and `defer writeFile.Close()` runs unconditionally.
- **HTTP User-Agent** is set to a Chrome user agent string via a custom `RoundTripper` wrapper.
- **Connection dial timeout** is hardcoded at 2 seconds in `connection.go`, separate from the per-probe timeout flag.
