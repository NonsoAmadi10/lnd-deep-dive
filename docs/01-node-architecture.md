# Chapter 1: Node Architecture & Startup

```
 ┌──────────────────────────────────────────────────────────────┐
 │  Chapter 1: Node Architecture & Startup                      │
 │  "From main() to a fully operational Lightning node"         │
 └──────────────────────────────────────────────────────────────┘
```

*Previous: [00 — README](./00-README.md) | Next: [02 — Brontide Transport](./02-brontide-transport.md)*

---

## Overview

Every LND node begins its life with a single function call. In this chapter,
we trace the full boot sequence from the `main()` function in `cmd/lnd/main.go`
all the way through to a fully operational Lightning node ready to accept
connections and route payments.

By the end of this chapter, you will understand:

- How LND starts up and what happens at each stage
- The `server` struct — the central nervous system of LND
- What each subsystem does and how they connect
- The complete boot sequence with all its dependencies

> 🔰 **For Beginners: What Is a Daemon?**
>
> A **daemon** is a background process that runs continuously on a computer,
> waiting for requests. The "D" in "LND" stands for "Daemon." When you start
> LND, it doesn't show a graphical window — it runs in the background, listens
> for connections from other Lightning nodes, and exposes an API for your
> applications to use.
>
> Think of it like a web server (Apache, Nginx) — it starts up, loads its
> configuration, and then sits there handling requests until you tell it to stop.

---

## 1.1 The Entry Point

### File: `cmd/lnd/main.go`

Everything begins here. The `main()` function (line 12) is remarkably simple:

```go
// cmd/lnd/main.go:12
func main() {
    // Hook interceptor for os signals.
    shutdownInterceptor, err := signal.Intercept()
    if err != nil {
        _, _ = fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }

    // Load the configuration, and parse any command line options.
    // ...

    if err = lnd.Main(
        loadedConfig, lnd.ListenerCfg{}, implCfg, shutdownInterceptor,
    ); err != nil {
        _, _ = fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
```

Let's break down what happens:

1. **Signal Interceptor**: LND sets up an OS signal handler *first*. This
   ensures that even during startup, pressing Ctrl+C will trigger a clean
   shutdown. The `signal.Intercept()` function captures SIGINT and SIGTERM.

2. **Configuration Loading**: Command-line flags and config file are parsed
   into the `Config` struct (defined in `config.go`).

3. **`lnd.Main()` Call**: This is where the real work begins. The function is
   defined in `lnd.go:148`.

> 📝 **Key Takeaway**
>
> The binary entry point (`cmd/lnd/main.go`) is intentionally thin. All real
> logic lives in `lnd.go:Main()`, which makes LND embeddable — other Go
> programs can call `lnd.Main()` directly to run an LND node in-process.

---

## 1.2 The Main Function

### File: `lnd.go`

The `Main()` function (line 148) orchestrates the entire boot sequence:

```go
// lnd.go:148
func Main(cfg *Config, lisCfg ListenerCfg, implCfg *ImplementationCfg,
    interceptor signal.Interceptor) error {
    // ... boot sequence ...
}
```

It takes four arguments:

| Argument | Type | Purpose |
|----------|------|---------|
| `cfg` | `*Config` | All configuration options (network, ports, paths, etc.) |
| `lisCfg` | `ListenerCfg` | Custom TCP/TLS listeners (usually empty) |
| `implCfg` | `*ImplementationCfg` | Database and wallet implementations |
| `interceptor` | `signal.Interceptor` | OS signal handler for clean shutdown |

> 🔰 **For Beginners: What Is RPC?**
>
> **RPC (Remote Procedure Call)** is a way for one program to call functions in
> another program, usually over a network. LND uses **gRPC**, a high-performance
> RPC framework by Google, to expose its API.
>
> When you use `lncli` (the command-line tool), it makes gRPC calls to the LND
> daemon. When a mobile wallet app talks to your node, it also uses gRPC. The
> API is defined in `.proto` files in the `lnrpc/` directory.

---

## 1.3 The Boot Sequence

The boot sequence follows a strict order. Each step depends on the previous
one completing successfully. Here's the full sequence:

```
┌────────────────────────────────────────────────────────────────────┐
│                    LND Boot Sequence                               │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  1. Load Configuration (config.go)                                 │
│     │                                                              │
│     ▼                                                              │
│  2. TLS Certificate Setup (tls_manager.go)                        │
│     │  • Generate or load TLS cert/key                             │
│     │  • Used for gRPC encryption                                  │
│     ▼                                                              │
│  3. Wallet Unlock / Create                                         │
│     │  • Start unlocker RPC service                                │
│     │  • Wait for user to provide password                         │
│     │  • Decrypt wallet seed (aezeed)                              │
│     ▼                                                              │
│  4. Chain Backend Connection                                       │
│     │  • Connect to bitcoind / btcd / neutrino                     │
│     │  • Sync to chain tip                                         │
│     ▼                                                              │
│  5. Channel Database Init (channeldb/)                            │
│     │  • Open bolt/postgres database                               │
│     │  • Load existing channel state                               │
│     ▼                                                              │
│  6. Server Creation (server.go)                                    │
│     │  • Initialize ALL subsystems                                 │
│     │  • Wire subsystems together                                  │
│     ▼                                                              │
│  7. Server Start                                                   │
│     │  • Start all subsystems in dependency order                  │
│     │  • Begin listening for peer connections                       │
│     ▼                                                              │
│  8. RPC Server Start (rpcserver.go)                               │
│     │  • Register gRPC services                                    │
│     │  • Generate macaroon credentials                             │
│     │  • Start listening for API requests                          │
│     ▼                                                              │
│  9. ✅ Node Ready                                                  │
│     • Accepting peer connections                                   │
│     • Processing API requests                                      │
│     • Routing payments                                             │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### Why This Order Matters

The order is not arbitrary. Each step has dependencies:

- **TLS** must come before the wallet unlocker because the unlocker itself is a
  gRPC service that needs encryption.
- **Wallet unlock** must come before the chain backend because the wallet keys
  are needed to watch for on-chain transactions.
- **Chain backend** must come before the server because the server needs to know
  the current blockchain height.
- **Channel database** must come before the server because existing channels
  need to be loaded into memory.

> ⚠️ **Security Note**
>
> During step 3 (Wallet Unlock), LND starts a temporary gRPC server that
> *only* exposes the wallet unlocker service. This means the full API is NOT
> available until the wallet is unlocked. This is a deliberate security design —
> an attacker who gains network access to your node cannot interact with the
> full API without knowing the wallet password.

---

## 1.4 The Server Struct: LND's Central Hub

### File: `server.go:225`

The `server` struct is the heart of LND. It holds references to every major
subsystem and is responsible for starting, stopping, and connecting them all.

```go
// server.go:225
type server struct {
    // ... (many fields, approximately 200+ lines of struct definition)

    // Core infrastructure
    cc              *chainreg.ChainControl    // line ~321
    fundingMgr      *funding.Manager          // line ~323
    graphDB         *graphdb.ChannelGraph     // line ~325
    chanStateDB     *channeldb.ChannelStateDB // line ~328

    // Peer and channel management
    aliasMgr        *aliasmgr.Manager         // line ~342
    htlcSwitch      *htlcswitch.Switch        // line ~344

    // On-chain monitoring
    breachArbitrator *contractcourt.BreachArbitrator // line ~360

    // Routing
    chanRouter      *routing.ChannelRouter    // line ~367

    // Gossip
    authGossiper    *discovery.AuthenticatedGossiper // line ~371

    // Contract resolution
    chainArb        *contractcourt.ChainArbitrator   // line ~379

    // ... and many more
}
```

### How the Subsystems Connect

Here is a detailed view of the data flow between subsystems:

```
                    ┌─────────────────────┐
                    │    Peer Manager     │
                    │   (peer messages)   │
                    └──────────┬──────────┘
                               │
              Incoming LN messages (BOLT-1/2)
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
   ┌─────────────┐   ┌──────────────┐   ┌──────────────┐
   │  Funding     │   │  HTLC Switch │   │  Gossiper    │
   │  Manager     │   │              │   │              │
   │  (open/close │   │  (forward    │   │  (announce   │
   │   channels)  │   │   payments)  │   │   channels)  │
   └──────┬──────┘   └──────┬───────┘   └──────┬───────┘
          │                  │                  │
          ▼                  ▼                  ▼
   ┌──────────────────────────────────────────────────┐
   │                  Channel Database                 │
   │                  (channeldb/)                     │
   │         Persistent storage for all state          │
   └──────────────────────────────────────────────────┘
          │                  │                  │
          ▼                  ▼                  ▼
   ┌─────────────┐   ┌──────────────┐   ┌──────────────┐
   │  Wallet      │   │  Contract    │   │  Channel     │
   │  (sign txs,  │   │  Court       │   │  Router      │
   │   manage     │   │  (on-chain   │   │  (find       │
   │   UTXOs)     │   │   disputes)  │   │   paths)     │
   └─────────────┘   └──────────────┘   └──────────────┘
```

---

## 1.5 Subsystem Overview

Let's briefly describe each major subsystem. Each will get its own detailed
chapter later in this guide.

### Funding Manager (`funding/manager.go`)

Handles the channel opening and closing flow. When you run `lncli openchannel`,
the funding manager coordinates the multi-step process:

1. Exchange `open_channel` / `accept_channel` messages
2. Create the funding transaction (2-of-2 multisig)
3. Exchange signatures
4. Broadcast the funding transaction
5. Wait for confirmations
6. Exchange `channel_ready` messages

*See: [Chapter 4: Channel Lifecycle](./04-channel-lifecycle.md)*

### HTLC Switch (`htlcswitch/switch.go`)

The payment forwarding engine. When a payment arrives at your node destined
for another node, the HTLC Switch:

1. Receives the incoming HTLC from the source channel
2. Decrypts the onion routing layer to find the next hop
3. Forwards the HTLC to the destination channel
4. Handles settlement (success) or failure (timeout)

Think of it as a telephone exchange — routing calls (payments) between lines
(channels).

*See: [Chapter 6: HTLC Forwarding & Switch](./06-htlc-forwarding.md)*

### Channel Router (`routing/router.go`)

The pathfinding engine. When you want to send a payment, the router:

1. Queries the channel graph for possible paths
2. Evaluates paths based on fees, capacity, and reliability
3. Constructs the onion-encrypted route
4. Manages payment retries and multipath payments (MPP)

*See: [Chapter 8: Payment Lifecycle](./08-payment-lifecycle.md)*

### Breach Arbitrator (`contractcourt/breach_arbitrator.go`)

The security guard. Watches for cheating — if a channel counterparty
broadcasts an old (revoked) commitment transaction, the breach arbitrator:

1. Detects the revoked transaction on-chain
2. Constructs a "justice transaction" that sweeps ALL funds
3. Broadcasts the justice transaction as quickly as possible

This is the enforcement mechanism that makes Lightning channels secure.

*See: [Chapter 11: Contract Court](./11-contract-court.md)*

### Authenticated Gossiper (`discovery/gossiper.go`)

Manages the peer-to-peer gossip protocol (BOLT-7). Nodes share information
about:

- **Channel announcements**: "A channel exists between node A and node B"
- **Node announcements**: "Here is node A's address and features"
- **Channel updates**: "Here are node A's current fee rates for this channel"

The gossiper validates all announcements cryptographically before propagating
them.

*See: [Chapter 9: Gossip Protocol](./09-gossip-protocol.md)*

### Invoice Registry (`invoices/invoiceregistry.go`)

Manages Lightning invoices — the payment requests that encode amount, payment
hash, and destination. The registry handles:

- Creating new invoices
- Looking up invoices by payment hash
- Settling invoices when payment arrives
- Canceling expired invoices

*See: [Chapter 8: Payment Lifecycle](./08-payment-lifecycle.md)*

### Watchtower Client (`watchtower/wtclient/`)

An optional subsystem that delegates channel monitoring to an external
watchtower server. If your node goes offline, the watchtower can detect and
punish cheating on your behalf.

*See: [Chapter 10: Watchtowers](./10-watchtowers.md)*

---

## 1.6 Configuration Deep Dive

### File: `config.go`

The `Config` struct in `config.go` defines every configurable option. Here are
the most important ones for security:

```go
// Selected security-relevant configuration options:

// TLS configuration
TLSCertPath    string  // Path to TLS certificate
TLSKeyPath     string  // Path to TLS private key
TLSExtraIPs    []string // Additional IPs for the TLS cert

// Macaroon configuration
AdminMacPath   string  // Path to admin macaroon
ReadMacPath    string  // Path to read-only macaroon
InvoiceMacPath string  // Path to invoice macaroon

// Network
NoListen       bool    // Disable incoming peer connections
ExternalHosts  []string // Advertised addresses for peer connections
```

> 🔰 **For Beginners: What Is TLS?**
>
> **TLS (Transport Layer Security)** is the encryption protocol used to secure
> web traffic (HTTPS). LND uses TLS to encrypt gRPC connections between the
> daemon and its clients (like `lncli` or your application).
>
> TLS is different from Brontide (Chapter 2). Brontide encrypts peer-to-peer
> connections between Lightning nodes. TLS encrypts the API connection between
> YOU and YOUR node.
>
> ```
> ┌──────────┐   TLS (gRPC)    ┌──────────┐   Brontide    ┌──────────┐
> │  lncli   │◄──────────────►│  Your    │◄─────────────►│  Remote  │
> │  (you)   │                │  LND     │               │  LND     │
> └──────────┘                └──────────┘               └──────────┘
>   Client                      Server                    Peer
> ```

### Macaroon File Permissions

LND creates macaroon files with specific permissions:

```go
// lnd.go:60
const (
    adminMacaroonFilePermissions = 0640
)
```

The `0640` permission means:
- **Owner (6)**: Read + Write
- **Group (4)**: Read only
- **Others (0)**: No access

> ⚠️ **Security Note**
>
> The admin macaroon grants full access to your node, including the ability
> to send all funds. Protect it like a private key. The `0640` permission is
> a reasonable default, but on shared systems, consider `0600` (owner-only)
> instead. Also, consider which user and group own the macaroon file.

---

## 1.7 Server Start Sequence

When the server is created, subsystems are started in a specific dependency
order. Here is the simplified sequence from `server.go`'s `Start()` method:

```go
// Simplified start sequence from server.go
func (s *server) Start() error {
    // 1. Start chain-related services first
    s.cc.Start()

    // 2. Start the channel database
    // (already opened during server creation)

    // 3. Start the HTLC Switch
    s.htlcSwitch.Start()

    // 4. Start the funding manager
    s.fundingMgr.Start()

    // 5. Start the breach arbitrator
    s.breachArbitrator.Start()

    // 6. Start the chain arbitrator
    s.chainArb.Start()

    // 7. Start the gossiper
    s.authGossiper.Start()

    // 8. Start the channel router
    s.chanRouter.Start()

    // 9. Start listening for peer connections
    s.startListeners()

    // 10. Connect to persistent peers
    s.connectToPersistentPeers()

    return nil
}
```

> 📝 **Key Takeaway**
>
> The server start sequence is carefully ordered: chain services → switching →
> funding → breach detection → routing → listening. Each subsystem can depend
> on the ones started before it.

---

## 1.8 Shutdown Sequence

Clean shutdown is equally important. LND shuts down subsystems in reverse
order to prevent data corruption:

```
┌─────────────────────────────────────────┐
│           Shutdown Sequence              │
├─────────────────────────────────────────┤
│                                         │
│  1. Stop accepting new connections      │
│  2. Disconnect all peers                │
│  3. Stop the gossiper                   │
│  4. Stop the channel router             │
│  5. Stop the HTLC switch               │
│  6. Stop the funding manager            │
│  7. Stop the chain arbitrator           │
│  8. Stop the breach arbitrator          │
│  9. Close the channel database          │
│ 10. Stop chain backend connection       │
│                                         │
│  ✅ Clean exit                          │
│                                         │
└─────────────────────────────────────────┘
```

The signal interceptor (set up in `cmd/lnd/main.go`) triggers this sequence
when the process receives SIGINT (Ctrl+C) or SIGTERM.

---

## 1.9 The Chain Backend Abstraction

LND supports multiple Bitcoin chain backends through an abstraction layer:

```
                    ┌──────────────────┐
                    │   LND Server     │
                    └────────┬─────────┘
                             │
                    ┌────────┴─────────┐
                    │  ChainControl    │
                    │  (chainreg/)     │
                    └────────┬─────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │   bitcoind   │ │    btcd      │ │  neutrino    │
    │  (full node) │ │ (full node)  │ │ (SPV light)  │
    └──────────────┘ └──────────────┘ └──────────────┘
```

| Backend | Description | Use Case |
|---------|-------------|----------|
| `bitcoind` | Bitcoin Core full node | Production — most common |
| `btcd` | Go-based full node | Development and testing |
| `neutrino` | BIP-157/158 light client | Mobile and resource-constrained |

The `ChainControl` struct in `chainreg/` provides a unified interface
regardless of which backend is used. This means the rest of LND doesn't need
to know or care which Bitcoin implementation is running underneath.

> 🔰 **For Beginners: Full Node vs SPV**
>
> A **full node** downloads and validates every Bitcoin block and transaction.
> It's the most secure option but requires ~500GB of disk space.
>
> **SPV (Simplified Payment Verification)** is a lightweight mode that only
> downloads block headers and transactions relevant to your wallet. It uses
> less storage but trusts full nodes to provide accurate data.
>
> Neutrino is LND's built-in SPV implementation. It's great for mobile wallets
> and development but not recommended for high-value production nodes.

---

## 1.10 Configuration Loading Details

The configuration loading process (`config.go`) follows a specific precedence:

```
Priority (highest to lowest):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Command-line flags         (--bitcoin.active --bitcoin.testnet)
2. Environment variables      (LND_BITCOIN_ACTIVE=1)
3. Config file                (~/.lnd/lnd.conf)
4. Defaults                   (hardcoded in config.go)
```

Key default values:

```go
// Selected defaults from config.go
DefaultLndDir          = "~/.lnd"
DefaultConfigFilename  = "lnd.conf"
DefaultTLSCertFilename = "tls.cert"
DefaultTLSKeyFilename  = "tls.key"
DefaultAdminMacFilename = "admin.macaroon"
DefaultRPCPort         = 10009
DefaultPeerPort        = 9735      // BOLT-1 standard port
```

> 📝 **Key Takeaway**
>
> The default peer port `9735` is the BOLT-1 standard. All Lightning
> implementations (LND, CLN, Eclair) use this port by default, making it easy
> for nodes to discover and connect to each other.

---

## 1.11 Error Handling and Logging

LND uses the `btclog` package for structured logging. Each subsystem has its
own logger with a subsystem prefix:

```go
// log.go — logger setup
var (
    srvrLog = build.NewSubLogger("SRVR", nil) // Server
    rpcsLog = build.NewSubLogger("RPCS", nil) // RPC Server
    fndgLog = build.NewSubLogger("FNDG", nil) // Funding
    hswcLog = build.NewSubLogger("HSWC", nil) // HTLC Switch
    // ... many more
)
```

When reading LND logs, look for the 4-character prefix to identify which
subsystem generated the message:

```
2024-01-15 10:00:01.234 [INF] SRVR: Starting server...
2024-01-15 10:00:01.456 [INF] FNDG: Funding manager starting
2024-01-15 10:00:01.789 [INF] HSWC: HTLC Switch starting
2024-01-15 10:00:02.001 [INF] DISC: Gossiper starting
```

---

## 1.12 Concurrency Model

LND makes heavy use of Go's concurrency primitives. Understanding the pattern
is essential for reading the codebase:

### The Standard Subsystem Pattern

Almost every subsystem in LND follows the same lifecycle pattern:

```go
// The standard LND subsystem pattern
type Subsystem struct {
    started  int32           // atomic flag
    stopped  int32           // atomic flag
    quit     chan struct{}    // shutdown signal
    wg       sync.WaitGroup  // tracks goroutines
}

func (s *Subsystem) Start() error {
    // Ensure we only start once
    if !atomic.CompareAndSwapInt32(&s.started, 0, 1) {
        return nil
    }

    s.wg.Add(1)
    go s.mainLoop()

    return nil
}

func (s *Subsystem) Stop() error {
    if !atomic.CompareAndSwapInt32(&s.stopped, 0, 1) {
        return nil
    }

    close(s.quit)  // Signal all goroutines to stop
    s.wg.Wait()    // Wait for all goroutines to finish

    return nil
}

func (s *Subsystem) mainLoop() {
    defer s.wg.Done()

    for {
        select {
        case msg := <-s.incomingMessages:
            s.handleMessage(msg)
        case <-s.quit:
            return
        }
    }
}
```

> 📝 **Key Takeaway**
>
> The `started`/`stopped` atomic flags, `quit` channel, and `WaitGroup`
> pattern appears in nearly every LND subsystem. Once you recognize this
> pattern, reading new subsystems becomes much faster.

---

## 1.13 The AccessManager

LND includes an `AccessManager` (defined in `accessman.go`) that controls
peer connection limits and rate limiting:

```go
// accessman.go — manages peer access control
type AccessManager struct {
    // Tracks connection counts per peer
    // Enforces maximum connection limits
    // Rate-limits new connections
}
```

The access manager prevents denial-of-service attacks by limiting:

- Maximum number of concurrent peer connections
- Connection rate from a single IP address
- Pending (not-yet-authenticated) connections

> ⚠️ **Security Note**
>
> The access manager is a critical defense-in-depth mechanism. If you're
> running a public routing node, pay attention to the connection limits in
> your configuration. Too many connections can exhaust file descriptors and
> memory, making your node unresponsive.

---

## Summary

In this chapter, we traced the LND boot sequence from `main()` to a fully
operational node:

```
cmd/lnd/main.go:12  →  lnd.go:148 (Main)  →  server.go:225 (server struct)
       │                     │                       │
   Entry point         Orchestration          Central hub for
                                              all subsystems
```

Key takeaways:

1. The `server` struct in `server.go:225` is the central hub connecting all
   subsystems — understanding it is key to navigating the codebase.

2. The boot sequence follows a strict dependency order: config → TLS → wallet
   → chain → database → server → RPC.

3. Every subsystem follows the same start/stop pattern with atomic flags,
   quit channels, and WaitGroups.

4. LND supports multiple chain backends (bitcoind, btcd, neutrino) through
   the `ChainControl` abstraction.

---

> 💡 **Exercises**
>
> **⭐ Easy:**
> 1. Open `cmd/lnd/main.go` and trace the call to `lnd.Main()`. What happens
>    if `Main()` returns an error?
> 2. Open `server.go` and find the `server` struct. List five subsystem fields
>    and look up the package each one comes from.
>
> **⭐⭐ Medium:**
> 3. Find the `Start()` method on the `server` struct. In what order are
>    subsystems started? Why might this order matter?
> 4. Search for `atomic.CompareAndSwapInt32` across the codebase. How many
>    subsystems use the standard start/stop pattern described above?
>
> **⭐⭐⭐ Challenging:**
> 5. Trace the full path from `lnd.Main()` to the server being ready to accept
>    peer connections. List every function called along the way with file and
>    approximate line numbers.
> 6. Modify the boot sequence to add a custom log message "MY CUSTOM NODE IS
>    STARTING" right after the wallet is unlocked but before the chain backend
>    connects. Build and test on simnet.

---

*Previous: [00 — README](./00-README.md) | Next: [02 — Brontide Transport](./02-brontide-transport.md)*
