# Chapter 10: Tor Integration & IP Privacy

> _"On the Lightning Network, your IP address is your fingerprint. Tor is the glove."_

---

## Table of Contents

1. [Why Tor?](#why-tor)
2. [Tor Architecture with LND](#tor-architecture-with-lnd)
3. [Two Connections to the Tor Daemon](#two-connections-to-the-tor-daemon)
4. [The Controller](#the-controller)
5. [Authentication Hierarchy](#authentication-hierarchy)
6. [SAFECOOKIE Challenge-Response](#safecookie-challenge-response)
7. [Onion Service Creation](#onion-service-creation)
8. [V2 vs. V3 Onion Services](#v2-vs-v3-onion-services)
9. [Network Abstraction: ClearNet vs. ProxyNet](#network-abstraction-clearnet-vs-proxynet)
10. [Stream Isolation](#stream-isolation)
11. [Watchtower Onion Services](#watchtower-onion-services)
12. [SkipProxy Escape Hatch](#skipproxy-escape-hatch)
13. [Configuration Reference](#configuration-reference)
14. [Security Deep Dive](#security-deep-dive)
15. [Exercises](#exercises)

---

## Why Tor?

🔰 **For Beginners**

Every device on the internet has an **IP address** — a unique number that identifies
where it is on the network. When your Lightning node connects to a peer, that peer
learns your IP address. Your ISP also sees every connection your node makes.

Why is this a problem?

- **Your IP reveals your location**: IP addresses are geolocated. Your peer (or ISP)
  knows what city — sometimes what building — you're in.
- **Your IP links to your identity**: Your ISP knows your name and billing address.
  If someone connects your Lightning node to your IP, they connect it to you.
- **Your IP enables targeted attacks**: DDoS attacks, physical theft, or legal
  pressure can be directed at your physical location.

**Tor** (The Onion Router) solves this by routing your traffic through **three
relays**, each of which only knows the previous and next hop — never the full path.

```
┌──────────────────────────────────────────────────────────────────┐
│                     WHY TOR MATTERS                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WITHOUT TOR:                                                    │
│                                                                  │
│    Your Node (IP: 203.0.113.42)                                  │
│         │                                                        │
│         │  Direct TCP connection                                 │
│         │  (peer sees your real IP)                               │
│         ▼                                                        │
│    Peer Node ── "I know you're at 203.0.113.42!"                │
│                                                                  │
│  ─────────────────────────────────────────────────────           │
│                                                                  │
│  WITH TOR:                                                       │
│                                                                  │
│    Your Node (IP hidden)                                         │
│         │                                                        │
│         │  Encrypted                                             │
│         ▼                                                        │
│    Guard Relay ──► Middle Relay ──► Exit Relay                   │
│                                        │                         │
│                                        ▼                         │
│    Peer Node ── "Connection came from Tor. No real IP!"          │
│                                                                  │
│  OR with hidden services:                                        │
│                                                                  │
│    Your Node                     Peer Node                       │
│         │                             │                          │
│    .onion address ◄── Rendezvous ──► .onion address              │
│    (neither side reveals their real IP!)                          │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

📝 **Key Takeaway**
> Tor doesn't just hide your IP from peers — it hides your network activity from
> your ISP, prevents traffic analysis, and enables **hidden services** where neither
> side reveals their real IP address.

---

## Tor Architecture with LND

LND integrates with Tor through two separate connections to the Tor daemon:

```
┌──────────────────────────────────────────────────────────────────┐
│                LND + TOR ARCHITECTURE                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────────────┐        ┌─────────────────────┐      │
│  │                        │        │                     │      │
│  │         LND            │        │    Tor Daemon       │      │
│  │                        │        │    (tor process)     │      │
│  │  ┌──────────────────┐  │        │                     │      │
│  │  │  SOCKS5 Proxy    │──┼───────►│  Port 9050          │      │
│  │  │  Client          │  │        │  (SOCKS5 proxy)     │      │
│  │  │                  │  │        │                     │      │
│  │  │  Routes all      │  │        │  Routes traffic     │      │
│  │  │  outbound peer   │  │        │  through Tor        │      │
│  │  │  connections     │  │        │  network             │      │
│  │  └──────────────────┘  │        │                     │      │
│  │                        │        │                     │      │
│  │  ┌──────────────────┐  │        │                     │      │
│  │  │  Control Port    │──┼───────►│  Port 9051          │      │
│  │  │  Client          │  │        │  (control protocol) │      │
│  │  │                  │  │        │                     │      │
│  │  │  Creates hidden  │  │        │  Manages onion      │      │
│  │  │  services,       │  │        │  services, reports  │      │
│  │  │  manages Tor     │  │        │  status             │      │
│  │  └──────────────────┘  │        │                     │      │
│  │                        │        │                     │      │
│  └────────────────────────┘        └─────────────────────┘      │
│                                                                  │
│  Connection 1 (SOCKS5): Outbound traffic routing                 │
│  Connection 2 (Control): Onion service management                │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Two Connections to the Tor Daemon

### Connection 1: SOCKS5 Proxy (Port 9050)

🔰 **For Beginners**: **SOCKS5** is a protocol that lets one program ask another to
make network connections on its behalf. LND tells the Tor daemon: "Connect to this
address for me and relay the data." The destination never sees LND's real IP.

Used for: connecting to Lightning peers, DNS lookups, blockchain backend connections.

### Connection 2: Control Port (Port 9051)

The control port speaks the **Tor Control Protocol** — a text-based protocol for
managing the Tor daemon. LND uses it to authenticate, create hidden services, and
query status. Authentication is handled through the `Controller` struct.

---

## The Controller

The `Controller` struct (`tor/controller.go:105-138`) manages the control port
connection:

```go
// Controller is responsible for communicating with the Tor daemon
// via the Tor Control Protocol.
type Controller struct {
    // conn is the TCP connection to the Tor control port.
    conn net.Conn

    // password is used for HASHEDPASSWORD authentication.
    password string

    // activeServiceID holds the ID of the currently active
    // onion service.
    activeServiceID string

    // ... (additional fields for lifecycle management)
}
```

The Controller provides methods for:

| Operation            | Description                                     |
|----------------------|-------------------------------------------------|
| `authenticate()`    | Authenticate with Tor daemon (line 441-478)     |
| `AddOnion()`         | Create a new hidden service                     |
| `DelOnion()`         | Remove an existing hidden service               |
| `GetVersion()`       | Query Tor daemon version                        |

---

## Authentication Hierarchy

Before LND can create hidden services, it must authenticate with the Tor daemon.
LND tries three methods in order of preference, defined at
`tor/controller.go:48-56`:

```go
const (
    authSafeCookie     = "SAFECOOKIE"      // line 49
    authHashedPassword = "HASHEDPASSWORD"  // line 51-53
    authNull           = "NULL"            // line 55-56
)
```

```
┌──────────────────────────────────────────────────────────────────┐
│              AUTHENTICATION HIERARCHY                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  LND asks Tor: "What auth methods do you support?"               │
│                                                                  │
│      ┌─────────────────────────────────────┐                     │
│      │  1. HASHEDPASSWORD                  │  Most preferred     │
│      │     (password provided in config)   │                     │
│      └──────────────┬──────────────────────┘                     │
│                     │ Not available?                              │
│                     ▼                                             │
│      ┌─────────────────────────────────────┐                     │
│      │  2. SAFECOOKIE                      │  Recommended        │
│      │     (file-based mutual auth)        │                     │
│      └──────────────┬──────────────────────┘                     │
│                     │ Not available?                              │
│                     ▼                                             │
│      ┌─────────────────────────────────────┐                     │
│      │  3. NULL                            │  ⚠️ No auth!       │
│      │     (no authentication at all)      │                     │
│      └─────────────────────────────────────┘                     │
│                                                                  │
│  ⚠️ If NULL is the only option, LND connects without any        │
│     authentication. Anyone with access to the control port       │
│     can create/delete hidden services!                           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

⚠️ **Security Note**
> The **NULL** authentication fallback means LND will connect to a Tor control port
> that has no authentication. If you're running Tor on a shared machine, another user
> could manipulate your hidden services. Always configure HASHEDPASSWORD or
> SAFECOOKIE authentication in your `torrc`.

---

## SAFECOOKIE Challenge-Response

The SAFECOOKIE method (`tor/controller.go:497-589`) is the most interesting
authentication mechanism. It uses **HMAC-SHA256** for mutual authentication — both
LND and the Tor daemon prove their identity to each other.

🔰 **For Beginners**: A **challenge-response** protocol works like this: "I'll give
you a puzzle. If you can solve it, you must have the secret key." Both sides exchange
puzzles, proving they both have access to a shared cookie file on disk.

### The Flow

```
┌──────────────────────────────────────────────────────────────────┐
│              SAFECOOKIE AUTHENTICATION FLOW                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  LND (Controller)                     Tor Daemon                 │
│       │                                    │                     │
│  1.   │  Read cookie file from disk        │                     │
│       │  (shared secret)                   │                     │
│       │                                    │                     │
│  2.   │──── AUTHCHALLENGE SAFECOOKIE ─────►│                     │
│       │     + client_nonce (32 bytes)      │                     │
│       │                                    │                     │
│  3.   │                                    │  Compute:           │
│       │                                    │  server_hash =      │
│       │                                    │  HMAC-SHA256(       │
│       │                                    │    key=serverKey,   │
│       │                                    │    cookie +         │
│       │                                    │    client_nonce +   │
│       │                                    │    server_nonce)    │
│       │                                    │                     │
│  4.   │◄── AUTHCHALLENGE response ─────────│                     │
│       │    server_hash + server_nonce       │                     │
│       │                                    │                     │
│  5.   │  Verify server_hash               │                     │
│       │  (proves Tor has the cookie)       │                     │
│       │                                    │                     │
│  6.   │  Compute:                          │                     │
│       │  client_hash = HMAC-SHA256(        │                     │
│       │    key=controllerKey,              │                     │
│       │    cookie + client_nonce +         │                     │
│       │    server_nonce)                   │                     │
│       │                                    │                     │
│  7.   │──── AUTHENTICATE client_hash ─────►│                     │
│       │                                    │                     │
│  8.   │                                    │  Verify             │
│       │                                    │  client_hash        │
│       │                                    │                     │
│  9.   │◄──── 250 OK ──────────────────────│                     │
│       │                                    │                     │
│                                                                  │
│  HMAC keys (from tor/controller.go:60-68):                       │
│    serverKey     = "Tor safe cookie authentication server-to-    │
│                     controller hash"                             │
│    controllerKey = "Tor safe cookie authentication controller-   │
│                     to-server hash"                              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

The `computeHMAC256` helper at `tor/controller.go:616-620`:

```go
func computeHMAC256(key, message []byte) []byte {
    mac := hmac.New(sha256.New, key)
    mac.Write(message)
    return mac.Sum(nil)
}
```

📝 **Key Takeaway**
> SAFECOOKIE achieves **mutual authentication**: LND proves it can read the cookie
> file (has local access), and the Tor daemon proves it also has the cookie. This
> prevents an attacker from impersonating either side.

---

## Onion Service Creation

When LND starts with `--tor.active`, it creates a hidden service so that other nodes
can reach it without knowing its IP address.

### The Creation Flow

From `server.go:3382-3384`:

```go
// createNewHiddenService creates a new Tor onion service and
// registers the resulting .onion address as a node address.
func (s *server) createNewHiddenService(ctx context.Context) error {
```

The function builds an `AddOnionConfig` struct (line 3402-3416) and sends the
`ADD_ONION` command to the Tor daemon:

```
┌──────────────────────────────────────────────────────────────────┐
│              ONION SERVICE CREATION                               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. LND builds AddOnionConfig:                                   │
│     ┌──────────────────────────────────────────┐                 │
│     │  Type:        V3 (ED25519)               │                 │
│     │  VirtualPort: 9735 (Lightning P2P)       │                 │
│     │  TargetPorts: [9735]                     │                 │
│     │  Store:       OnionFile{                 │                 │
│     │    privateKeyPath: ~/.lnd/v3_onion_...   │                 │
│     │    encryptKey: true/false                │                 │
│     │  }                                       │                 │
│     └──────────────────────────────────────────┘                 │
│                                                                  │
│  2. Controller sends to Tor daemon:                              │
│     ADD_ONION ED25519-V3:<key> Port=9735,9735                    │
│                                                                  │
│  3. Tor daemon responds:                                         │
│     250-ServiceID=<56-char-onion-address>                        │
│     250 OK                                                       │
│                                                                  │
│  4. LND stores the private key to disk:                          │
│     ~/.lnd/v3_onion_private_key                                  │
│     (optionally encrypted with --tor.encryptkey)                 │
│                                                                  │
│  5. LND adds the .onion address to its NodeAnnouncement:         │
│     addresses: [..., "abc...xyz.onion:9735"]                     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Key Storage

The onion private key is managed by `OnionFile` (`tor/cmd_onion.go`):

```go
// NewOnionFile creates a new OnionFile with the given path
// and optional encryption.
func NewOnionFile(privateKeyPath string, encryptKey bool) *OnionFile
```

The key is stored at the path specified by `--tor.privatekeypath` (default:
`~/.lnd/v3_onion_private_key`). If `--tor.encryptkey` is set, the key is encrypted
before writing to disk.

⚠️ **Security Note**
> By default, the onion private key is stored **unencrypted** on disk. Anyone who
> can read this file can impersonate your node's `.onion` address. Always set
> `--tor.encryptkey=true` in production, or ensure strict file permissions
> (`chmod 600`).

---

## V2 vs. V3 Onion Services

From `tor/cmd_onion.go:24-40`:

```go
const (
    V2 OnionType = iota  // DEPRECATED
    V3                   // Current standard
)
V2KeyParam = "RSA1024"    // line 37
V3KeyParam = "ED25519-V3"  // line 40
```

| Feature         | V2 (Deprecated)     | V3 (Current)           |
|-----------------|---------------------|------------------------|
| Key algorithm   | RSA-1024            | ED25519                |
| Address length  | 16 characters       | 56 characters          |
| Security level  | ❌ Broken (80-bit)  | ✅ Strong (128-bit)   |
| Tor support     | ❌ Removed in 0.4.6 | ✅ Active             |

⚠️ **Security Note**
> **Never use V2 onion services.** RSA-1024 is breakable. Tor removed V2 support
> in version 0.4.6. LND defaults to V3.

---

## Network Abstraction: ClearNet vs. ProxyNet

LND abstracts network operations behind interfaces defined in `tor/net.go`. This
allows the same LND code to work with or without Tor.

### ClearNet (tor/net.go:43-72)

```go
// ClearNet is an implementation of the Net interface that doesn't
// use a proxy for network connections.
type ClearNet struct{}

func (c *ClearNet) Dial(network, address string, timeout time.Duration) (net.Conn, error) {
    // Direct TCP connection — no proxy
    return net.DialTimeout(network, address, timeout)
}

func (c *ClearNet) LookupHost(host string) ([]string, error) {
    return net.LookupHost(host)
}

func (c *ClearNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
    return net.ResolveTCPAddr(network, address)
}
```

### ProxyNet (tor/net.go:75-96)

```go
// ProxyNet is an implementation of the Net interface that routes
// connections through a SOCKS5 proxy (Tor).
type ProxyNet struct {
    // SOCKS is the host:port of the SOCKS5 proxy.
    SOCKS string  // line 80

    // DNS is the host:port for DNS-over-proxy lookups.
    DNS string  // line 84

    // StreamIsolation forces a new Tor circuit per connection.
    StreamIsolation bool  // line 86-89

    // SkipProxyForClearNetTargets bypasses the proxy for
    // clearnet (non-.onion) addresses.
    SkipProxyForClearNetTargets bool  // line 92-95
}
```

```
┌──────────────────────────────────────────────────────────────────┐
│              NETWORK ABSTRACTION                                 │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐    implements     ┌──────────────┐          │
│  │    ClearNet      │ ───────────────► │              │          │
│  │  (direct TCP)    │                  │  Net          │          │
│  └─────────────────┘                  │  Interface    │          │
│                                        │              │          │
│  ┌─────────────────┐    implements     │  - Dial()    │          │
│  │    ProxyNet      │ ───────────────► │  - LookupHost│          │
│  │  (via SOCKS5)    │                  │  - LookupSRV │          │
│  └─────────────────┘                  │  - ResolveTCP │          │
│                                        └──────────────┘          │
│                                                                  │
│  LND picks ClearNet or ProxyNet based on --tor.active flag.      │
│  All peer connections use the same interface — the rest of       │
│  the code doesn't know (or care) whether Tor is enabled.        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

📝 **Key Takeaway**
> The `Net` interface abstraction means LND's peer connection code works identically
> with or without Tor. Only the `Dial()` implementation changes — from direct TCP
> to SOCKS5-proxied connections.

---

## Stream Isolation

🔰 **For Beginners**: When you use Tor, your traffic goes through a **circuit** — a
path through three relays. By default, Tor may reuse the same circuit for multiple
connections, which means an exit relay could correlate those connections as coming
from the same user. **Stream isolation** forces Tor to build a **new circuit** for
each connection, preventing this correlation.

### How LND Implements Stream Isolation

When `StreamIsolation` is enabled in `ProxyNet` (line 86-89), LND generates **random
SOCKS5 credentials** for each new connection:

```
┌──────────────────────────────────────────────────────────────────┐
│              STREAM ISOLATION                                    │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WITHOUT stream isolation:                                       │
│                                                                  │
│    Connection 1 ──┐                                              │
│    Connection 2 ──┼──► Same SOCKS5 creds ──► Same Tor circuit    │
│    Connection 3 ──┘    (default)              (correlatable!)    │
│                                                                  │
│  ─────────────────────────────────────────────────────           │
│                                                                  │
│  WITH stream isolation (--tor.streamisolation):                   │
│                                                                  │
│    Connection 1 ──► Random creds A ──► Circuit A                 │
│    Connection 2 ──► Random creds B ──► Circuit B                 │
│    Connection 3 ──► Random creds C ──► Circuit C                 │
│                                                                  │
│  Each connection gets unique random username:password,            │
│  forcing Tor to build an independent circuit.                    │
│                                                                  │
│  ✅ An exit relay can't tell these connections belong             │
│     to the same node.                                            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

The SOCKS5 protocol supports username/password authentication. Tor uses the
username/password pair as a **circuit isolation key** — connections with different
credentials get different circuits.

📝 **Key Takeaway**
> Stream isolation prevents Tor exit relays from correlating multiple connections
> from your node. Enable it with `--tor.streamisolation` for maximum privacy,
> at the cost of slightly higher latency (new circuit setup per connection).

---

## Watchtower Onion Services

LND's watchtower (a service that monitors channels while you're offline) gets its
**own separate `.onion` address**, independent from the main node's address.

From `watchtower/standalone.go:163-199`:

```go
// createNewHiddenService creates a new Tor hidden service
// for the watchtower.
func (w *Standalone) createNewHiddenService() error {
    // Uses w.cfg.WatchtowerKeyPath for key storage (line 184)
    // Uses w.cfg.Type for V2/V3 selection (line 187)
    // Calls w.cfg.TorController.AddOnion(onionCfg) (line 190)
}
```

The watchtower key path is configured via `--tor.watchtowerkeypath` and is set up
in `lnd.go:534-591`.

```
┌──────────────────────────────────────────────────────────────────┐
│              SEPARATE ONION SERVICES                             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  LND Node                                                        │
│  ├── Main .onion:       abc...xyz.onion:9735  (Lightning P2P)    │
│  │   Key: ~/.lnd/v3_onion_private_key                            │
│  │                                                               │
│  └── Watchtower .onion:  def...uvw.onion:9911 (Watchtower P2P)   │
│      Key: ~/.lnd/v3_watchtower_private_key                       │
│                                                                  │
│  Why separate?                                                   │
│  • Isolates the watchtower identity from the node identity       │
│  • If one .onion is compromised, the other remains safe          │
│  • Watchtower clients don't learn the node's main address        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## SkipProxy Escape Hatch

The `SkipProxyForClearNetTargets` option (`tor/net.go:92-95`) bypasses Tor for
non-`.onion` addresses, improving latency but at a **severe privacy cost**:

```
  Normal Tor (SkipProxy=false):  All connections ──► Tor ──► Peer (IP hidden)
  SkipProxy (SkipProxy=true):    .onion ──► Tor; Clearnet ──► DIRECT (IP EXPOSED!)
```

⚠️ **Security Note**
> **SkipProxy is extremely dangerous.** Clearnet peers see your real IP. An attacker
> could advertise both `.onion` and clearnet addresses to deanonymize you. Only use
> with full understanding of the privacy trade-off.

---

## Configuration Reference

All Tor-related configuration flags, defined in `lncfg/tor.go:6-20`:

| Flag                                 | Type   | Default                           | Description                                |
|--------------------------------------|--------|-----------------------------------|--------------------------------------------|
| `--tor.active`                       | bool   | `false`                           | Enable Tor integration                     |
| `--tor.socks`                        | string | `localhost:9050`                  | SOCKS5 proxy address                       |
| `--tor.dns`                          | string | `soa.nodes.lightning.directory:53`| DNS server for SRV queries via Tor         |
| `--tor.streamisolation`              | bool   | `false`                           | New Tor circuit per connection              |
| `--tor.skip-proxy-for-clearnet-targets` | bool | `false`                          | Bypass Tor for non-.onion peers            |
| `--tor.control`                      | string | `localhost:9051`                  | Tor control port address                   |
| `--tor.v3`                           | bool   | `false`                           | Create a V3 onion service                  |
| `--tor.privatekeypath`               | string | `~/.lnd/v3_onion_private_key`     | Path to onion service private key          |
| `--tor.encryptkey`                   | bool   | `false`                           | Encrypt the private key file on disk       |
| `--tor.watchtowerkeypath`            | string | `~/.lnd/v3_watchtower_private_key`| Path to watchtower onion private key       |

### Minimal Tor Configuration Example

```ini
# In lnd.conf
[tor]
tor.active=true
tor.v3=true
tor.encryptkey=true
tor.streamisolation=true
tor.socks=127.0.0.1:9050
tor.control=127.0.0.1:9051
```

### Tor Daemon Configuration (torrc)

```ini
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
# Or: HashedControlPassword 16:872860B76453A77D...
```

---

## Security Deep Dive

### 1. Onion Key Unencrypted by Default

⚠️ **Security Note**
> The `--tor.encryptkey` flag defaults to `false`. This means your onion service
> private key sits on disk in plaintext. If an attacker gains read access to your
> filesystem (e.g., via a backup, a container escape, or a misconfigured file share),
> they can steal your `.onion` identity.
>
> **Mitigation**: Always set `--tor.encryptkey=true` in production.

### 2. NULL Authentication Fallback

⚠️ **Security Note**
> If the Tor daemon only supports NULL authentication, LND will connect without any
> authentication. This means any local process can control the Tor daemon and
> create/delete hidden services.
>
> **Mitigation**: Always configure `CookieAuthentication 1` or
> `HashedControlPassword` in your `torrc`.

### 3. SkipProxy Leaks IP

⚠️ **Security Note**
> As detailed in the [SkipProxy section](#skipproxy-escape-hatch), this flag causes
> LND to connect directly to clearnet peers, exposing your real IP address. This
> completely defeats the purpose of Tor for those connections.
>
> **Mitigation**: Never enable `skip-proxy-for-clearnet-targets` unless you have
> a specific operational need and fully understand the privacy implications.

### 4. Password Visible in Process List

⚠️ **Security Note**
> Passing `--tor.password=<password>` on the CLI exposes it in `ps aux`.
> **Mitigation**: Use SAFECOOKIE auth, or set the password in `lnd.conf` with
> restrictive file permissions.

### 5. DeletePrivateKey Uses os.Remove

⚠️ **Security Note**
> `DeletePrivateKey` (`tor/cmd_onion.go:157-159`) calls `os.Remove()` which
> unlinks the file but does **not** overwrite contents. Data remains on disk
> until blocks are reused — forensic recovery is possible.
> **Mitigation**: Use full-disk encryption (LUKS, FileVault).

### 6. No mlock for Private Key in Memory

⚠️ **Security Note**
> The onion private key in memory is not protected with `mlock()` and could be
> swapped to disk under memory pressure.
> **Mitigation**: Disable swap or use encrypted swap.

---

## Cross-References

- **Chapter 8: Macaroons & RPC Permissions** — When connecting to LND over Tor,
  the IP-lock macaroon caveat will see `127.0.0.1` (the SOCKS proxy address) rather
  than the real client IP. Plan your macaroon caveats accordingly.
- **Chapter 9: Gossip & Network Discovery** — Node announcements can include `.onion`
  addresses. When `--tor.active` is set, LND adds the `.onion` address to its
  `NodeAnnouncement` so peers can find it on the Tor network.

---

## Exercises

💡 **Exercise 1: Set Up LND with Tor**

```bash
# Install Tor (macOS: brew install tor / Linux: sudo apt install tor)
# Add to /etc/tor/torrc:
#   SocksPort 9050
#   ControlPort 9051
#   CookieAuthentication 1

# Add to ~/.lnd/lnd.conf:
#   [tor]
#   tor.active=true
#   tor.v3=true
#   tor.encryptkey=true
#   tor.streamisolation=true

# Start Tor, then LND, and verify:
lncli getinfo | jq '.uris'
```

💡 **Exercise 2: Understand the Authentication Flow**

Read `tor/controller.go:441-478` and answer:
1. How does LND determine which auth methods Tor supports?
2. What happens if both HASHEDPASSWORD and SAFECOOKIE are available?
3. Trace `authenticateViaSafeCookie()` (line 497-589). What are the two HMAC keys
   and why are they different?

💡 **Exercise 3: Security Audit**

Check your LND+Tor deployment for these issues:

```bash
# Key encryption enabled?
grep "tor.encryptkey" ~/.lnd/lnd.conf

# Tor auth configured?
grep -E "^(CookieAuthentication|HashedControlPassword)" /etc/tor/torrc

# SkipProxy disabled?
grep "skip-proxy" ~/.lnd/lnd.conf

# Key file permissions restrictive?
ls -la ~/.lnd/v3_onion_private_key
```

💡 **Exercise 4: Test Stream Isolation**

```bash
# Same circuit (no isolation):
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

# Different circuits (with isolation via random creds):
curl --socks5-hostname 127.0.0.1:9050 --proxy-user "rand1:rand1" \
     https://check.torproject.org/api/ip
curl --socks5-hostname 127.0.0.1:9050 --proxy-user "rand2:rand2" \
     https://check.torproject.org/api/ip
# Different exit IPs = stream isolation working!
```

💡 **Exercise 5: Code Review — DeletePrivateKey**

Read `tor/cmd_onion.go:157-159`. Why is `os.Remove` insufficient for secure
deletion? Write a Go function that overwrites with random bytes before unlinking.
Consider challenges on CoW filesystems (ZFS, btrfs) and SSDs (wear leveling).

---

## Summary

In this chapter, you learned:

- **Tor** hides your IP address by routing traffic through three relays
- LND uses **two connections** to the Tor daemon: SOCKS5 (port 9050) for traffic
  routing and control (port 9051) for hidden service management
- The **Controller** (`tor/controller.go:105`) manages the control port connection
- Authentication follows a **hierarchy**: HASHEDPASSWORD → SAFECOOKIE → NULL
- **SAFECOOKIE** uses HMAC-SHA256 mutual authentication (line 497-589)
- Onion services are created via `ADD_ONION` in `server.go:3382`
- **V3** (ED25519) onion services are the current standard; V2 (RSA-1024) is deprecated
- **ClearNet** vs **ProxyNet** (`tor/net.go`) abstracts network operations
- **Stream isolation** generates random SOCKS5 credentials per connection
- The **watchtower** gets its own separate `.onion` address
- **SkipProxy** bypasses Tor for clearnet peers — **dangerous for privacy**
- Multiple security concerns: unencrypted keys, NULL auth, `os.Remove` without zeroing

Previous: [← Chapter 9: Gossip & Network Discovery](09-gossip-discovery.md) |
[← Chapter 8: Macaroons & RPC Permissions](08-macaroons-rpc.md)
