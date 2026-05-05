# Chapter 8: Macaroons & RPC Permissions

> _"In LND, every RPC call must prove it has the right to be there — and macaroons are the bouncers at the door."_

---

## Table of Contents

1. [What Are Macaroons?](#what-are-macaroons)
2. [Macaroons vs. JWT Tokens](#macaroons-vs-jwt-tokens)
3. [Bearer Tokens & Caveats](#bearer-tokens--caveats)
4. [The Permission Model](#the-permission-model)
5. [Root Key Management](#root-key-management)
6. [The InterceptorChain](#the-interceptorchain)
7. [RPC State Machine](#rpc-state-machine)
8. [The Interceptor Pipeline](#the-interceptor-pipeline)
9. [Whitelisted RPCs](#whitelisted-rpcs)
10. [Mandatory Middleware](#mandatory-middleware)
11. [SafeCopyMacaroon Workaround](#safecopymacaroon-workaround)
12. [Security Notes](#security-notes)
13. [Exercises](#exercises)

---

## What Are Macaroons?

🔰 **For Beginners**

If you've used a website, you've probably encountered **cookies** — small tokens your
browser sends with every request so the server knows who you are. **Macaroons** are like
cookies, but with a cryptographic superpower: **caveats**.

Think of it like a bakery analogy:

1. The **baker** (LND) creates a fresh macaroon with a **root key** (secret recipe).
2. The baker stamps the macaroon with **permissions** ("this macaroon can read invoices").
3. Anyone who holds the macaroon can **add restrictions** (caveats) to it — like
   "only valid for the next 5 minutes" — **without** needing to go back to the baker.
4. But **nobody can remove** a restriction once it's been added.

This is fundamentally different from most token systems. With a JWT, only the server can
issue tokens. With macaroons, **anyone holding a token can make it more restrictive**.

```
┌─────────────────────────────────────────────────────┐
│                  MACAROON STRUCTURE                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│   ┌───────────────┐                                 │
│   │   Identifier   │  "who created me + root key ID"│
│   └───────┬───────┘                                 │
│           │                                         │
│           ▼                                         │
│   ┌───────────────┐                                 │
│   │   Caveat #1    │  "entity=invoices, action=read"│
│   │   (1st party)  │                                │
│   └───────┬───────┘                                 │
│           │  HMAC chain                             │
│           ▼                                         │
│   ┌───────────────┐                                 │
│   │   Caveat #2    │  "timeout < 2024-12-31"        │
│   │   (1st party)  │                                │
│   └───────┬───────┘                                 │
│           │  HMAC chain                             │
│           ▼                                         │
│   ┌───────────────┐                                 │
│   │   Signature    │  HMAC(rootKey, all caveats)    │
│   │   (32 bytes)   │                                │
│   └───────────────┘                                 │
│                                                     │
└─────────────────────────────────────────────────────┘
```

The key insight: each caveat is **chained** via HMAC. Adding a caveat computes a new
HMAC over the old signature + the new caveat. This means:

- You can **verify** the chain with the root key.
- You can **add** caveats (extend the chain).
- You **cannot remove** caveats (you'd need to reverse HMAC).

---

## Macaroons vs. JWT Tokens

🔰 **For Beginners**

**JWT (JSON Web Tokens)** are the most common authentication tokens in web apps. They
contain a JSON payload signed by the server. Here's how they compare to macaroons:

| Feature                  | JWT                          | Macaroon                     |
|--------------------------|------------------------------|------------------------------|
| **Creator**              | Only the server              | Server issues root; anyone attenuates |
| **Attenuation**          | ❌ Cannot restrict after issue | ✅ Anyone can add caveats   |
| **Format**               | Base64 JSON                  | Binary (protobuf-like)       |
| **Revocation**           | Blocklist required           | Delete root key ID           |
| **Third-party caveats**  | ❌ Not supported             | ✅ Delegated auth possible  |
| **Size**                 | Larger (JSON overhead)       | Compact binary               |
| **Expiry**               | Built-in `exp` claim         | Via timeout caveat           |

The critical difference: **JWTs are all-or-nothing**. If you have a JWT with admin
access, you can't give someone a "read-only" version of it. With macaroons, you can
take your admin macaroon and create a restricted version that only allows reading
invoices, only from a specific IP, only for the next hour.

📝 **Key Takeaway**
> Macaroons enable **delegation without coordination**. You don't need to go back to
> the server to create a restricted token — you do it yourself, cryptographically.

---

## Bearer Tokens & Caveats

🔰 **For Beginners**

A **bearer token** is a credential where possession alone grants access — like a
physical key. If someone steals your macaroon, they can use it. That's why caveats
are so important — they limit the blast radius.

### Types of Caveats in LND

LND supports several first-party caveats you can bake into a macaroon:

#### 1. Timeout Caveat

Limits how long the macaroon is valid:

```go
// From macaroons/constraints.go
// TimeoutConstraint creates a caveat that expires after
// the given number of seconds.
func TimeoutConstraint(seconds int64) Constraint {
    return func(mac *macaroon.Macaroon) error {
        caveatStr := fmt.Sprintf("%s %d",
            CondTimeoutPrefix, time.Now().Unix()+seconds,
        )
        return mac.AddFirstPartyCaveat([]byte(caveatStr))
    }
}
```

Usage: `lncli bakemacaroon --timeout 3600` (valid for 1 hour)

#### 2. IP Lock Caveat

Restricts the macaroon to a single IP address:

```go
// IPLockConstraint locks a macaroon to a specific IP.
func IPLockConstraint(ipAddr string) Constraint {
    return func(mac *macaroon.Macaroon) error {
        caveatStr := fmt.Sprintf("%s %s", CondIPAddressPrefix, ipAddr)
        return mac.AddFirstPartyCaveat([]byte(caveatStr))
    }
}
```

Usage: `lncli bakemacaroon --ip_address 192.168.1.100`

#### 3. Custom Caveats

You can add arbitrary conditions that are checked by middleware:

```go
// CustomConstraint adds an arbitrary caveat string.
func CustomConstraint(name, condition string) Constraint {
    return func(mac *macaroon.Macaroon) error {
        caveatStr := fmt.Sprintf("%s %s %s",
            CondCustomPrefix, name, condition,
        )
        return mac.AddFirstPartyCaveat([]byte(caveatStr))
    }
}
```

```
┌──────────────────────────────────────────────────────────┐
│              CAVEAT EXAMPLES IN PRACTICE                 │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Admin Macaroon (unrestricted):                          │
│    ┌─────────────────────────────────┐                   │
│    │ permissions: [all entities/acts] │                   │
│    │ caveats: (none)                  │                   │
│    │ sig: 0xabcdef...                 │                   │
│    └─────────────────────────────────┘                   │
│              │                                           │
│              │  Add timeout + IP lock                    │
│              ▼                                           │
│  Restricted Macaroon:                                    │
│    ┌─────────────────────────────────┐                   │
│    │ permissions: [all entities/acts] │                   │
│    │ caveat: timeout < 1735689600     │                   │
│    │ caveat: ipaddr 10.0.0.5          │                   │
│    │ sig: 0x123456... (new HMAC)      │                   │
│    └─────────────────────────────────┘                   │
│                                                          │
│  ⚠️  Same permissions, but now time-limited             │
│     and IP-restricted!                                   │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

⚠️ **Security Note**
> Bearer tokens are powerful but dangerous. If someone intercepts your macaroon
> over an unencrypted channel, they have full access. **Always** use TLS for gRPC
> connections. LND enforces this by default — the `tls.cert` and `tls.key` files
> in your LND directory encrypt all RPC traffic.

---

## The Permission Model

LND's permission system is defined in `rpcserver.go:104-226`. It follows a matrix of
**entities** and **actions**:

### Entities (10 total)

| Entity     | What It Controls                                       |
|------------|--------------------------------------------------------|
| `onchain`  | On-chain wallet operations (send, receive, list UTXOs) |
| `offchain` | Lightning channel operations (open, close, payments)   |
| `address`  | Address generation and lookups                         |
| `message`  | Message signing and verification                       |
| `peers`    | Peer connection management                             |
| `info`     | Node info queries (GetInfo, DescribeGraph)             |
| `invoices` | Invoice creation, lookup, settlement                   |
| `signer`   | Low-level signing operations                           |
| `macaroon` | Macaroon baking, listing, deletion                     |
| `uri`      | Custom per-URI permission (see below)                  |

### Actions (3 total)

| Action     | Meaning                                        |
|------------|------------------------------------------------|
| `read`     | Query / list / get operations                  |
| `write`    | Create / update / delete operations            |
| `generate` | Key generation (used by `signer`, `macaroon`)  |

Defined at `rpcserver.go:221-226`:

```go
// validActions is a map of all valid actions.
var validActions = map[string]bool{
    "read": true, "write": true, "generate": true,
}

// validEntities is a map of all valid entities.
var validEntities = map[string]bool{
    "onchain": true, "offchain": true, "address": true,
    "message": true, "peers": true, "info": true,
    "invoices": true, "signer": true, "macaroon": true,
    "uri": true,
}
```

### Permission Groups

LND pre-defines four macaroon permission levels (`rpcserver.go:107-215`):

```
┌───────────────────────────────────────────────────────────┐
│              MACAROON PERMISSION HIERARCHY                 │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  admin.macaroon                                           │
│  ├── read:  ALL entities                                  │
│  ├── write: ALL entities                                  │
│  └── generate: signer, macaroon                           │
│                                                           │
│  readonly.macaroon                                        │
│  ├── read: ALL entities                                   │
│  └── (no write, no generate)                              │
│                                                           │
│  invoice.macaroon                                         │
│  ├── read:  invoices, address, onchain                    │
│  └── write: invoices, address                             │
│                                                           │
│  Custom (via `lncli bakemacaroon`):                       │
│  └── Any combination of entity:action pairs               │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

### The Special `uri` Entity

The `uri` entity (`macaroons/service.go:22-29`) allows **per-RPC** permissions:

```go
// PermissionEntityCustomURI is the entity for a custom URI permission.
// Format: "uri:/lnrpc.Lightning/GetInfo"
const PermissionEntityCustomURI = "uri"
```

This lets you create a macaroon that can only call specific RPCs by their full URI,
giving you surgical control over what an API client can do.

📝 **Key Takeaway**
> LND's permission model is a 10×3 matrix of entities and actions. The `uri` entity
> adds a wildcard dimension, letting you restrict access to individual RPC methods.

---

## Root Key Management

The **root key** is the master secret that all macaroons derive from. Without it,
LND cannot verify any macaroon.

### Storage

Root keys are stored in the `macaroons/store.go:64-69` `RootKeyStorage` struct,
backed by a key-value database (bbolt or SQL):

```go
// RootKeyStorage implements the bakery.RootKeyStore interface.
type RootKeyStorage struct {
    kvdb.Backend
    encKeyDB kvdb.Backend
    mu       sync.RWMutex
}
```

Key facts about root key storage:

- The **default root key ID** is `0` (`macaroons/store.go:25-27`)
- Root keys are **32 bytes** of cryptographic randomness
- They are **encrypted at rest** using a key derived from the wallet password via
  **scrypt** (a memory-hard key derivation function)
- The key bucket in the database is named `"macrootkeys"` (`macaroons/store.go:22-23`)

### Lifecycle

```
┌──────────────┐     scrypt(password)     ┌──────────────┐
│    Wallet     │ ───────────────────────► │  Encryption  │
│   Password    │                          │     Key      │
└──────────────┘                          └──────┬───────┘
                                                  │
                                                  ▼
                                          ┌──────────────┐
                                          │  Root Key    │
                                          │  (32 bytes)  │
                                          │  encrypted   │
                                          │  in DB       │
                                          └──────┬───────┘
                                                  │
                                          Decrypt │ on unlock
                                                  ▼
                                          ┌──────────────┐
                                          │  Root Key    │
                                          │  (plaintext) │──► HMAC(key, caveats)
                                          │  in memory   │     = macaroon sig
                                          └──────────────┘
```

### Key Operations

From `macaroons/store.go`:

| Method               | Line | Purpose                                    |
|----------------------|------|--------------------------------------------|
| `NewRootKeyStorage`  | 72   | Create a new storage instance              |
| `CreateUnlock`       | 91   | Decrypt root key with wallet password      |
| `ChangePassword`     | 149  | Re-encrypt root key with new password      |
| `GenerateNewRootKey` | 341  | Generate a fresh 32-byte root key          |
| `SetRootKey`         | 385  | Manually set a root key (for recovery)     |
| `ListMacaroonIDs`    | 448  | List all root key IDs in use               |
| `DeleteMacaroonID`   | 485  | Delete a root key (revokes all its macaroons) |

⚠️ **Security Note**
> Deleting a root key ID via `DeleteMacaroonID` **instantly revokes** every macaroon
> ever created with that key. This is the nuclear option — use it when you suspect a
> macaroon has been compromised. There is no way to revoke individual macaroons; you
> must revoke the entire root key.

---

## The InterceptorChain

The `InterceptorChain` is the gatekeeper for all RPC calls in LND. Defined at
`rpcperms/interceptor.go:137-194`, it wraps every gRPC method in a series of checks.

```go
// InterceptorChain is a struct that holds all the interceptors
// and middleware that are used to secure the gRPC server.
type InterceptorChain struct {
    // state is the current RPC state of the server.
    state rpcState

    // noMacaroons indicates whether macaroon auth is disabled.
    noMacaroons bool

    // svc is the macaroon service used to verify macaroons.
    svc *macaroons.Service

    // rpcsLog is a logger for RPC state transitions.
    rpcsLog btclog.Logger

    // ... (additional fields for middleware, Prometheus, etc.)
}
```

---

## RPC State Machine

Before any RPC can execute, LND checks the **server state**. The state machine is
defined at `rpcperms/interceptor.go:25-51`:

```
┌─────────────────┐
│ waitingToStart   │  LND binary just launched
│   (line 30)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     No wallet file found
│ walletNotCreated │ ◄─────────────────────────
│   (line 35)      │
└────────┬────────┘
         │  Wallet exists but locked
         ▼
┌─────────────────┐
│  walletLocked    │  Waiting for password
│   (line 40)      │
└────────┬────────┘
         │  Password provided
         ▼
┌─────────────────┐
│ walletUnlocked   │  Wallet open, subsystems starting
│   (line 44)      │
└────────┬────────┘
         │  All RPC sub-servers registered
         ▼
┌─────────────────┐
│   rpcActive      │  gRPC ready, but not all subsystems
│   (line 47)      │
└────────┬────────┘
         │  All subsystems fully initialized
         ▼
┌─────────────────┐
│  serverActive    │  Fully operational
│   (line 50)      │
└────────────────┘
```

Each RPC method is tagged with the **minimum state** it requires. For example:
- `GetState` only needs `waitingToStart`
- `UnlockWallet` needs `walletLocked`
- `SendPayment` needs `serverActive`

If the server hasn't reached the required state yet, the RPC returns an error telling
the caller to try later.

📝 **Key Takeaway**
> The RPC state machine ensures that callers can't send payments before the wallet is
> unlocked, or open channels before the chain backend is synced. It's a safety net
> against race conditions during startup.

---

## The Interceptor Pipeline

Every RPC call passes through a **five-stage pipeline** defined in
`rpcperms/interceptor.go:538-599` (`CreateServerOpts`):

```
┌──────────────────────────────────────────────────────────────┐
│                    RPC REQUEST PIPELINE                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   Client Request                                             │
│        │                                                     │
│        ▼                                                     │
│   ┌──────────┐                                               │
│   │  Stage 1  │  ERROR LOG INTERCEPTOR                       │
│   │ (line 604)│  Logs any errors from downstream stages.     │
│   └────┬─────┘  Does NOT block requests.                     │
│        │                                                     │
│        ▼                                                     │
│   ┌──────────┐                                               │
│   │  Stage 2  │  RPC STATE CHECK                             │
│   │ (line 774)│  Is the server in the right state for        │
│   └────┬─────┘  this RPC? (See state machine above)          │
│        │                                                     │
│        ▼                                                     │
│   ┌──────────┐                                               │
│   │  Stage 3  │  MACAROON VERIFICATION                       │
│   │ (line 682)│  Extract macaroon from metadata,             │
│   └────┬─────┘  verify signature & caveats.                  │
│        │                                                     │
│        ▼                                                     │
│   ┌──────────┐                                               │
│   │  Stage 4  │  MIDDLEWARE INTERCEPTOR                       │
│   │ (line 807)│  External middleware can inspect/reject.      │
│   └────┬─────┘  Fail-closed if middleware crashes.           │
│        │                                                     │
│        ▼                                                     │
│   ┌──────────┐                                               │
│   │  Stage 5  │  PROMETHEUS METRICS                          │
│   │           │  Record request counts, latencies.           │
│   └────┬─────┘                                               │
│        │                                                     │
│        ▼                                                     │
│   RPC Handler                                                │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

Each stage has **two variants**: one for unary RPCs (single request/response) and
one for streaming RPCs (persistent connections):

| Stage         | Unary Method                         | Stream Method                        |
|---------------|--------------------------------------|--------------------------------------|
| Error Log     | `errorLogUnaryServerInterceptor`     | `errorLogStreamServerInterceptor`    |
| RPC State     | `rpcStateUnaryServerInterceptor`     | `rpcStateStreamServerInterceptor`    |
| Macaroon      | `MacaroonUnaryServerInterceptor`     | `MacaroonStreamServerInterceptor`    |
| Middleware    | `middlewareUnaryServerInterceptor`   | `middlewareStreamServerInterceptor`  |

---

## Whitelisted RPCs

Some RPCs must work **before** the wallet is unlocked — and therefore before any
macaroon can be verified. These are whitelisted at
`rpcperms/interceptor.go:85-96`:

```go
var macaroonWhitelist = map[string]bool{
    "/lnrpc.WalletUnlocker/GenSeed":        true,  // line 87
    "/lnrpc.WalletUnlocker/InitWallet":     true,  // line 88
    "/lnrpc.WalletUnlocker/UnlockWallet":   true,  // line 89
    "/lnrpc.WalletUnlocker/ChangePassword": true,  // line 90
    "/lnrpc.State/SubscribeState":          true,  // line 94
    "/lnrpc.State/GetState":               true,  // line 95
}
```

These RPCs skip Stage 3 (macaroon verification) entirely. This makes sense because:

- **GenSeed**: Generates a new wallet seed — no wallet exists yet.
- **InitWallet**: Creates a new wallet — needs seed, not macaroon.
- **UnlockWallet**: Unlocks existing wallet — provides the password that decrypts
  the root key needed to verify macaroons!
- **ChangePassword**: Changes the wallet password (requires old password).
- **SubscribeState/GetState**: Monitoring RPCs that report server status.

⚠️ **Security Note**
> The whitelist is **hardcoded** and cannot be extended via configuration. This is
> intentional — adding RPCs to the whitelist would expose them without authentication.
> If you're writing a custom gRPC middleware, be aware that these RPCs will arrive
> **without** a macaroon in their metadata.

---

## Mandatory Middleware

LND supports **external middleware** that can intercept RPC calls for custom
authorization logic. This is configured via the `--rpcmiddleware` flag.

The critical design decision: middleware is **fail-closed**
(`rpcperms/interceptor.go:807-863`).

```
┌─────────────────────────────────────────────────┐
│         MIDDLEWARE FAILURE BEHAVIOR              │
├─────────────────────────────────────────────────┤
│                                                 │
│  Middleware registered & responding:             │
│    Request ──► Middleware ──► Allow/Deny         │
│                                                 │
│  Middleware registered but crashed/hung:         │
│    Request ──► Middleware ──► TIMEOUT            │
│                              │                  │
│                              ▼                  │
│                         ❌ REQUEST DENIED       │
│                                                 │
│  No middleware registered:                       │
│    Request ──► (skip stage) ──► Allow            │
│                                                 │
└─────────────────────────────────────────────────┘
```

This means: if you register a mandatory middleware and it crashes, **all RPCs will
fail**. This is a safety feature — it prevents requests from bypassing your custom
authorization logic if the middleware goes down.

📝 **Key Takeaway**
> Mandatory middleware follows the **fail-closed** principle: if the middleware can't
> make a decision, the request is denied. This is the secure default, but it means
> a buggy middleware can take down your entire RPC interface.

---

## SafeCopyMacaroon Workaround

The `SafeCopyMacaroon` function at `macaroons/service.go:372-384` exists to work
around a subtle bug in the upstream Go macaroon library:

```go
// SafeCopyMacaroon creates a copy of a macaroon that is safe to
// modify. This is needed because the macaroon library's Clone()
// method does not perform a deep copy of all internal fields.
func SafeCopyMacaroon(mac *macaroon.Macaroon) (*macaroon.Macaroon, error) {
    macBytes, err := mac.MarshalBinary()
    if err != nil {
        return nil, err
    }

    newMac := &macaroon.Macaroon{}
    if err := newMac.UnmarshalBinary(macBytes); err != nil {
        return nil, err
    }

    return newMac, nil
}
```

Why is this needed? The Go `macaroon.Macaroon` struct contains internal slices. When
you use the library's `Clone()` method, it performs a **shallow copy** — the clone
shares the same underlying byte arrays as the original. If you then add a caveat to
the clone, it can corrupt the original macaroon's data.

The workaround: serialize to bytes, then deserialize into a brand new struct.
This guarantees a **true deep copy** with no shared memory.

🔰 **For Beginners**

In Go, slices are reference types — they point to an underlying array in memory.
Copying a struct that contains slices just copies the pointer, not the data.
This is called a **shallow copy**. To get independent copies, you need to either
manually copy each slice or use a serialize/deserialize roundtrip like LND does here.

---

## Security Notes

### Summary of Security Considerations

⚠️ **Security Note: Macaroon File Permissions**
> LND writes macaroon files (`admin.macaroon`, `readonly.macaroon`,
> `invoice.macaroon`) with restrictive permissions, but if you copy them to
> another machine, ensure they're readable only by the intended user
> (`chmod 600`). A leaked admin macaroon grants full control of your node.

⚠️ **Security Note: Root Key Deletion**
> Deleting a root key ID revokes all associated macaroons instantly but
> **cannot be undone**. If you delete the default root key (ID 0) and haven't
> baked new macaroons with a different root key ID, you'll lock yourself out.

⚠️ **Security Note: No Macaroon Mode**
> Running with `--no-macaroons` disables all authentication. This is useful for
> development but **catastrophically dangerous** in production. Any process that
> can reach the gRPC port has full admin access.

⚠️ **Security Note: TLS Is Mandatory**
> Macaroons are bearer tokens transmitted in gRPC metadata. Without TLS, they
> travel in plaintext and can be intercepted. LND generates TLS certificates
> automatically and refuses to start without them (unless explicitly overridden).

---

## Cross-References

- **Chapter 9: Gossip & Network Discovery** — Macaroons also protect gossip-related
  RPCs like `DescribeGraph` and `GetNetworkInfo`.
- **Chapter 10: Tor Integration & IP Privacy** — When using Tor, the IP-lock caveat
  on macaroons interacts with Tor's IP anonymization (the IP seen will be `127.0.0.1`
  for local connections via the SOCKS proxy).

---

## Exercises

💡 **Exercise 1: Bake a Read-Only Invoice Macaroon**

Using `lncli`, create a macaroon that can only read invoices, locked to `127.0.0.1`,
and valid for 1 hour:

```bash
lncli bakemacaroon invoices:read \
    --ip_address 127.0.0.1 \
    --save_to ./invoice-reader.macaroon \
    --timeout 3600
```

Then verify it works:

```bash
# This should succeed:
lncli --macaroonpath=./invoice-reader.macaroon listinvoices

# This should fail (no write permission):
lncli --macaroonpath=./invoice-reader.macaroon addinvoice --amt=1000
```

💡 **Exercise 2: Trace the Interceptor Pipeline**

Open `rpcperms/interceptor.go` and find the `CreateServerOpts()` function at line 538.
Answer these questions:

1. In what order are the interceptors chained?
2. What happens if you swap the macaroon and RPC state interceptors?
3. Why is the error log interceptor first (outermost)?

💡 **Exercise 3: Understand Root Key Rotation**

Using the LND API, perform a root key rotation:

```bash
# Step 1: List current root key IDs
lncli listmacaroonids

# Step 2: Generate a new root key
lncli generatemacaroonrootkey

# Step 3: Bake a new admin macaroon with the new root key
lncli bakemacaroon --root_key_id 1 \
    onchain:read onchain:write \
    offchain:read offchain:write \
    address:read address:write \
    message:read message:write \
    peers:read peers:write \
    info:read info:write \
    invoices:read invoices:write \
    signer:read signer:generate \
    macaroon:read macaroon:write macaroon:generate \
    --save_to ./new-admin.macaroon

# Step 4: Delete the old root key (this revokes all old macaroons!)
lncli deletemacaroonid 0
```

💡 **Exercise 4: Code Reading**

Read through `macaroons/service.go` and answer:

1. Where is the `Service` struct defined? (Hint: around line 87-101)
2. What is the `ExternalValidators` map used for?
3. How does the service decide which root key to use when verifying a macaroon?

💡 **Exercise 5: Security Audit**

Imagine you're auditing a production LND deployment. Check for these common mistakes:

1. Are macaroon files readable by other users? (`ls -la ~/.lnd/data/chain/bitcoin/mainnet/`)
2. Is `--no-macaroons` set in the config? (`grep no-macaroons ~/.lnd/lnd.conf`)
3. Is TLS properly configured? (`openssl s_client -connect localhost:10009`)
4. Are there any macaroons with no timeout caveat in use by automated systems?

---

## Summary

In this chapter, you learned:

- **Macaroons** are bearer tokens with cryptographic caveats, unlike JWTs
- LND uses a **10-entity × 3-action** permission model
- The **root key** (32 bytes) is encrypted with scrypt and stored in the database
- The **InterceptorChain** enforces a 5-stage pipeline on every RPC call
- The server has a **6-state state machine** that controls which RPCs are available
- **6 RPCs** are whitelisted and skip macaroon verification
- Middleware is **fail-closed** — if it crashes, all RPCs are denied
- `SafeCopyMacaroon` works around a shallow-copy bug in the macaroon library

Next: [Chapter 9: Gossip & Network Discovery →](09-gossip-discovery.md)
