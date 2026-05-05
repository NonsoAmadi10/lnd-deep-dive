# Chapter 6: Watchtowers

> *"You shouldn't have to stay awake 24/7 to keep your Bitcoin safe. That's
> what watchtowers are for."*

---

## Table of Contents

1. [The Problem Watchtowers Solve](#the-problem-watchtowers-solve)
2. [Architecture Overview](#architecture-overview)
3. [The Cryptographic Trick](#the-cryptographic-trick)
4. [Blob Types & Justice Kits](#blob-types--justice-kits)
5. [Session Management & Policies](#session-management--policies)
6. [The Lookout: Watching the Chain](#the-lookout-watching-the-chain)
7. [Client-Side: Sending Backups](#client-side-sending-backups)
8. [Known Limitations](#known-limitations)
9. [Exercises](#-exercises)
10. [Cross-References](#cross-references)

---

## The Problem Watchtowers Solve

### 🔰 For Beginners

Remember from [Chapter 4](04-channels-commitments.md) that Lightning
channels use a **punishment mechanism**: if your counterparty broadcasts an
old (revoked) commitment transaction, you can sweep all the funds with a
**justice transaction**.

But there's a catch: you have to be **online** to detect the breach. The
cheater's output has a time lock (e.g., 144 blocks ≈ 24 hours), and you
must broadcast the justice transaction before that lock expires.

**What if your node is offline?**

```
┌─────────────────────────────────────────────────────────┐
│                    THE PROBLEM                          │
│                                                         │
│  Alice (honest)           Bob (cheater)                 │
│  ┌──────────┐            ┌──────────┐                  │
│  │  OFFLINE │            │  ONLINE  │                  │
│  │  (phone  │            │          │                  │
│  │  dead)   │            │ Broadcasts│                  │
│  │          │            │ OLD state │                  │
│  └──────────┘            └────┬─────┘                  │
│                               │                         │
│                          ┌────▼─────────────────┐      │
│                          │ Bitcoin Blockchain    │      │
│                          │ Old commitment TX     │      │
│                          │ Bob: 0.8 BTC (locked) │      │
│                          │ Alice: 0.2 BTC        │      │
│                          └──────────────────────┘      │
│                                                         │
│  Alice has 144 blocks (~24 hours) to respond...         │
│  but she's offline! Bob steals 0.6 BTC!                │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### The Solution: Watchtowers

A **watchtower** is a third-party service that watches the blockchain on
your behalf. If it detects a breach, it broadcasts the justice transaction
for you — even while you're sleeping.

```
┌─────────────────────────────────────────────────────────┐
│                    THE SOLUTION                         │
│                                                         │
│  Alice (offline)   Watchtower (always on)   Bob         │
│  ┌──────────┐     ┌──────────────┐     ┌──────────┐   │
│  │  OFFLINE │     │  WATCHING    │     │  Tries   │   │
│  │          │     │  24/7        │     │  to cheat│   │
│  └──────────┘     └──────┬───────┘     └────┬─────┘   │
│                          │                   │         │
│       Previously sent    │    Broadcasts     │         │
│       encrypted backup───┘    old state──────┘         │
│                          │                   │         │
│                    ┌─────▼───────────────────▼──┐      │
│                    │  Tower detects breach!      │      │
│                    │  Decrypts justice data      │      │
│                    │  Broadcasts justice TX      │      │
│                    │  ALL funds → Alice          │      │
│                    └────────────────────────────┘      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

📝 **Key Takeaway**: Watchtowers provide security while you're offline. They
hold encrypted data that can ONLY be decrypted when a specific breach
occurs. The tower cannot read your payment data or steal your funds.

---

## Architecture Overview

LND's watchtower system has two main components:

```
┌──────────────────────────────────────────────────────────┐
│                                                          │
│   CLIENT SIDE (wtclient/)        SERVER SIDE             │
│   ┌─────────────────────┐       ┌──────────────────────┐│
│   │                     │       │  watchtower/          ││
│   │  TowerClient        │       │  ┌────────────────┐  ││
│   │  ├── Manager        │  TCP  │  │  wtserver/     │  ││
│   │  ├── SessionQueue   │◄─────►│  │  (receives     │  ││
│   │  ├── BackupTask     │       │  │   backups)     │  ││
│   │  └── NegotiatorSess │       │  ├────────────────┤  ││
│   │                     │       │  │  lookout/      │  ││
│   └─────────────────────┘       │  │  (watches      │  ││
│                                 │  │   blockchain)  │  ││
│   Your LND node                 │  ├────────────────┤  ││
│                                 │  │  wtdb/         │  ││
│                                 │  │  (database)    │  ││
│                                 │  └────────────────┘  ││
│                                 │                      ││
│                                 │  Tower's LND node    ││
│                                 └──────────────────────┘│
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Key Packages

| Package | Role |
|---------|------|
| `wtclient/` | Client-side: creates backup tasks, manages sessions with towers |
| `watchtower/lookout/` | Server-side: watches blockchain for breaches |
| `watchtower/wtserver/` | Server-side: receives and stores encrypted backups |
| `watchtower/blob/` | Shared: blob types, encryption, justice kit definitions |
| `watchtower/wtdb/` | Shared: database layer for both client and tower |
| `watchtower/wtpolicy/` | Shared: policy definitions (fees, max updates) |
| `watchtower/wtwire/` | Shared: wire protocol messages between client and tower |

---

## The Cryptographic Trick

This is the most elegant part of the watchtower design. The tower stores
encrypted justice data, but **cannot decrypt it** until a breach actually
happens. Here's how:

### Step 1: Generating the Hint and Key

> **Source**: `watchtower/blob/derivation.go:53-71`

```go
// watchtower/blob/derivation.go
func NewBreachHintAndKeyFromHash(
    hash *chainhash.Hash,
) (BreachHint, BreachKey) {

    var (
        hint BreachHint  // 16 bytes
        key  BreachKey   // 32 bytes
    )

    h := sha256.New()

    // First SHA-256 pass: generates the hint
    h.Write(hash[:])            // hash = breach txid
    copy(hint[:], h.Sum(nil))   // hint = SHA256(txid)[:16]

    // Second SHA-256 pass: generates the encryption key
    h.Write(hash[:])            // feed txid again
    copy(key[:], h.Sum(nil))    // key = SHA256(txid || txid)

    return hint, key
}
```

### Step 2: The Two Pieces

```
Breach Transaction ID (txid):  abcdef1234567890...

    ┌─────────────────────────────────────────────┐
    │                                             │
    │   Hint = SHA256(txid)[:16]                  │
    │   ════════════════════                      │
    │   • First 16 bytes of SHA256(txid)          │
    │   • Just enough to IDENTIFY a breach        │
    │   • NOT enough to decrypt anything          │
    │   • Tower stores this as a lookup key        │
    │                                             │
    │   Key = SHA256(txid || txid)                │
    │   ═════════════════════════                  │
    │   • Full 32-byte SHA256 of txid doubled      │
    │   • Used to ENCRYPT the justice data        │
    │   • Tower does NOT have this key            │
    │   • Can only be derived from the actual txid │
    │                                             │
    └─────────────────────────────────────────────┘
```

### Step 3: How It All Fits Together

```
BACKUP PHASE (before breach):
═══════════════════════════════

Client                          Tower
  │                               │
  │  1. Compute:                  │
  │     hint = SHA256(txid)[:16]  │
  │     key  = SHA256(txid||txid) │
  │                               │
  │  2. Encrypt justice data      │
  │     with key                  │
  │                               │
  │  3. Send (hint, encrypted     │
  │     blob) to tower            │
  │  ─────────────────────────►  │
  │                               │  4. Store:
  │                               │     hint → encrypted blob
  │                               │     (can't decrypt!)
  ▼                               ▼


BREACH PHASE (during attack):
═══════════════════════════════

Blockchain                      Tower
  │                               │
  │  5. Revoked commitment TX     │
  │     appears on chain          │
  │     (txid is now known!)      │
  │  ─────────────────────────►  │
  │                               │
  │                               │  6. Compute:
  │                               │     hint = SHA256(txid)[:16]
  │                               │     → Match found!
  │                               │
  │                               │  7. Compute:
  │                               │     key = SHA256(txid||txid)
  │                               │     → NOW can decrypt!
  │                               │
  │                               │  8. Decrypt justice data
  │                               │  9. Broadcast justice TX
  │                               │
  │  ◄──── Justice TX ──────────  │
  │        (sweeps ALL funds      │
  │         back to honest party) │
  ▼                               ▼
```

### 🔰 For Beginners: Why Is This Brilliant?

The tower holds encrypted data but **cannot read it** unless a breach
actually happens. This has three amazing properties:

1. **Privacy**: The tower doesn't know your channel balances, payment
   history, or counterparty identities
2. **Security**: The tower cannot construct a justice TX on its own — it
   needs the actual breach transaction to derive the decryption key
3. **Efficiency**: The tower only needs to check each new transaction
   against its stored hints (a simple hash comparison)

⚠️ **Security Note**: The hint is only 16 bytes (128 bits), which means
there's a theoretical chance of false positives (two different txids
producing the same hint). However, 2^128 possible values makes this
astronomically unlikely — about 1 in 340 undecillion.

---

## Blob Types & Justice Kits

### Blob Types

> **Source**: `watchtower/blob/type.go:71-78`

LND supports multiple blob types to handle different channel commitment
formats:

```go
// watchtower/blob/type.go:71
const (
    // TypeAltruistCommit sweeps commitment outputs for
    // legacy (pre-anchor) channels.
    TypeAltruistCommit = FlagCommitOutputs

    // TypeAltruistAnchorCommit sweeps commitment outputs
    // for anchor channels (P2WSH to-remote output).
    TypeAltruistAnchorCommit = FlagCommitOutputs |
                               FlagAnchorChannel

    // TypeAltruistTaprootCommit sweeps commitment outputs
    // for taproot channels (P2TR outputs).
    TypeAltruistTaprootCommit = FlagCommitOutputs |
                                FlagTaprootChannel
)
```

### 🔰 For Beginners: Why "Altruist"?

These are called **altruist** types because the tower sweeps funds back
to the channel owner and keeps **nothing** for itself. There's no reward
or bounty for the tower — it's a purely altruistic service.

In the future, LND may support **reward** blob types where the tower
takes a small fee for its justice service. But for now, all blob types
are altruistic.

### Evolution of Blob Types

```
Version    Type                          Channel Format
───────    ──────────────────────        ──────────────
  v1       TypeAltruistCommit            Legacy (P2WSH)
  v2       TypeAltruistAnchorCommit      Anchor (P2WSH + anchors)
  v3       TypeAltruistTaprootCommit     Taproot (P2TR, MuSig2)
```

### The JusticeKit Interface

> **Source**: `watchtower/blob/justice_kit.go:19-57`

```go
// watchtower/blob/justice_kit.go:19
type JusticeKit interface {
    // ToLocalOutputSpendInfo returns the spend info for the
    // to_local output (the cheater's delayed output).
    ToLocalOutputSpendInfo() (
        *txscript.PkScript, wire.TxWitness, error,
    )

    // ToRemoteOutputSpendInfo returns the spend info for the
    // to_remote output (our immediately-spendable output).
    ToRemoteOutputSpendInfo() (
        *txscript.PkScript, wire.TxWitness, uint32, error,
    )

    // HasCommitToRemoteOutput reports whether a to_remote
    // output exists on the breached commitment.
    HasCommitToRemoteOutput() bool

    // AddToLocalSig adds the signature for sweeping the
    // to_local output.
    AddToLocalSig(sig lnwire.Sig)

    // AddToRemoteSig adds the signature for sweeping the
    // to_remote output.
    AddToRemoteSig(sig lnwire.Sig)

    // SweepAddress returns the address where swept funds
    // will be sent.
    SweepAddress() []byte

    // PlainTextSize returns the size of the unencrypted blob.
    PlainTextSize() int
}
```

### Three Implementations

| Implementation | Channel Type | Key Difference |
|---------------|-------------|----------------|
| `legacyJusticeKit` | Pre-anchor | P2WSH scripts for both outputs |
| `anchorJusticeKit` | Anchor | P2WSH with anchor outputs for fee bumping |
| `taprootJusticeKit` | Taproot | P2TR outputs, MuSig2 key aggregation |

Each implementation knows how to construct the correct witness data to
spend the breached commitment's outputs.

📝 **Key Takeaway**: The `JusticeKit` encapsulates everything the tower
needs to sweep funds after a breach — the scripts, signatures, and
destination address. Different channel types need different kits because
the underlying Bitcoin scripts are different.

---

## Session Management & Policies

### Session Policy

> **Source**: `watchtower/wtpolicy/policy.go`

```go
// watchtower/wtpolicy/policy.go:25
// DefaultMaxUpdates is the maximum number of encrypted blobs
// a client can send in a single session.
const DefaultMaxUpdates = 1024

// watchtower/wtpolicy/policy.go:34
// DefaultSweepFeeRate is the fee rate used for justice TXs.
// 2500 sat/kW ≈ 10 sat/vbyte — a reasonable priority fee.
const DefaultSweepFeeRate = chainfee.SatPerKWeight(2500)
```

### Session Lifecycle

```
┌───────────────────────────────────────────────────┐
│              SESSION LIFECYCLE                     │
│                                                   │
│  1. NEGOTIATE                                     │
│     Client contacts tower                         │
│     Agrees on: max_updates, sweep_fee_rate,       │
│                blob_type                          │
│     ┌──────────────────────────────────────┐      │
│     │  Session Created                     │      │
│     │  Max updates: 1024                   │      │
│     │  Sweep fee: 2500 sat/kW              │      │
│     │  Blob type: TypeAltruistAnchorCommit │      │
│     └──────────────────────────────────────┘      │
│                          │                        │
│  2. BACKUP (repeated up to 1024 times)            │
│     For each channel state update:                │
│     ┌──────────────────────────────────────┐      │
│     │  Send: (sequence_num, hint, blob)    │      │
│     │  sequence_num: 1, 2, 3, ... 1024     │      │
│     └──────────────────────────────────────┘      │
│                          │                        │
│  3. EXHAUSTED                                     │
│     After 1024 updates, session is full           │
│     Client negotiates NEW session                 │
│                                                   │
└───────────────────────────────────────────────────┘
```

### Why 1024 Updates?

Each session stores up to `DefaultMaxUpdates = 1024` encrypted blobs.
This is a balance between:

- **Too few**: Frequent session renegotiation overhead
- **Too many**: Large database for the tower, longer breach scanning

For an active channel with ~100 updates/day, one session lasts about
10 days.

⚠️ **Security Note**: When a session is exhausted, the client MUST
negotiate a new session. If the client fails to do so, new state updates
won't be backed up by the tower, leaving the channel unprotected against
breaches during those states.

---

## The Lookout: Watching the Chain

> **Source**: `watchtower/lookout/lookout.go`

The **lookout** is the component that actually watches the blockchain for
breaches. For every new block:

```
┌───────────────────────────────────────────────────────┐
│              LOOKOUT PROCESSING LOOP                   │
│                                                       │
│  New block arrives                                    │
│       │                                               │
│       ▼                                               │
│  For each transaction in block:                       │
│       │                                               │
│       ├── Compute hint = SHA256(txid)[:16]            │
│       │                                               │
│       ├── Look up hint in database                    │
│       │   ├── No match → skip (not a breach)          │
│       │   │                                           │
│       │   └── Match found!                            │
│       │       │                                       │
│       │       ├── Compute key = SHA256(txid||txid)    │
│       │       │                                       │
│       │       ├── Decrypt blob with key               │
│       │       │                                       │
│       │       ├── Construct JusticeDescriptor:        │
│       │       │   ├── BreachedCommitTx               │
│       │       │   ├── SessionInfo                    │
│       │       │   └── JusticeKit                     │
│       │       │                                       │
│       │       └── Dispatch to Punisher               │
│       │           └── Broadcast justice TX            │
│       │                                               │
│       └── Next transaction                            │
│                                                       │
└───────────────────────────────────────────────────────┘
```

### The Punisher

When a match is found, the lookout dispatches a `JusticeDescriptor` to
the **punisher**, which:

1. Constructs the justice transaction using the `JusticeKit`
2. Sets the fee rate to `DefaultSweepFeeRate` (2500 sat/kW)
3. Broadcasts the justice transaction to the Bitcoin network
4. Attempts to sweep all outputs (to_local + to_remote) in a single TX

### 🔰 For Beginners: What Is a Justice Transaction?

A justice transaction is Bitcoin's version of "I caught you cheating, and
now I'm taking everything." When a revoked commitment is broadcast:

```
Revoked Commitment TX (the cheat attempt):
├── to_local:  Bob's delayed output (0.8 BTC)
│              → Can be swept with revocation key!
└── to_remote: Alice's output (0.2 BTC)
               → Can be swept immediately

Justice TX:
├── Input 1: to_local (using revocation key)
├── Input 2: to_remote
└── Output:  Alice's sweep address (1.0 BTC - fees)

Result: Alice gets ALL the money. Bob gets nothing.
```

---

## Client-Side: Sending Backups

> **Source**: `wtclient/`

### The Backup Task

```
┌──────────────────────────────────────────────────────────┐
│                   BACKUP TASK FLOW                        │
│                                                          │
│  1. Channel state update occurs                          │
│     (new commitment signed & old one revoked)            │
│                          │                               │
│  2. Client creates BackupTask:                           │
│     ├── breach_txid   = old commitment txid              │
│     ├── breach_hint   = SHA256(txid)[:16]                │
│     ├── breach_key    = SHA256(txid||txid)               │
│     └── justice_data  = JusticeKit (scripts + sigs)      │
│                          │                               │
│  3. Encrypt justice_data with breach_key                 │
│                          │                               │
│  4. Queue task to SessionQueue                           │
│                          │                               │
│  5. SessionQueue sends to tower:                         │
│     ├── session_id                                       │
│     ├── sequence_number                                  │
│     ├── breach_hint                                      │
│     └── encrypted_blob                                   │
│                          │                               │
│  6. Tower stores (hint → blob) mapping                   │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Key Client Components

| Component | File | Role |
|-----------|------|------|
| `Manager` | `wtclient/manager.go` | Manages multiple tower connections |
| `SessionQueue` | `wtclient/session_queue.go` | Queues backup tasks for a session |
| `BackupTask` | `wtclient/backup_task.go` | Creates encrypted backup blobs |
| `SessionNegotiator` | `wtclient/session_negotiator.go` | Negotiates new sessions |
| `CandidateIterator` | `wtclient/candidate_iterator.go` | Selects which tower to use |

### Manager Responsibilities

The `Manager` coordinates everything:

1. Maintains connections to one or more watchtowers
2. Distributes backup tasks across active sessions
3. Negotiates new sessions when existing ones are exhausted
4. Handles tower failures (retries with backup towers)

---

## Known Limitations

### The Rebroadcast Gap

> **Source**: `watchtower/lookout/lookout.go:299`

There is a known limitation in the lookout: after a breach is detected
and the justice data is decrypted, if the LND node (running the tower)
restarts before the justice transaction confirms, **the decrypted justice
transaction is not automatically rebroadcast**.

```
┌───────────────────────────────────────────────┐
│           THE REBROADCAST GAP                  │
│                                               │
│  1. Breach detected ✓                         │
│  2. Blob decrypted ✓                          │
│  3. Justice TX broadcast ✓                    │
│  4. *** NODE RESTARTS ***                     │
│  5. Justice TX not rebroadcast ✗              │
│                                               │
│  Risk: If the justice TX was evicted from      │
│  mempools during restart, the breach may       │
│  go unpunished.                                │
│                                               │
└───────────────────────────────────────────────┘
```

⚠️ **Security Note**: This is a real limitation. In practice, the risk is
mitigated by the fact that:
- Justice TXs typically confirm quickly (target: 2 blocks)
- Bitcoin nodes usually keep transactions in their mempool across restarts
- The time window for this race condition is small

However, for maximum security, tower operators should ensure high uptime
and avoid unnecessary restarts during active breach responses.

### Other Limitations

1. **No HTLC sweeping**: Current watchtower implementations only sweep
   the to_local and to_remote outputs. HTLC outputs on breached
   commitments are not swept by the tower.

2. **Single sweep address**: The justice TX sends all funds to a single
   address specified during session creation. This address cannot be
   changed mid-session.

3. **No reward mechanism**: All current blob types are altruistic. There's
   no built-in incentive for tower operators beyond goodwill.

4. **Session exhaustion**: If a channel has more than 1024 state updates
   per session, the client must negotiate new sessions continuously.

---

## The Wire Protocol

> **Source**: `watchtower/wtwire/`

Communication between client and tower uses a custom wire protocol:

```
CLIENT                              TOWER
  │                                   │
  │  CreateSession                    │
  │  (blob_type, max_updates,         │
  │   reward_base, reward_rate,       │
  │   sweep_fee_rate)                 │
  │  ────────────────────────────►   │
  │                                   │
  │  CreateSessionReply               │
  │  (code: accepted/rejected,        │
  │   max_updates, sweep_fee_rate)    │
  │  ◄────────────────────────────   │
  │                                   │
  │  StateUpdate                      │
  │  (seq_num, hint, blob)            │
  │  ────────────────────────────►   │
  │                                   │
  │  StateUpdateReply                 │
  │  (code: accepted/rejected,        │
  │   last_applied)                   │
  │  ◄────────────────────────────   │
  │                                   │
  │  ... (repeat up to max_updates)   │
  │                                   │
  │  DeleteSession                    │
  │  ────────────────────────────►   │
  │                                   │
  │  DeleteSessionReply               │
  │  ◄────────────────────────────   │
  ▼                                   ▼
```

---

## Security Model Deep Dive

### What the Tower Knows

| Information | Tower Has It? |
|------------|---------------|
| Your node's identity | ✓ (connects directly) |
| Number of channels | ~ (knows # of sessions) |
| Channel balances | ✗ (encrypted) |
| Payment history | ✗ (encrypted) |
| Counterparty identities | ✗ (encrypted) |
| Channel capacity | ✗ (encrypted) |
| Sweep address | ✗ (encrypted until breach) |

### What the Tower CAN Do

1. ✓ Detect breaches (by matching hints)
2. ✓ Punish cheaters (by decrypting and broadcasting justice TX)
3. ✓ Refuse service (go offline or reject sessions)

### What the Tower CANNOT Do

1. ✗ Steal your funds (doesn't have your keys)
2. ✗ Read your payment data (encrypted)
3. ✗ Forge justice transactions (needs actual breach TX)
4. ✗ Cause you to lose money by going offline (you can still
   self-monitor or use other towers)

📝 **Key Takeaway**: The worst a malicious tower can do is **nothing** —
fail to respond to a breach. This is why running multiple towers with
different operators is recommended for maximum security.

---

## 💡 Exercises

### Exercise 1: Verify the Cryptography

Using `watchtower/blob/derivation.go`:

1. Write a Go program that takes a 32-byte txid and computes the
   BreachHint and BreachKey
2. Verify that `len(hint) == 16` and `len(key) == 32`
3. What's the probability of a hint collision (two different txids
   producing the same 16-byte hint)?

### Exercise 2: Understand Blob Encryption

1. Find the blob encryption logic in `watchtower/blob/`
2. What cipher is used? What mode?
3. How large is the encrypted blob for a legacy channel? An anchor channel?
4. Why is the blob size important for tower storage planning?

### Exercise 3: Session Capacity Planning

A Lightning Service Provider runs 500 channels, each averaging 200 state
updates per day:

1. How many sessions are needed per day? (at 1024 updates per session)
2. How much storage does the tower need per day (assume 400 bytes/blob)?
3. After 1 year, how much total storage?
4. Is `DefaultMaxUpdates = 1024` a good default for this use case?

### Exercise 4: Simulate a Breach

Walk through the full breach detection flow:

1. Start at `watchtower/lookout/lookout.go` — find the main processing loop
2. How does the lookout iterate through transactions in a new block?
3. What happens when a hint match is found?
4. Trace the path from match → decrypt → punish
5. Find the gap mentioned in [Known Limitations](#known-limitations)

### Exercise 5: Multi-Tower Redundancy

Design a backup strategy using multiple towers:

1. If you have 3 towers, should you send the same backup to all 3?
2. What are the privacy implications of using multiple towers?
3. What happens if Tower A and Tower B both detect the same breach?
4. How does LND's `wtclient/manager.go` handle tower selection?

---

## Cross-References

- **Chapter 4**: [Channels & Commitment Transactions](04-channels-commitments.md) —
  Understanding what's being revoked and why breaches are possible
- **Chapter 5**: [HTLCs, Routing & the Switch](05-htlc-switch-routing.md) —
  What happens to in-flight HTLCs during a breach
- **Chapter 7**: [Channel Backups (SCB)](07-channel-backups.md) — A
  complementary recovery mechanism that works differently from watchtowers

---

*Next: [Chapter 7 — Channel Backups (SCB) →](07-channel-backups.md)*
