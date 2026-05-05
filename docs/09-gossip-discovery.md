# Chapter 9: Gossip & Network Discovery (BOLT-7)

> _"The Lightning Network has no central directory. Every node learns about the
> network by talking to its neighbors — this is gossip."_

---

## Table of Contents

1. [What Is Gossip?](#what-is-gossip)
2. [The AuthenticatedGossiper](#the-authenticatedgossiper)
3. [Three Gossip Message Types](#three-gossip-message-types)
4. [Channel Announcements](#channel-announcements)
5. [Channel Updates](#channel-updates)
6. [Node Announcements](#node-announcements)
7. [Rate Limiting](#rate-limiting)
8. [The Ban Manager](#the-ban-manager)
9. [SyncManager: Active vs. Passive](#syncmanager-active-vs-passive)
10. [Channel Announcement Proofs](#channel-announcement-proofs)
11. [AssumeChannelValid](#assumechannelvalid)
12. [SCID Aliases for Privacy](#scid-aliases-for-privacy)
13. [Trickle Broadcasting](#trickle-broadcasting)
14. [Security Considerations](#security-considerations)
15. [Exercises](#exercises)

---

## What Is Gossip?

🔰 **For Beginners**

Imagine you're in a large school and you need to find out who's friends with whom, so
you can pass notes through intermediaries. There's no teacher handing out a friendship
chart. Instead, each student tells their neighbors: "Hey, I'm friends with Alice!" and
those neighbors pass it on. Eventually, everyone has a rough map of the social network.

This is **gossip** — a decentralized protocol where nodes share information about the
network topology with their peers. In the Lightning Network, gossip serves three
purposes:

1. **Announce channels**: "This payment channel exists between nodes A and B."
2. **Share routing policies**: "To route through my channel, the fee is 1 sat + 0.01%."
3. **Advertise node info**: "My alias is 'ACINQ', I'm at this IP, I support these features."

```
┌──────────────────────────────────────────────────────────────────┐
│      Alice ──chan──► Bob ──chan──► Carol                          │
│                                                                  │
│  1. A & B open channel, create ChannelAnnouncement (4 sigs)      │
│  2. B forwards announcement to C                                 │
│  3. C validates and adds to its local graph                      │
└──────────────────────────────────────────────────────────────────┘
```

📝 **Key Takeaway**
> Gossip is how Lightning nodes build a **shared, decentralized map** of the payment
> network. There is no central server — every node independently verifies and relays
> announcements from its peers.

---

## The AuthenticatedGossiper

The central processor for all gossip messages in LND is the `AuthenticatedGossiper`,
defined at `discovery/gossiper.go:490-582`:

```go
// AuthenticatedGossiper is a subsystem which is responsible for
// receiving announcements, validating them and applying the changes
// to router subsystem.
type AuthenticatedGossiper struct {
    // cfg holds the gossiper configuration.
    cfg *Config

    // syncMgr manages gossip synchronization with peers.
    syncMgr *SyncManager

    // banman tracks misbehaving peers.
    banman *banman

    // channelMtx guards access to the channel state.
    channelMtx sync.Mutex

    // ... (message queues, validation barriers, lifecycle)
}
```

### Key Methods

| Method                     | Line  | Purpose                                         |
|----------------------------|-------|-------------------------------------------------|
| `Start()`                  | 673   | Start the gossiper subsystem                    |
| `Stop()`                   | 848   | Stop the gossiper subsystem                     |
| `ProcessRemoteAnnouncement`| 890   | Handle a gossip message from a peer             |
| `ProcessLocalAnnouncement` | 1006  | Handle a gossip message from our own node       |
| `networkHandler`           | 1482  | Main event loop (select on channels)            |
| `syncBlockHeight`          | 724   | Sync block height with chain backend            |
| `InitSyncState`            | 1787  | Initialize sync state for a new peer connection |
| `PruneSyncState`           | 1794  | Clean up sync state when a peer disconnects     |

The `networkHandler` (line 1482) is the heart of the gossiper. It runs as a goroutine
and processes events from multiple channels:

```go
func (d *AuthenticatedGossiper) networkHandler(ctx context.Context) {
    trickleTimer := time.NewTicker(d.cfg.TrickleDelay)  // line 1492
    defer trickleTimer.Stop()

    for {
        select {
        case announcement := <-d.networkMsgs:
            // Process incoming gossip message
        case <-trickleTimer.C:
            // Batch and broadcast pending announcements
        case <-d.quit:
            return
        }
    }
}
```

---

## Three Gossip Message Types

The Lightning gossip protocol (BOLT-7) defines three message types. Each serves a
different purpose and has different validation requirements.

```
┌──────────────────────────────────────────────────────────────┐
│                GOSSIP MESSAGE TYPES                           │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────────────┐                                  │
│  │  ChannelAnnouncement   │  "This channel EXISTS"           │
│  │  (BOLT-7 type 256)     │  Requires 4 signatures           │
│  │                        │  Sent once per channel           │
│  └────────────────────────┘                                  │
│                                                              │
│  ┌────────────────────────┐                                  │
│  │  ChannelUpdate         │  "Here are my routing POLICIES"  │
│  │  (BOLT-7 type 258)     │  Requires 1 signature            │
│  │                        │  Sent whenever policy changes    │
│  └────────────────────────┘                                  │
│                                                              │
│  ┌────────────────────────┐                                  │
│  │  NodeAnnouncement      │  "Here is my node INFO"          │
│  │  (BOLT-7 type 257)     │  Requires 1 signature            │
│  │                        │  Sent whenever info changes      │
│  └────────────────────────┘                                  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Channel Announcements

A `ChannelAnnouncement` proves that a payment channel exists on the Bitcoin blockchain.
It's the most security-critical gossip message because it requires **four signatures**.

### Why Four Signatures?

Each channel has two participants, and each participant has two keys:

1. **Node key** — the persistent identity key of the Lightning node
2. **Bitcoin key** — the key that controls the on-chain funding output

Both participants must sign with **both keys**, yielding four signatures total:

```
┌────────────────────────────────────────────────────┐
│          CHANNEL ANNOUNCEMENT SIGNATURES           │
├────────────────────────────────────────────────────┤
│                                                    │
│   Node A                        Node B             │
│   ┌──────────────┐   funding   ┌──────────────┐   │
│   │              │◄───tx──────►│              │   │
│   │  node_key_A  │             │  node_key_B  │   │
│   │  btc_key_A   │             │  btc_key_B   │   │
│   └──────────────┘             └──────────────┘   │
│                                                    │
│   Signatures required:                             │
│   1. sig_node_A  ── "I, node A, vouch for this"   │
│   2. sig_node_B  ── "I, node B, vouch for this"   │
│   3. sig_btc_A   ── "My Bitcoin key A is real"     │
│   4. sig_btc_B   ── "My Bitcoin key B is real"     │
│                                                    │
│   All four MUST be valid for the announcement      │
│   to be accepted by other nodes.                   │
│                                                    │
└────────────────────────────────────────────────────┘
```

🔰 **For Beginners**

The four-signature requirement prevents **fake channel attacks**. Without it, an
attacker could announce channels that don't exist, polluting the network graph and
wasting routing attempts. By requiring both node keys AND both Bitcoin keys, LND
ensures that the channel corresponds to a real on-chain transaction.

### What's in a ChannelAnnouncement?

| Field            | Description                                               |
|------------------|-----------------------------------------------------------|
| `ShortChannelID` | Compact encoding: `block_height:tx_index:output_index`    |
| `NodeID1`        | Public key of the first node (lexicographically smaller)   |
| `NodeID2`        | Public key of the second node                             |
| `BitcoinKey1`    | Bitcoin funding key of the first node                     |
| `BitcoinKey2`    | Bitcoin funding key of the second node                    |
| `Features`       | Feature bits supported by this channel                    |
| `ChainHash`      | Which blockchain (mainnet, testnet, etc.)                  |

---

## Channel Updates

A `ChannelUpdate` message advertises the **routing policy** for one direction of a
channel. Each node sends its own update for its side.

### Routing Policy Fields

```go
// Key fields in a ChannelUpdate message
type ChannelUpdate1 struct {
    ShortChannelID  ShortChannelID  // Which channel
    Timestamp       uint32          // When this policy was set
    ChannelFlags    uint8           // Direction bit + disabled bit
    TimeLockDelta   uint16          // CLTV delta (min blocks for HTLC timeout)
    HtlcMinimumMsat uint64         // Minimum HTLC size we'll forward
    HtlcMaximumMsat uint64         // Maximum HTLC size we'll forward
    BaseFee         uint32          // Fixed fee in msat
    FeeRate         uint32          // Proportional fee in millionths
}
```

Example: A routing policy of `BaseFee=1000, FeeRate=100` means:

- Fixed fee: 1 sat (1000 msat)
- Proportional fee: 0.01% (100 parts per million)
- To forward 100,000 sats: `1 sat + (100,000 × 100 / 1,000,000) = 1 + 10 = 11 sats`

### The Disabled Flag

The `ChannelFlags` byte contains a "disabled" bit. When set, it tells the network:
"Don't route through this channel right now." This is used when:

- A peer goes offline
- The channel runs out of outbound liquidity
- Manual channel disabling via `lncli updatechanpolicy --chan_point=... --disabled`

📝 **Key Takeaway**
> Channel updates are the most frequently changing gossip messages. Every time a node
> adjusts its fees, CLTV delta, or HTLC limits, it broadcasts a new `ChannelUpdate`.
> Rate limiting (covered below) is critical to prevent update spam.

---

## Node Announcements

A `NodeAnnouncement` advertises metadata about a node:

| Field       | Description                                          |
|-------------|------------------------------------------------------|
| `Alias`     | Human-readable name (up to 32 UTF-8 bytes)           |
| `Color`     | RGB hex color (e.g., `#3399FF`)                      |
| `Addresses` | Network addresses (IPv4, IPv6, Tor .onion)           |
| `Features`  | Feature bits this node supports                      |
| `Timestamp` | When this announcement was created                   |
| `Signature` | Signature from the node's identity key               |

Node announcements are **only valid** if the node has at least one announced channel.
You can't just broadcast your existence — you need to prove you're a real participant
with on-chain channels.

---

## Rate Limiting

Gossip can be abused. An attacker could flood the network with channel updates,
consuming bandwidth and CPU. LND implements multiple layers of rate limiting.

### Per-Channel Rate Limiting

Defined at `discovery/gossiper.go:51-56`:

```go
// DefaultMaxChannelUpdateBurst is the default maximum number of
// updates for a specific channel and direction that we'll accept
// over the channel update interval.
DefaultMaxChannelUpdateBurst = 10  // line 51

// DefaultChannelUpdateInterval is the default interval used to
// determine how often we should allow a new update for a specific
// channel and direction.
DefaultChannelUpdateInterval = time.Minute  // line 56
```

This means: for any given channel direction, LND accepts **at most 10 updates per
minute**. Additional updates within that window are silently dropped.

### Outbound Bandwidth Limits

From `discovery/sync_manager.go:37-47`:

```go
// DefaultMsgBytesBurst is the default burst limit for outbound
// gossip messages.
DefaultMsgBytesBurst = 2 * 1000 * 1_024  // 2 MB burst (line 37)

// DefaultMsgBytesPerSecond is the default rate limit for outbound
// gossip messages in bytes per second.
DefaultMsgBytesPerSecond = 1000 * 1_024  // 1 MB/s global (line 42)

// DefaultPeerMsgBytesPerSecond is the default per-peer rate limit
// for outbound gossip messages in bytes per second.
DefaultPeerMsgBytesPerSecond = 50 * 1_024  // 50 KB/s per peer (line 47)
```

```
┌──────────────────────────────────────────────────────────────┐
│                  RATE LIMITING LAYERS                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Layer 1: Per-Channel Update Limit                           │
│  ┌─────────────────────────────────────────┐                 │
│  │  Max 10 updates / minute / direction    │                 │
│  │  Prevents single-channel spam           │                 │
│  └─────────────────────────────────────────┘                 │
│                                                              │
│  Layer 2: Global Outbound Bandwidth                          │
│  ┌─────────────────────────────────────────┐                 │
│  │  1 MB/s total across all peers          │                 │
│  │  2 MB burst allowance                   │                 │
│  │  Prevents bandwidth exhaustion          │                 │
│  └─────────────────────────────────────────┘                 │
│                                                              │
│  Layer 3: Per-Peer Outbound Bandwidth                        │
│  ┌─────────────────────────────────────────┐                 │
│  │  50 KB/s per individual peer            │                 │
│  │  Prevents one peer from hogging pipe    │                 │
│  └─────────────────────────────────────────┘                 │
│                                                              │
│  Layer 4: Ban Manager (see below)                            │
│  ┌─────────────────────────────────────────┐                 │
│  │  Score-based banning for violators      │                 │
│  │  100 points → 48-hour ban               │                 │
│  └─────────────────────────────────────────┘                 │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## The Ban Manager

When a peer sends too many invalid or rate-limited messages, LND's **ban manager**
steps in. Defined at `discovery/ban.go`:

### Constants

```go
// DefaultBanThreshold is the default threshold at which a peer
// will be banned.
DefaultBanThreshold = 100  // line 19

// maxBannedPeers is the maximum number of peers we'll track bans for.
maxBannedPeers = 10_000  // line 24 (LRU cache)

// banTime is how long a peer is banned after crossing the threshold.
banTime = time.Hour * 48  // line 30

// resetDelta is the period after which a peer's ban score resets.
resetDelta = time.Hour * 48  // line 35

// purgeInterval is how often we clean up expired ban entries.
purgeInterval = time.Minute * 10  // line 40
```

### How It Works

```
  Peer sends invalid gossip
         │
         ▼
  ┌──────────────┐
  │ Add to score │  (+points based on violation severity)
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐     No
  │ Score ≥ 100? │──────────► Continue accepting messages
  └──────┬───────┘
         │ Yes
         ▼
  ┌──────────────┐
  │  BAN PEER    │  Reject all gossip for 48 hours
  │  for 48h     │
  └──────────────┘
```

### The `banman` Struct

From `discovery/ban.go:142-150`:

```go
type banman struct {
    // peerBanIndex is an LRU cache tracking ban state per peer.
    peerBanIndex *lru.Cache  // maxBannedPeers = 10,000 entries

    // cfg holds the ban manager configuration.
    cfg *banCfg

    // ... (lifecycle management)
}
```

⚠️ **Security Note: In-Memory Only!**
> The ban manager stores all ban state **in memory only**. When LND restarts, **all
> bans are cleared**. This means an attacker who is banned can simply wait for your
> node to restart (or trigger a restart) to reset their ban. This is a known
> limitation — there's no persistent ban list on disk.

⚠️ **Security Note: LRU Eviction**
> The ban list is an LRU cache with a maximum of 10,000 entries. If an attacker
> controls more than 10,000 peer identities, they can **evict** other banned peers
> from the cache by filling it with new entries.

---

## SyncManager: Active vs. Passive

Not all peers gossip equally. LND's `SyncManager` (`discovery/sync_manager.go:156-220`)
divides peers into **active** and **passive** syncers:

### Active Syncers

- **Receive** full real-time gossip updates from the peer.
- Limited in number to avoid bandwidth overload.
- **Rotated** every 20 minutes (`DefaultSyncerRotationInterval`, line 22).

### Passive (Inactive) Syncers

- Do **not** receive real-time updates.
- Only used for initial graph synchronization.
- Remain idle until rotated to active.

### Pinned Syncers

- **Always active** — they bypass the rotation mechanism.
- Configured via `PinnedSyncers` in the gossiper config (line 349-352).
- Useful for critical peers (e.g., your LSP or a well-connected hub).

```
┌──────────────────────────────────────────────────────────────┐
│                  SYNC MANAGER ARCHITECTURE                    │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌────────────────────────────────────────────┐             │
│   │              SyncManager                    │             │
│   │  (discovery/sync_manager.go:156)            │             │
│   ├────────────────────────────────────────────┤             │
│   │                                            │             │
│   │  activeSyncers    ┌──┐┌──┐┌──┐            │             │
│   │  (line 193)       │P1││P2││P3│  (rotated) │             │
│   │                   └──┘└──┘└──┘            │             │
│   │                                            │             │
│   │  inactiveSyncers  ┌──┐┌──┐┌──┐┌──┐┌──┐   │             │
│   │  (line 198)       │P4││P5││P6││P7││P8│   │             │
│   │                   └──┘└──┘└──┘└──┘└──┘   │             │
│   │                                            │             │
│   │  pinnedSyncers    ┌──┐┌──┐                │             │
│   │  (line 202)       │PA││PB│  (always on)   │             │
│   │                   └──┘└──┘                │             │
│   │                                            │             │
│   └────────────────────────────────────────────┘             │
│                                                              │
│   Every 20 minutes:                                          │
│     • Random active syncer moves to inactive pool            │
│     • Random inactive syncer moves to active pool            │
│     • Pinned syncers are NEVER rotated                       │
│                                                              │
│   Every 1 hour:                                              │
│     • One syncer performs a HISTORICAL SYNC                  │
│     • Catches up on any missed announcements                 │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Timing Constants (discovery/sync_manager.go)

| Constant                         | Value       | Line | Purpose                           |
|----------------------------------|-------------|------|-----------------------------------|
| `DefaultSyncerRotationInterval`  | 20 minutes  | 22   | How often active syncers rotate   |
| `DefaultHistoricalSyncInterval`  | 1 hour      | 27   | How often historical syncs run    |
| `DefaultFilterConcurrency`       | 5           | 31   | Max concurrent filter applications|

📝 **Key Takeaway**
> The SyncManager balances bandwidth efficiency with graph freshness by rotating
> which peers actively send gossip. Pinned syncers ensure critical peers always
> provide real-time updates.

---

## Channel Announcement Proofs

When a new channel is opened, the funding transaction must be **confirmed** on the
blockchain before the channel can be announced to the network.

### DefaultProofMatureDelta

From `discovery/gossiper.go:75-78`:

```go
// DefaultProofMatureDelta is the default number of confirmations
// needed before we process a channel announcement proof.
DefaultProofMatureDelta = 6  // line 75
```

This means: after a channel's funding transaction is mined, both nodes wait for
**6 confirmations** (~1 hour) before exchanging announcement signatures.

### The Proof Exchange Flow

```
  Block N:    Funding TX mined
  Block N+1:  ...waiting...
  Block N+2:  ...waiting...
  Block N+3:  ...waiting...
  Block N+4:  ...waiting...
  Block N+5:  ...waiting...
  Block N+6:  ✅ 6 confirmations reached!
              │
              ▼
  ┌──────────────────────────────────────────────────┐
  │  Node A sends AnnounceSignatures to Node B       │
  │  (contains A's node_sig and A's bitcoin_sig)     │
  └──────────────────────┬───────────────────────────┘
                         │
                         ▼
  ┌──────────────────────────────────────────────────┐
  │  Node B sends AnnounceSignatures to Node A       │
  │  (contains B's node_sig and B's bitcoin_sig)     │
  └──────────────────────┬───────────────────────────┘
                         │
                         ▼
  ┌──────────────────────────────────────────────────┐
  │  Both nodes now have all 4 signatures.           │
  │  They construct the ChannelAnnouncement and      │
  │  broadcast it to the gossip network.             │
  └──────────────────────────────────────────────────┘
```

---

## AssumeChannelValid

The `AssumeChannelValid` flag (`discovery/gossiper.go:392-395`) tells LND to **skip
UTXO validation** when processing channel announcements:

```go
// AssumeChannelValid toggles whether the gossiper should check
// for channel existence by verifying its funding outpoint on-chain.
AssumeChannelValid bool  // line 392
```

### When Is This Used?

- **Neutrino (light client) nodes**: They don't have the full UTXO set and **must**
  use `AssumeChannelValid` because they can't look up arbitrary outputs.
- **Full nodes**: Should **never** set this flag. Without UTXO validation, an attacker
  could announce fake channels backed by spent or nonexistent outputs.

⚠️ **Security Note**
> `AssumeChannelValid` is **dangerous** for full nodes. It skips the cryptographic
> proof that a channel's funding output exists and is unspent. Only use it with
> Neutrino, where UTXO lookup is not available.

---

## SCID Aliases for Privacy

🔰 **For Beginners**

A **Short Channel ID (SCID)** is a compact way to refer to a channel:
`block_height:tx_index:output_index`. For example, `700000:1234:0` means "the channel
funded by the first output of the 1234th transaction in block 700,000."

The problem: this reveals **exactly** which on-chain transaction funds the channel,
linking your on-chain and off-chain activity.

### option-scid-alias

The `option-scid-alias` feature (BOLT-7) lets nodes use a **random alias** instead of
the real SCID when routing. The alias is negotiated between channel partners and has
no relationship to the actual on-chain funding transaction.

From `discovery/gossiper.go`:

```go
// IsAlias checks whether a ShortChannelID is an alias. (line 363)
IsAlias func(scid lnwire.ShortChannelID) bool

// FindBaseByAlias looks up the real SCID from an alias. (line 372)
FindBaseByAlias func(alias lnwire.ShortChannelID) (lnwire.ShortChannelID, error)

// GetAlias returns the peer's alias for a channel. (line 378)
GetAlias func(lnwire.ChannelID) (lnwire.ShortChannelID, error)

// SignAliasUpdate signs a channel update using the alias. (line 367)
SignAliasUpdate func(u *lnwire.ChannelUpdate1) (*ecdsa.Signature, error)
```

```
┌──────────────────────────────────────────────────────────────┐
│                SCID ALIAS PRIVACY                            │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Without alias:                                              │
│    Invoice: "Route via SCID 700000:1234:0"                   │
│    Observer: "I can look up tx 1234 in block 700000          │
│              and see who funded that channel!"               │
│                                                              │
│  With alias:                                                 │
│    Invoice: "Route via SCID 17592186044416"                  │
│    Observer: "That's a random number. I can't trace it       │
│              to any on-chain transaction."                    │
│                                                              │
│  ✅ The alias is only meaningful to the channel partners.    │
│  ✅ Unannounced (private) channels ALWAYS use aliases.       │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

📝 **Key Takeaway**
> SCID aliases break the link between your Lightning channels and on-chain
> transactions. For maximum privacy, use unannounced channels with `option-scid-alias`.

---

## Trickle Broadcasting

LND doesn't broadcast gossip messages immediately. Instead, it **batches** them and
sends them on a timer. This is called **trickle broadcasting**.

### Why Batch?

1. **Bandwidth efficiency**: Sending one large batch is cheaper than many small messages.
2. **Timing analysis prevention**: If LND immediately forwarded every message, an
   observer could correlate timing to determine which node originated a message.

### Implementation

From `discovery/gossiper.go`:

```go
// DefaultSubBatchDelay is the default delay between sub-batches
// of announcements.
DefaultSubBatchDelay = 5 * time.Second  // line 68

// In the Config struct:
TrickleDelay time.Duration  // line 267 — main trickle timer period
SubBatchDelay time.Duration // line 341 — delay between sub-batches
```

The `networkHandler` (line 1482) accumulates announcements and flushes them on each
tick of the `trickleTimer` (line 1492):

```
┌──────────────────────────────────────────────────────────────┐
│              TRICKLE BROADCASTING TIMELINE                    │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Time ──────────────────────────────────────────────►        │
│                                                              │
│  t=0s     Receive ChannelUpdate from peer A                  │
│  t=2s     Receive NodeAnnouncement from peer B               │
│  t=4s     Receive ChannelAnnouncement from peer C            │
│           │                                                  │
│  t=5s     ├── SubBatchDelay expires ──┐                      │
│           │                           ▼                      │
│           │                    ┌──────────────┐              │
│           │                    │ Send batch 1 │              │
│           │                    │ to all peers  │              │
│           │                    └──────────────┘              │
│  t=7s     Receive ChannelUpdate from peer D                  │
│           │                                                  │
│  t=10s    ├── SubBatchDelay expires ──┐                      │
│           │                           ▼                      │
│           │                    ┌──────────────┐              │
│           │                    │ Send batch 2 │              │
│           │                    │ to all peers  │              │
│           │                    └──────────────┘              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

The `delayNextBatch` helper (line 1389-1393) introduces a pause between sub-batches
to spread the network load.

---

## Security Considerations

### 1. Gossip Flooding

🔰 **For Beginners**: A **gossip flood** is when an attacker sends huge volumes of
gossip messages to overwhelm your node's CPU and bandwidth.

**LND's defenses**: Rate limiting (10 updates/min/channel), bandwidth caps (1 MB/s
global, 50 KB/s per peer), and the ban manager (100 points → 48h ban).

### 2. Eclipse Attacks

🔰 **For Beginners**: An **eclipse attack** is when an attacker surrounds your node
with malicious peers, controlling all the information you receive. They can hide
channels, show fake ones, or censor specific routes.

**LND's defenses**: Multiple independent syncer peers, syncer rotation every 20 minutes,
and UTXO validation (ensuring announced channels actually exist on-chain).

### 3. Privacy Leakage via Timing

If LND forwarded messages instantly, an attacker connected to multiple nodes could
determine which node **originated** a message by observing which node forwarded it
first.

**LND's defense**: Trickle broadcasting batches messages, adding random delay between
reception and forwarding.

### 4. In-Memory Bans & Channel Spam

⚠️ **Security Note**
> Bans are lost on restart — an attacker can wait for a restart to resume. Also,
> attackers can open many small channels to flood the graph. UTXO validation ensures
> channels are real, but small legitimate channels can still be used for spam.

---

## Cross-References

- **Chapter 8: Macaroons & RPC Permissions** — Gossip RPCs like `DescribeGraph`
  require `info:read` permission.
- **Chapter 10: Tor Integration & IP Privacy** — Node announcements can include
  `.onion` addresses for privacy.

---

## Exercises

💡 **Exercise 1: Explore the Network Graph**

```bash
lncli getnetworkinfo
lncli describegraph | head -100
lncli getchaninfo --chan_id <short_channel_id>
lncli getnodeinfo --pub_key <node_pubkey>
```

Questions: How many nodes/channels? What's average capacity? Find a Tor node.

💡 **Exercise 2: Trace the Gossip Path**

Open `discovery/gossiper.go` and trace a `ChannelUpdate` from
`ProcessRemoteAnnouncement` (line 890) through validation, rate limiting, and
into the trickle broadcast queue.

💡 **Exercise 3: Understand the Ban Manager**

Read `discovery/ban.go`: What is `peerBanIndex` (line 142)? What happens when
the LRU is full? Design a disk-persistent ban solution with trade-off analysis.

---

## Summary

In this chapter, you learned:

- **Gossip** is how Lightning nodes build a decentralized map of the payment network
- The **AuthenticatedGossiper** (`discovery/gossiper.go:490`) processes all gossip
- Three message types: **ChannelAnnouncement** (4 sigs), **ChannelUpdate** (policy),
  **NodeAnnouncement** (metadata)
- **Rate limiting** operates at per-channel (10/min), global (1 MB/s), and per-peer
  (50 KB/s) levels
- The **ban manager** (`discovery/ban.go`) uses a score-based system (100 → 48h ban)
  but is **in-memory only**
- **SyncManager** rotates active syncers every 20 minutes with hourly historical syncs
- Channel announcement proofs require **6 confirmations** before exchange
- **AssumeChannelValid** skips UTXO checks — only safe for Neutrino light clients
- **SCID aliases** hide the on-chain funding transaction for privacy
- **Trickle broadcasting** batches gossip to prevent timing analysis

Next: [Chapter 10: Tor Integration & IP Privacy →](10-tor-privacy.md)

Previous: [← Chapter 8: Macaroons & RPC Permissions](08-macaroons-rpc.md)
