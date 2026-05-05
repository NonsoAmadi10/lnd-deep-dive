# Chapter 5: HTLCs, Routing & the Switch

> *"The Lightning Network is an onion-routed payment network where every hop
> only knows its immediate neighbors — never the full path."*

---

## Table of Contents

1. [What Is an HTLC?](#what-is-an-htlc)
2. [The Three-Layer Architecture](#the-three-layer-architecture)
3. [Layer 3: ChannelRouter](#layer-3-channelrouter)
4. [Layer 2: The Switch](#layer-2-the-switch)
5. [Layer 1: channelLink](#layer-1-channellink)
6. [Payment Flow: End to End](#payment-flow-end-to-end)
7. [Payment Circuits](#payment-circuits)
8. [Mission Control](#mission-control)
9. [Security Mechanisms](#security-mechanisms)
10. [The Interceptable Switch](#the-interceptable-switch)
11. [Exercises](#-exercises)
12. [Cross-References](#cross-references)

---

## What Is an HTLC?

### 🔰 For Beginners: The Pizza Delivery Analogy

Imagine you order pizza, but the delivery driver doesn't trust you to pay,
and you don't trust them to actually deliver. Here's how an HTLC solves it:

1. You put money in a lockbox that opens with a **secret code**
2. You tell the driver: "Deliver the pizza. The restaurant has the code."
3. The driver delivers, gets the code from the restaurant, opens the lockbox
4. If the driver doesn't deliver within 30 minutes? The lockbox **returns
   your money automatically**

That's an HTLC:
- **Hash**: The locked box (secured by a hash of the secret code)
- **Time**: The 30-minute deadline (after which money returns)
- **Locked**: You can't take the money back early
- **Contract**: Enforced by Bitcoin script, not trust

### Technical Definition

An HTLC (Hash Time-Locked Contract) is a conditional Bitcoin output:

```
IF
    # Payment path: recipient knows the preimage
    OP_SHA256 <payment_hash> OP_EQUALVERIFY
    <receiver_pubkey> OP_CHECKSIG
ELSE
    # Timeout path: sender reclaims after expiry
    <cltv_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <sender_pubkey> OP_CHECKSIG
ENDIF
```

**Two spending paths:**
1. **Preimage reveal**: The receiver knows `preimage` where
   `SHA256(preimage) = payment_hash`. They can claim funds immediately.
2. **Timeout**: After `cltv_expiry` blocks, the sender reclaims the funds.

### Multi-Hop HTLCs

The magic of Lightning is chaining HTLCs across multiple channels:

```
Alice ──HTLC──► Bob ──HTLC──► Carol ──HTLC──► Dave
  │               │               │               │
  │  hash=H       │  hash=H       │  hash=H       │
  │  timeout=40   │  timeout=30   │  timeout=20   │
  │               │               │               │
  │               │               │   Dave knows   │
  │               │               │   preimage!    │
  │               │               │               │
  │               │               │◄── preimage ──│
  │               │◄── preimage ──│               │
  │◄── preimage ──│               │               │
  │               │               │               │
  ▼               ▼               ▼               ▼
 -0.01          ±0.00           ±0.00           +0.01
 (+ fees)       (+ fee)         (+ fee)
```

Notice the **decreasing timeouts**: each hop has a shorter timeout than the
previous one. This ensures that if a downstream hop fails, each upstream
node has time to reclaim their funds before their own HTLC expires.

📝 **Key Takeaway**: HTLCs are the atomic unit of Lightning payments. They
ensure that either the entire multi-hop payment succeeds (everyone gets
paid) or it completely fails (everyone gets refunded). There's no
in-between state.

---

## The Three-Layer Architecture

LND processes payments through three distinct layers, each with a clear
responsibility:

```
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  Layer 3: ChannelRouter (routing/router.go:327)          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  "Where should this payment go?"                   │  │
│  │  • Path finding (Dijkstra's algorithm)             │  │
│  │  • Fee calculation                                 │  │
│  │  • Mission Control (learning from failures)        │  │
│  │  • Graph management                                │  │
│  └──────────────────────┬─────────────────────────────┘  │
│                         │                                │
│  Layer 2: Switch (htlcswitch/switch.go:242)              │
│  ┌──────────────────────▼─────────────────────────────┐  │
│  │  "Route this HTLC to the right channel"            │  │
│  │  • HTLC forwarding between channels                │  │
│  │  • Payment circuit tracking                        │  │
│  │  • Dust threshold enforcement                      │  │
│  │  • Circular route detection                        │  │
│  └──────────────────────┬─────────────────────────────┘  │
│                         │                                │
│  Layer 1: channelLink (htlcswitch/link.go:322)           │
│  ┌──────────────────────▼─────────────────────────────┐  │
│  │  "Apply this HTLC to the channel state machine"    │  │
│  │  • Wire protocol ↔ channel state bridge            │  │
│  │  • Onion decryption (peeling)                      │  │
│  │  • HTLC commitment signing                         │  │
│  │  • Fee/CLTV policy enforcement                     │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Layer 3: ChannelRouter

> **Source**: `routing/router.go:327`

```go
// routing/router.go:327
type ChannelRouter struct {
    started uint32  // atomic flag
    stopped uint32  // atomic flag

    cfg  *Config    // router configuration
    quit chan struct{}
    wg   sync.WaitGroup
}
```

The `ChannelRouter` is the **brain** of payment routing. It maintains the
full channel graph (a map of all public channels in the Lightning Network)
and finds optimal paths for payments.

### Key Responsibilities

1. **Path finding**: Uses a modified Dijkstra's algorithm to find the
   cheapest path from sender to receiver
2. **Graph pruning**: Automatically removes channels from the graph as
   they're closed on-chain
3. **Payment lifecycle**: Manages the entire lifecycle of an outgoing
   payment, including retries with different routes
4. **Mission Control integration**: Learns from failed payment attempts
   to avoid bad nodes and channels in the future

### Payment Initiation

When you send a payment, the flow starts here:

```go
// The user-facing method
router.SendPayment(paymentRequest) →
    // Creates a payment lifecycle
    paymentLifecycle.resumePayment() →
        // Finds a route
        router.FindRoute(target, amount) →
            // Sends HTLC to the Switch
            switch.SendHTLC(firstHop, attemptID, htlc)
```

📝 **Key Takeaway**: The `ChannelRouter` never touches channel state
directly. It finds paths and delegates actual HTLC handling to the Switch.

---

## Layer 2: The Switch

> **Source**: `htlcswitch/switch.go:242`

The Switch is the **heart** of HTLC routing. It sits between the
`ChannelRouter` (which decides *where* to send) and the `channelLink`
(which handles the *how*).

### Key Fields

```go
// htlcswitch/switch.go:242
type Switch struct {
    started  int32   // atomic lifecycle flag
    shutdown int32   // atomic shutdown flag

    // bestHeight is the best known height of the main chain.
    bestHeight int32  // accessed atomically

    cfg *Config

    // networkResults stores the outcome of user-initiated payments.
    networkResults *networkResultStore

    // circuits is the payment circuit storage — tracks in-flight
    // HTLCs for crash recovery.
    circuits CircuitMap
}
```

### How the Switch Routes Packets

The central routing method is `handlePacketForward`:

> **Source**: `htlcswitch/switch.go:1126`

```go
func (s *Switch) handlePacketForward(packet *htlcPacket) error
```

This method dispatches packets based on their type:

```
┌─────────────────────────────────────────────────┐
│            handlePacketForward                   │
│                                                 │
│  Incoming packet                                │
│       │                                         │
│       ├── UpdateAddHTLC?                        │
│       │   ├── Check circular forward            │
│       │   ├── Check dust threshold              │
│       │   ├── Create payment circuit             │
│       │   └── Forward to outgoing link          │
│       │                                         │
│       ├── UpdateFulfillHTLC?                    │
│       │   ├── Look up circuit by circuit key    │
│       │   ├── Close the circuit                 │
│       │   └── Forward settle to incoming link   │
│       │                                         │
│       └── UpdateFailHTLC?                       │
│           ├── Look up circuit by circuit key    │
│           ├── Close the circuit                 │
│           └── Forward fail to incoming link     │
│                                                 │
└─────────────────────────────────────────────────┘
```

### SendHTLC — The Entry Point

> **Source**: `htlcswitch/switch.go:547`

```go
func (s *Switch) SendHTLC(
    firstHop lnwire.ShortChannelID,
    attemptID uint64,
    htlc *lnwire.UpdateAddHTLC,
) error
```

This is called by the `ChannelRouter` to inject a new outgoing HTLC into
the network. The Switch:

1. Looks up the `channelLink` for `firstHop`
2. Queues the HTLC packet for that link
3. The link processes it asynchronously via its mailbox

---

## Layer 1: channelLink

> **Source**: `htlcswitch/link.go:322`

```go
// htlcswitch/link.go:322
type channelLink struct {
    started      int32  // atomic
    reestablished int32 // atomic — set after channel_reestablish
    shutdown     int32  // atomic
    failed       bool   // indicates link error

    // keystoneBatch holds circuit keystones to write before
    // signing the next commitment.
    keystoneBatch []Keystone

    // openedCircuits tracks circuits opened in current update.
    openedCircuits []CircuitKey

    // closedCircuits tracks circuits closed in current update.
    closedCircuits []CircuitKey
}
```

The `channelLink` is the bridge between the Lightning wire protocol and
the channel state machine (from [Chapter 4](04-channels-commitments.md)).

### Onion Peeling — processRemoteAdds

> **Source**: `htlcswitch/link.go:2964`

```go
func (l *channelLink) processRemoteAdds(fwdPkg *channeldb.FwdPkg)
```

When an HTLC arrives from a remote peer, `processRemoteAdds` is where
the **onion routing** magic happens:

```
┌───────────────────────────────────────────────────┐
│              processRemoteAdds                     │
│                                                   │
│  1. Receive encrypted onion blob                  │
│                                                   │
│  2. Decrypt outer layer (peel the onion)          │
│     ┌─────────────────────────────────────┐       │
│     │  Onion Packet (1300 bytes)          │       │
│     │  ┌───────────┐                     │       │
│     │  │ Our Layer │ next_hop, amt, cltv  │       │
│     │  ├───────────┤                     │       │
│     │  │ Encrypted │ for next hop        │       │
│     │  │ remaining │                     │       │
│     │  │ layers    │                     │       │
│     │  └───────────┘                     │       │
│     └─────────────────────────────────────┘       │
│                                                   │
│  3. Validate: fees sufficient? CLTV ok?           │
│                                                   │
│  4. Decision:                                     │
│     ├── Final hop? → Settle (we're the payee)     │
│     └── Intermediate? → Forward to Switch          │
│                                                   │
└───────────────────────────────────────────────────┘
```

### 🔰 For Beginners: What Is Onion Routing?

Imagine sending a letter through a chain of friends. You put the letter in
an envelope addressed to Dave. You put THAT envelope inside another
envelope addressed to Carol. And THAT inside one addressed to Bob.

```
┌─────────────────────────────────────────┐
│  To: Bob                                │
│  ┌───────────────────────────────────┐  │
│  │  To: Carol                        │  │
│  │  ┌─────────────────────────────┐  │  │
│  │  │  To: Dave                    │  │  │
│  │  │  ┌───────────────────────┐  │  │  │
│  │  │  │  "Here's 0.01 BTC"   │  │  │  │
│  │  │  └───────────────────────┘  │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

Each friend peels off their layer and forwards the rest. Bob knows Alice
sent it and that Carol is next, but **Bob doesn't know Dave is the final
recipient**. This is onion routing — each hop only sees one layer.

In Lightning, the "envelopes" are encrypted with each hop's public key
using the Sphinx protocol. The onion packet is always 1300 bytes regardless
of path length, preventing size-based correlation attacks.

---

## Payment Flow: End to End

Here's the complete journey of a payment through all three layers:

```
User: "Pay invoice lnbc10n1..."
         │
         ▼
┌─ ChannelRouter ──────────────────────────────────┐
│  1. Decode payment request                        │
│  2. FindRoute() — Dijkstra through channel graph  │
│  3. Construct onion packet (Sphinx)               │
│  4. Create UpdateAddHTLC message                  │
│  5. Call Switch.SendHTLC(firstHop, htlc)          │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼
┌─ Switch ─────────────────────────────────────────┐
│  6. Look up channelLink for firstHop             │
│  7. Check dust threshold                          │
│  8. Check circular forward                        │
│  9. Create payment circuit                        │
│ 10. Queue packet to link's mailbox               │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼
┌─ channelLink ────────────────────────────────────┐
│ 11. Add HTLC to channel state (Chapter 4)        │
│ 12. SignNextCommitment() — sign new state         │
│ 13. Send commit_sig to peer                       │
│ 14. Receive revoke_and_ack from peer              │
│ 15. HTLC is now irrevocably committed             │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼
              Wire protocol to next hop
              (peer's channelLink receives it)
```

### The Return Path (Settlement)

When the final recipient reveals the preimage:

```
Dave (final hop)                 Carol              Bob               Alice
     │                            │                  │                  │
     │  UpdateFulfillHTLC         │                  │                  │
     │  (preimage)                │                  │                  │
     │ ──────────────────────►   │                  │                  │
     │                            │                  │                  │
     │              channelLink receives fulfill     │                  │
     │              Switch looks up circuit           │                  │
     │              Forwards to incoming link         │                  │
     │                            │                  │                  │
     │                            │  UpdateFulfill   │                  │
     │                            │ ───────────────►│                  │
     │                            │                  │                  │
     │                            │                  │  UpdateFulfill   │
     │                            │                  │ ───────────────►│
     │                            │                  │                  │
     │                            │                  │          Payment │
     │                            │                  │          complete│
     ▼                            ▼                  ▼                  ▼
```

---

## Payment Circuits

Payment circuits are how LND tracks in-flight HTLCs and ensures crash
recovery works correctly.

### What Is a Circuit?

A circuit maps an **incoming** HTLC to its **outgoing** HTLC:

```
Incoming Channel        Switch         Outgoing Channel
     │                   │                    │
     │  HTLC #42        │                    │
     │ ───────────────► │                    │
     │                   │  HTLC #17         │
     │                   │ ──────────────►   │
     │                   │                    │
     │    Circuit: (incoming_chan, 42) ↔ (outgoing_chan, 17)
     │                   │                    │
     │  Fulfill #42      │                    │
     │ ◄─────────────── │  Fulfill #17       │
     │                   │ ◄──────────────── │
     │                   │                    │
     │    Circuit closed                      │
     ▼                   ▼                    ▼
```

### Why Circuits Are Critical

If LND crashes mid-payment, circuits let it recover:

1. On restart, LND reads all open circuits from disk
2. For each circuit, it knows which incoming HTLC maps to which outgoing HTLC
3. When the outgoing HTLC settles or fails, LND can forward the result
   back to the correct incoming channel

⚠️ **Security Note**: Circuits are persisted to disk before the HTLC is
forwarded. This ensures that even a crash between forwarding and receiving
a response won't cause funds to be lost or stuck.

---

## Mission Control

> **Source**: `routing/` package

Mission Control is LND's payment intelligence system. It learns from
failed payment attempts and adjusts future routing decisions.

### How It Works

```
Payment attempt #1: Alice → Bob → Carol → Dave
                         ✗ (Carol → Dave failed)

Mission Control records:
  "Carol → Dave: failed at 2024-01-15 10:30:00
   Reason: insufficient capacity"

Payment attempt #2: Alice → Bob → Eve → Dave
                         ✓ (success!)

Mission Control records:
  "Bob → Eve → Dave: succeeded with 10,000 sats"
```

### Estimator Models

LND uses two probability estimators:

1. **A priori estimator**: Base probability of success for a node/channel
   pair, decaying over time (old failures matter less)

2. **Bimodal estimator**: Models channel liquidity as a probability
   distribution. Assumes liquidity is more likely at the extremes (mostly
   full or mostly empty) than in the middle.

📝 **Key Takeaway**: Mission Control prevents LND from repeatedly trying
routes that are known to fail. It maintains a probabilistic map of the
network's actual capacity, not just its advertised capacity.

---

## Security Mechanisms

### 1. Dust Fee Exposure Check

> **Source**: `htlcswitch/switch.go:2577`

```go
func (s *Switch) dustExceedsFeeThreshold(
    link ChannelLink,
    amount lnwire.MilliSatoshi,
    incoming bool,
) bool
```

### 🔰 For Beginners: What Is Dust?

In Bitcoin, a "dust" output is one so small that it costs more in fees to
spend than it's worth. In Lightning, dust HTLCs are excluded from
the commitment transaction — they become part of the miner fee.

**The attack**: An adversary opens a channel and floods it with thousands of
tiny (dust) HTLCs. Each one isn't on the commitment transaction, but
collectively they inflate the fee the honest party would pay if they had
to force-close.

```
Normal commitment TX fee:     500 sats
With 1000 dust HTLCs:     500,000 sats  ← 1000x more expensive!
```

LND's defense: `dustExceedsFeeThreshold` checks the total dust exposure
(including HTLCs queued in the mailbox) and rejects new dust HTLCs if the
threshold is exceeded.

⚠️ **Security Note**: This check considers both on-chain dust (HTLCs
already in the commitment) AND mailbox dust (HTLCs queued but not yet
committed). An attacker could try to bypass the on-chain check by queuing
HTLCs faster than they're committed.

---

### 2. Circular Forward Detection

> **Source**: `htlcswitch/switch.go:1151`

```go
func (s *Switch) checkCircularForward(
    incoming, outgoing lnwire.ShortChannelID,
    allowCircular bool,
    paymentHash lntypes.Hash,
) *LinkError
```

A **circular forward** is when an HTLC arrives on one of your channels and
is forwarded right back out the same channel (or to the same peer on a
different channel).

```
Circular forward:
  Peer A ──HTLC──► Your Node ──HTLC──► Peer A
                     (same peer!)
```

**Why block it?** Circular forwards can be used for probing attacks (an
attacker learns your channel balances) or fee-free rebalancing at your
expense. By default, LND blocks circular forwards unless explicitly
allowed.

---

### 3. CLTV Expiry Limits

```go
// htlcswitch/link.go
// Maximum number of blocks an outgoing HTLC can be locked for.
const DefaultMaxOutgoingCltvExpiry = 2016
```

### 🔰 For Beginners: What Is CLTV?

**CLTV** (CheckLockTimeVerify) is a Bitcoin script opcode that prevents an
output from being spent until a certain block height. In Lightning, CLTV
is used for HTLC timeouts.

If the CLTV expiry is too far in the future, your funds could be locked for
weeks or months while waiting for a timeout. LND caps outgoing HTLCs at
2016 blocks (~2 weeks) to limit this exposure.

```
CLTV too high = funds locked too long
CLTV too low  = not enough time to settle

LND default: max 2016 blocks ≈ 14 days
```

---

### 4. Mailbox Delivery Timeout

```go
// htlcswitch/switch.go
// HTLCs expire from the mailbox after 1 minute.
const DefaultMailboxDeliveryTimeout = time.Minute
```

If an HTLC sits in a channel link's mailbox for more than 1 minute without
being processed, it's automatically failed. This prevents resource
exhaustion from slow or unresponsive peers.

---

## The Interceptable Switch

> **Source**: `htlcswitch/interceptable_switch.go`

The `InterceptableSwitch` is a proxy that wraps the regular `Switch` and
allows external services to **intercept** forwarded HTLCs before they're
processed.

```go
type InterceptableSwitch struct {
    // htlcSwitch is the underlying Switch.
    htlcSwitch *Switch

    // intercepted streams intercepted packets to the handler.
    intercepted chan *interceptedPackets

    // resolutionChan receives responses from the interceptor.
    resolutionChan chan *fwdResolution

    // interceptor is the current HTLC interceptor handler.
    interceptor ForwardInterceptor

    // heldHtlcSet tracks outstanding intercepted forwards.
    heldHtlcSet map[CircuitKey]InterceptedForward
}
```

### Three Resolution Options

When an HTLC is intercepted, the external service can:

```
┌──────────────────────────────────────────────┐
│         Intercepted HTLC                      │
│                │                              │
│    ┌───────────┼───────────┐                  │
│    │           │           │                  │
│    ▼           ▼           ▼                  │
│  Resume     Settle       Fail                 │
│  (forward   (provide     (reject with         │
│   as-is)    preimage)    error)               │
│                                               │
│  Use case:  Use case:   Use case:             │
│  Logging,   Hold        Rate                  │
│  monitoring invoices,   limiting,             │
│             LSPs        compliance            │
└──────────────────────────────────────────────┘
```

### Use Cases

1. **Hold invoices**: An LSP intercepts HTLCs and holds them until a
   mobile client comes online to claim them
2. **Just-in-time channels**: An LSP intercepts an HTLC, opens a channel
   to the recipient on-the-fly, then forwards the payment
3. **Compliance**: Intercept and reject payments that violate policies
4. **Analytics**: Log all forwarded payments for business intelligence

📝 **Key Takeaway**: The `InterceptableSwitch` is what makes LND extensible
for Lightning Service Providers (LSPs). Without it, all HTLC handling would
be fully automatic with no room for business logic.

---

## 💡 Exercises

### Exercise 1: Trace a Payment

Using `htlcswitch/switch.go`, trace the path of a payment:

1. Find `SendHTLC` (line 547). What does it do with the `firstHop`?
2. Follow the packet to `handlePacketForward` (line 1126). How does it
   decide where to send an `UpdateAddHTLC`?
3. What happens when a `UpdateFulfillHTLC` arrives? How is the circuit
   resolved?

### Exercise 2: Understand Dust Protection

1. Read `dustExceedsFeeThreshold` (switch.go:2577)
2. Calculate: if dust limit is 546 sats and fee rate is 25 sat/vbyte,
   what's the maximum number of dust HTLCs before the threshold is hit?
3. Why does the check include mailbox dust, not just committed dust?

### Exercise 3: Onion Routing Privacy

Consider a 4-hop payment path (A → B → C → D):

1. What does node B know about the payment?
2. What does node B NOT know?
3. How does the fixed 1300-byte onion size help privacy?
4. What would happen if the onion shrank with each hop?

### Exercise 4: Build a Mental Model

Draw your own diagram of the three-layer architecture:

1. For a locally-initiated payment (you → someone else)
2. For a forwarded payment (someone → you → someone else)
3. For a received payment (someone → you, final hop)

How do the layers interact differently in each case?

### Exercise 5: Mission Control Simulation

Imagine a network with 5 nodes (A-E) and the following channels:

```
A──B (1M sats capacity)
A──C (500K sats capacity)
B──D (200K sats capacity)
C──D (800K sats capacity)
D──E (1M sats capacity)
```

1. You want to send 300K sats from A to E. What route does Dijkstra find?
2. The payment fails at B→D (insufficient capacity). How does Mission
   Control adjust?
3. What route is tried next?

---

## Cross-References

- **Chapter 4**: [Channels & Commitment Transactions](04-channels-commitments.md) —
  How HTLCs are added to commitment transactions
- **Chapter 6**: [Watchtowers](06-watchtowers.md) — What happens when a
  channel with active HTLCs is breached
- **Chapter 7**: [Channel Backups (SCB)](07-channel-backups.md) — Recovery
  when circuit data is lost

---

*Next: [Chapter 6 — Watchtowers →](06-watchtowers.md)*
