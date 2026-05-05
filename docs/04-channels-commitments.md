# Chapter 4: Channels & Commitment Transactions

> *"A payment channel is a relationship between two parties, secured by Bitcoin
> script, where each party holds a constantly-updated IOU backed by real
> Bitcoin."*

---

## Table of Contents

1. [What Is a Payment Channel?](#what-is-a-payment-channel)
2. [The Commitment Struct](#the-commitment-struct)
3. [The State Machine — Four Critical Methods](#the-state-machine--four-critical-methods)
4. [Shachain: O(log N) Revocation Storage](#shachain-olog-n-revocation-storage)
5. [Breach Detection & Justice Transactions](#breach-detection--justice-transactions)
6. [Data Loss Detection](#data-loss-detection)
7. [Funding Flow](#funding-flow)
8. [Exercises](#-exercises)
9. [Cross-References](#cross-references)

---

## What Is a Payment Channel?

### 🔰 For Beginners

Imagine you and a friend buy a pizza together every Friday. Instead of
exchanging Bitcoin on-chain every week (slow, expensive), you could:

1. Lock $100 worth of Bitcoin into a shared safe (a **2-of-2 multisig**)
2. Keep a shared notebook where you track who owes what
3. Every Friday, update the notebook: "Alice: $80, Bob: $20"
4. When you're done, open the safe and split the money per the notebook

That shared safe is the **funding transaction**. The notebook is the
**commitment transaction**. The Lightning Network automates this with
cryptography.

### The Technical Picture

A payment channel is a **2-of-2 multisig output** on the Bitcoin blockchain.
Both parties must cooperate to spend from it. Off-chain, they exchange
**commitment transactions** — pre-signed Bitcoin transactions that can be
broadcast at any time to settle the channel on-chain.

```
┌─────────────────────────────────────────────────────┐
│                 BITCOIN BLOCKCHAIN                   │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │         Funding Transaction                   │  │
│  │  Output: 2-of-2 multisig(Alice, Bob)          │  │
│  │  Value:  1.0 BTC                              │  │
│  └───────────────────────────────────────────────┘  │
│                         │                           │
│            ┌────────────┴────────────┐              │
│            │     OFF-CHAIN ONLY      │              │
│            │                         │              │
│   ┌────────▼─────────┐  ┌───────────▼──────────┐   │
│   │ Alice's Commit TX │  │  Bob's Commit TX     │   │
│   │ Alice: 0.7 BTC    │  │  Alice: 0.7 BTC      │   │
│   │ Bob:   0.3 BTC    │  │  Bob:   0.3 BTC      │   │
│   │ (to-self delayed) │  │  (to-self delayed)   │   │
│   └──────────────────┘  └──────────────────────┘   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

Each party holds **their own version** of the commitment transaction. The key
asymmetry: your own output is **time-locked** (you must wait N blocks to
spend it), but your counterparty's output is immediately spendable. This
asymmetry enables the punishment mechanism.

### Why Two Versions?

If Alice broadcasts her commitment transaction, her output is delayed (say,
144 blocks). During that delay, Bob can check: "Is this the latest state?"
If Alice broadcast an **old** state — one she already revoked — Bob can use
the revocation key to sweep **all** funds immediately. This is the
**justice transaction**.

📝 **Key Takeaway**: Payment channels work because broadcasting an old
state is punishable. The honest party can take *all* funds if their
counterparty cheats.

---

## The Commitment Struct

> **Source**: `lnwallet/channel.go:181-249`

The `commitment` struct is the in-memory representation of a single commitment
state. Every time the channel updates (a payment is added, fulfilled, or
failed), a new `commitment` is created.

```go
// lnwallet/channel.go:181
type commitment struct {
    // height is the commitment height — essentially the update number.
    height uint64

    // whoseCommit indicates whether this is the local or remote
    // node's version of the commitment.
    whoseCommit lntypes.ChannelParty

    // messageIndices holds the log index for both parties at this
    // point in the commitment chain.
    messageIndices lntypes.Dual[uint64]

    // ourHtlcIndex is a running counter of our proposed HTLCs.
    ourHtlcIndex  uint64
    theirHtlcIndex uint64

    // txn is the actual commitment transaction.
    txn *wire.MsgTx

    // sig is the signature for the commitment transaction.
    sig []byte

    // ourBalance and theirBalance are the settled balances at
    // this point, excluding any pending HTLCs.
    ourBalance   lnwire.MilliSatoshi
    theirBalance lnwire.MilliSatoshi

    // fee is the total fee for this commitment.
    fee     btcutil.Amount
    feePerKw chainfee.SatPerKWeight

    // dustLimit is the minimum HTLC value for inclusion.
    dustLimit btcutil.Amount

    // outgoingHTLCs and incomingHTLCs are the active HTLCs on
    // this particular commitment.
    outgoingHTLCs []paymentDescriptor
    incomingHTLCs []paymentDescriptor

    // customBlob is optional opaque data for custom channels.
    customBlob fn.Option[tlv.Blob]
}
```

### Field-by-Field Breakdown

| Field | Type | Purpose |
|-------|------|---------|
| `height` | `uint64` | Sequential counter. Commitment #0 is the funding state. |
| `whoseCommit` | `ChannelParty` | `Local` or `Remote` — whose view is this? |
| `messageIndices` | `Dual[uint64]` | Log positions for both parties' HTLC logs |
| `txn` | `*wire.MsgTx` | The Bitcoin transaction itself |
| `sig` | `[]byte` | Counterparty's signature on this commitment |
| `ourBalance` | `MilliSatoshi` | Our side's balance (in milli-satoshis) |
| `theirBalance` | `MilliSatoshi` | Their side's balance |
| `fee` | `Amount` | Total commitment tx fee in satoshis |
| `dustLimit` | `Amount` | Outputs below this are "dust" and omitted |
| `outgoingHTLCs` | `[]paymentDescriptor` | HTLCs we offered |
| `incomingHTLCs` | `[]paymentDescriptor` | HTLCs offered to us |

### 🔰 For Beginners: What Is Dust?

In Bitcoin, every output must be large enough to be economically spendable.
If an HTLC is worth less than the transaction fee to claim it, it's called
**dust**. Dust outputs are excluded from the commitment transaction — they
effectively become part of the mining fee.

⚠️ **Security Note**: Dust exposure is a real attack vector. An attacker
could flood a channel with tiny HTLCs, inflating the commitment transaction
fee. LND tracks dust exposure carefully (see Chapter 5 for
`dustExceedsFeeThreshold`).

---

## The State Machine — Four Critical Methods

The Lightning channel state machine is driven by exactly **four methods**.
They form a strict sequence that must be followed for every state update:

```
  Alice                          Bob
    │                              │
    │  1. SignNextCommitment()     │
    │  ──── commit_sig ──────────►│
    │                              │ 2. ReceiveNewCommitment()
    │                              │
    │  3. RevokeCurrentCommitment()│
    │  ◄──── revoke_and_ack ──────│
    │                              │
    │  4. ReceiveRevocation()      │
    │                              │
    │        (roles swap)          │
    │                              │
    │  1. SignNextCommitment()     │
    │  ◄──── commit_sig ──────────│
    │                              │
    │  2. ReceiveNewCommitment()   │
    │                              │
    │  3. RevokeCurrentCommitment()│
    │  ──── revoke_and_ack ──────►│
    │                              │
    │                              │ 4. ReceiveRevocation()
    ▼                              ▼
```

### Method 1: `SignNextCommitment` — Propose New State

> **Source**: `lnwallet/channel.go:4125`

```go
func (lc *LightningChannel) SignNextCommitment(
    ctx context.Context,
) (*NewCommitState, error)
```

**What it does:**

1. Evaluates all pending HTLCs (adds, settles, fails) from both parties' logs
2. Constructs the **next** commitment transaction for the remote party
3. Signs the commitment transaction with our funding key
4. Signs each HTLC output individually (for second-level HTLC transactions)
5. Returns a `NewCommitState` containing the commitment signature, HTLC
   signatures, and pending HTLCs

**Why it matters:** This is how we *propose* a state transition. We're saying
"here's what I think the next state should look like, and here's my
signature proving I agree to it."

```
┌──────────────────────────────────────────┐
│         SignNextCommitment Flow          │
│                                          │
│  1. Gather pending updates from logs     │
│                  │                       │
│                  ▼                       │
│  2. Build remote party's next commit TX  │
│                  │                       │
│                  ▼                       │
│  3. Sign commit TX with funding key      │
│                  │                       │
│                  ▼                       │
│  4. Sign each HTLC output individually   │
│                  │                       │
│                  ▼                       │
│  5. Return NewCommitState                │
│     (commitSig + htlcSigs + pendingHTLCs)│
└──────────────────────────────────────────┘
```

📝 **Key Takeaway**: `SignNextCommitment` decrements the available revocation
window by 1. If the window is exhausted, you must wait for a revocation
before signing another commitment.

---

### Method 2: `ReceiveNewCommitment` — Validate Partner's Proposal

> **Source**: `lnwallet/channel.go:5363`

```go
func (lc *LightningChannel) ReceiveNewCommitment(
    commitSigs *CommitSigs,
) error
```

**What it does:**

1. Receives the counterparty's proposed commitment signature
2. Independently constructs what the commitment *should* look like
3. Verifies the signature against the expected commitment transaction
4. Verifies each HTLC signature
5. If everything checks out, extends our local commitment chain

**Critical validation**: We *never* trust the counterparty's transaction
directly. We reconstruct it ourselves and verify their signature matches.
This prevents a malicious counterparty from sneaking in a bad state.

⚠️ **Security Note**: If signature verification fails, the channel is
immediately force-closed. A bad signature means either a bug or an attack —
either way, we cannot continue operating the channel safely.

---

### Method 3: `RevokeCurrentCommitment` — Revoke Old State

> **Source**: `lnwallet/channel.go:5786`

```go
func (lc *LightningChannel) RevokeCurrentCommitment() (
    *lnwire.RevokeAndAck,
    []channeldb.HTLC,
    map[uint64]bool,
    error,
)
```

**What it does:**

1. Takes the current (now old) commitment and generates a **revocation**
2. The revocation contains the secret key that would let the counterparty
   punish us if we ever broadcast this old state
3. Advances our commitment state to the newly received one
4. Returns the `RevokeAndAck` message, active HTLCs, and resolved HTLCs

### 🔰 For Beginners: What Does "Revoking" Mean?

When you revoke a commitment, you're giving your counterparty a secret key.
If you ever broadcast the revoked commitment (cheating!), they can use that
key to take **all** the money in the channel. It's like handing someone the
combination to a safe and saying: "If I ever lie, you can open this safe
and take everything."

```
Revocation = "I promise to never broadcast this old state.
              Here's the proof that would let you punish me
              if I break that promise."
```

---

### Method 4: `ReceiveRevocation` — Accept Partner's Revocation

> **Source**: `lnwallet/channel.go:5888`

```go
func (lc *LightningChannel) ReceiveRevocation(
    revMsg *lnwire.RevokeAndAck,
) (*channeldb.FwdPkg, []channeldb.HTLC, error)
```

**What it does:**

1. Receives the counterparty's revocation of their old commitment
2. Verifies the revocation secret is correct for that commitment height
3. Stores the revocation in the **shachain** (see next section)
4. Advances the remote commitment chain
5. Compacts the HTLC log — removes entries that are fully settled
6. Returns a `FwdPkg` (forwarding package) for the revoked height

**Why the forwarding package matters:** HTLCs can only be safely forwarded
to the next hop *after* the previous state has been revoked. The `FwdPkg`
contains the HTLCs that are now irrevocably locked in, ready for forwarding.

📝 **Key Takeaway**: The four methods form an atomic update protocol. A
state update is only "final" after both sides have signed the new state
AND revoked the old one. This requires a full round-trip of messages.

---

## Shachain: O(log N) Revocation Storage

> **Source**: `shachain/store.go:12-55`

### The Problem

Every state update produces a revocation secret. After 10 million updates,
you'd need to store 10 million 32-byte secrets = 320 MB. For a busy
channel, this adds up fast.

### The Brilliant Solution

The **shachain** (SHA-chain) is a data structure that stores N secrets using
only O(log N) space. It exploits a binary tree structure where each secret
can be derived from its parent using SHA-256.

```
                    Root Secret
                   /            \
              SHA256(root||0)   SHA256(root||1)
              /          \        /          \
         s[0]          s[1]   s[2]          s[3]
```

```go
// shachain/store.go:12
type Store interface {
    // LookUp retrieves a previously stored secret by index.
    LookUp(uint64) (*chainhash.Hash, error)

    // AddNextEntry stores the next secret in the chain.
    AddNextEntry(*chainhash.Hash) error

    // Encode serializes the store to a writer.
    Encode(io.Writer) error
}
```

The primary implementation is `RevocationStore` (line 43), which uses
**buckets** for efficient derivation:

```go
// shachain/store.go:43
type RevocationStore struct {
    // buckets stores the minimal set of secrets needed to
    // derive all previous secrets.
    buckets [maxHeight]element

    // lenBuckets tracks how many buckets are currently in use.
    lenBuckets uint8

    // index tracks the current position in the chain.
    index index
}
```

### How It Works (Simplified)

Think of it like a family tree. If I give you the grandparent, you can
derive all grandchildren. But if I only give you a grandchild, you can't
go back up. The shachain exploits this:

```
Secret #7:  ████████  (store directly — it's a leaf)
Secret #6:  ████████  (derive from a stored ancestor)
Secret #5:  ████████  (derive from a stored ancestor)
Secret #4:  ████████  (store — it's a new branch point)
...

After 1024 secrets, only ~10 values stored (log2(1024) = 10)
```

📝 **Key Takeaway**: The shachain lets LND handle millions of state updates
without running out of storage. Each new revocation might replace an old
bucket, keeping memory constant at O(log N).

---

## Breach Detection & Justice Transactions

> **Source**: `contractcourt/breach_arbitrator.go`

### 🔰 For Beginners: What Is a Breach?

A **breach** happens when your counterparty broadcasts an old, revoked
commitment transaction. They're trying to steal money by reverting the
channel to a previous state (where they had more funds). When LND detects
this, it constructs a **justice transaction** to punish the cheater by
sweeping ALL funds.

### Key Constants

```go
// contractcourt/breach_arbitrator.go:36
// Justice transactions should confirm within 2 blocks.
// This is aggressive because time is of the essence — the
// cheater's output has a CSV delay, and we must sweep before
// they can spend it.
const justiceTxConfTarget = 2

// contractcourt/breach_arbitrator.go:42
// If the justice TX hasn't confirmed after 4 blocks, split
// it into smaller transactions to defeat HTLC pinning attacks.
const blocksPassedSplitPublish = 4
```

### The Anti-Pinning Strategy

```
Block 0: Breach detected! Broadcast full justice TX
         (sweeps ALL outputs in one transaction)
              │
              ▼
Block 1: Still unconfirmed? Bump fee (RBF)
              │
              ▼
Block 2: Still unconfirmed? Bump fee again
              │
              ▼
Block 3: Still unconfirmed? Getting worried...
              │
              ▼
Block 4: *** SPLIT PUBLISH ***
         Break into smaller TXs, one per output.
         This defeats HTLC pinning attacks where
         the cheater adds conflicting HTLC spends
         to prevent the full justice TX from confirming.
```

### 🔰 For Beginners: What Are Pinning Attacks?

An attacker broadcasts a revoked commitment and simultaneously spends
some HTLC outputs with low-fee transactions. These low-fee transactions
"pin" the justice transaction: it can't confirm because it conflicts with
the low-fee HTLC spends, but Bitcoin miners won't replace the low-fee
transactions either (due to RBF rules).

LND's defense: after 4 blocks (`blocksPassedSplitPublish`), split the
justice transaction into individual sweeps. Each output gets its own
transaction, so one pinned HTLC can't block the sweep of other outputs.

⚠️ **Security Note**: The `justiceTxConfTarget=2` is deliberately
aggressive. In a breach scenario, every block that passes gives the
cheater more opportunity to exploit the situation. LND uses high fees
to ensure rapid confirmation.

---

## Data Loss Detection

> **Source**: `lnwallet/channel.go:146-168`

What happens if your node crashes and you lose some state? LND's
**Data Loss Protection (DLP)** protocol handles this gracefully.

```go
// lnwallet/channel.go:146
type ErrCommitSyncLocalDataLoss struct {
    // ChannelPoint is the identifier for the channel that
    // experienced data loss.
    ChannelPoint wire.OutPoint

    // CommitPoint is the last unrevoked commitment point
    // received from the remote party.
    CommitPoint *btcec.PublicKey
}
```

### How DLP Works

When two nodes reconnect, they exchange `channel_reestablish` messages
containing their latest commitment heights. If the remote node's height
is *higher* than ours, we've lost data:

```
Alice (data loss victim)         Bob
    │                              │
    │  channel_reestablish         │
    │  "my height: 100"            │
    │  ─────────────────────────► │
    │                              │
    │  channel_reestablish         │
    │  "my height: 150,            │
    │   here's commit_point"       │
    │  ◄───────────────────────── │
    │                              │
    │  Alice detects: 150 > 100    │
    │  → ErrCommitSyncLocalDataLoss│
    │                              │
    │  Alice asks Bob to           │
    │  force-close with latest     │
    │  state (which favors Alice   │
    │  since it's newer)           │
    ▼                              ▼
```

📝 **Key Takeaway**: DLP ensures that even if you lose your database, your
counterparty can force-close with the latest state. You won't get the
absolute best outcome (you lose any in-flight HTLCs), but you won't lose
your settled balance. See [Chapter 7](07-channel-backups.md) for how SCB
backups leverage DLP.

---

## Funding Flow

> **Source**: `funding/` package

Opening a channel involves a careful multi-step negotiation:

```
  Initiator (Alice)                  Responder (Bob)
       │                                  │
  1.   │  ──── open_channel ───────────► │
       │       (proposed params)          │
       │                                  │
  2.   │  ◄─── accept_channel ────────── │
       │       (accepted params)          │
       │                                  │
  3.   │  Create funding TX               │
       │  (2-of-2 multisig output)        │
       │                                  │
  4.   │  ──── funding_created ────────► │
       │       (funding txid + sig)       │
       │                                  │
  5.   │  ◄─── funding_signed ─────────  │
       │       (counterparty sig)         │
       │                                  │
  6.   │  Broadcast funding TX            │
       │  Wait for confirmations...       │
       │                                  │
  7.   │  ──── channel_ready ──────────► │
       │  ◄─── channel_ready ──────────  │
       │                                  │
       │  ✅ Channel is now open!         │
       ▼                                  ▼
```

### Critical Safety Measure

Notice step 4: Alice sends Bob the funding transaction ID and her signature
*before* broadcasting the funding TX. Bob signs the initial commitment
transaction first. This ensures that both parties have a valid commitment
transaction *before* any money is locked up.

If the funding TX were broadcast first, Bob could refuse to sign, and
Alice's funds would be stuck in a 2-of-2 multisig forever.

⚠️ **Security Note**: The `funding/` package enforces minimum channel sizes,
maximum pending channel limits, and reserve requirements. These protect
against resource exhaustion attacks where a malicious peer opens thousands
of tiny channels.

---

## Commitment Transaction Structure

A commitment transaction has a specific structure designed for the
punishment mechanism:

```
┌─────────────────────────────────────────────────────────┐
│              COMMITMENT TRANSACTION                      │
│                                                         │
│  Input:                                                 │
│    └─ Funding Output (2-of-2 multisig)                  │
│                                                         │
│  Outputs (BIP 69 sorted):                               │
│    ├─ to_local: OP_IF                                   │
│    │     <revocation_pubkey> OP_CHECKSIG                │
│    │   OP_ELSE                                          │
│    │     <to_self_delay> OP_CSV OP_DROP                 │
│    │     <local_delayed_pubkey> OP_CHECKSIG             │
│    │   OP_ENDIF                                         │
│    │                                                    │
│    ├─ to_remote: <remote_pubkey> OP_CHECKSIG            │
│    │   (immediately spendable by remote party)          │
│    │                                                    │
│    ├─ HTLC #1: (offered or received)                    │
│    │   Complex script with hash preimage + timeout      │
│    │                                                    │
│    ├─ HTLC #2: ...                                      │
│    │                                                    │
│    └─ (anchor outputs for fee bumping, if enabled)      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 🔰 For Beginners: Reading the Script

The `to_local` output has two spending paths:

1. **Revocation path** (`OP_IF`): If someone knows the revocation key, they
   can spend immediately. This is how punishment works — the counterparty
   uses the revoked secret to derive the revocation key and sweep the funds.

2. **Normal path** (`OP_ELSE`): The owner waits `to_self_delay` blocks
   (typically 144 = ~1 day), then can spend with their delayed key.

The `to_remote` output is simple: the counterparty can spend it immediately.
This asymmetry is intentional — you should never need to broadcast your
own commitment transaction unless something goes wrong.

---

## The Complete State Update Lifecycle

Putting it all together, here's what happens when Alice sends Bob 0.01 BTC:

```
Step 1: Alice creates an HTLC update in her local log
Step 2: Alice calls SignNextCommitment()
        → Builds Bob's new commitment with the HTLC
        → Signs it and sends commit_sig to Bob

Step 3: Bob calls ReceiveNewCommitment()
        → Rebuilds the commitment independently
        → Verifies Alice's signature matches
        → Extends his local commitment chain

Step 4: Bob calls RevokeCurrentCommitment()
        → Reveals the revocation secret for his old state
        → Sends revoke_and_ack to Alice

Step 5: Alice calls ReceiveRevocation()
        → Stores revocation secret in shachain
        → Advances remote commitment chain
        → HTLCs are now irrevocably committed

Step 6: Bob does the same in reverse (signs Alice's commitment)
Step 7: Alice revokes her old commitment
Step 8: Both parties now have matching, updated states
```

📝 **Key Takeaway**: A single payment requires **two full rounds** through
the state machine — once for each party's commitment. This ensures both
sides have signed the new state and revoked the old one before the update
is considered final.

---

## Summary: The Commitment State Machine

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   ┌───────────┐    sign     ┌────────────────┐          │
│   │  Pending  │───────────►│  Signed (not    │          │
│   │  Updates  │             │  yet revoked)   │          │
│   └───────────┘             └───────┬────────┘          │
│                                     │                   │
│                                  revoke                 │
│                                     │                   │
│                              ┌──────▼────────┐          │
│                              │   Revoked     │          │
│                              │   (final)     │          │
│                              └──────┬────────┘          │
│                                     │                   │
│                         stored in shachain              │
│                              (O(log N) space)           │
│                                     │                   │
│                              ┌──────▼────────┐          │
│                              │  Available    │          │
│                              │  for breach   │          │
│                              │  detection    │          │
│                              └───────────────┘          │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 💡 Exercises

### Exercise 1: Trace a State Update

Open `lnwallet/channel.go` and trace through the four state machine methods
for a simple balance transfer. Answer:

1. What data structures are modified by `SignNextCommitment`?
2. What happens if `ReceiveNewCommitment` gets a bad signature?
3. What exactly is in the `RevokeAndAck` message?
4. Why does `ReceiveRevocation` return a `FwdPkg`?

### Exercise 2: Understand Dust

Using `lnwallet/channel.go`, find where dust limits are enforced:

1. What happens to an HTLC below the dust limit?
2. How does the dust limit affect the commitment transaction fee?
3. Why is dust different for offered vs received HTLCs?

### Exercise 3: Break the State Machine

Consider what happens if messages arrive out of order:

1. What if Bob receives two `commit_sig` messages without revoking?
2. What if Alice receives a revocation for a height she hasn't seen?
3. What protects against replay of old `commit_sig` messages?

### Exercise 4: Shachain Math

Calculate the storage requirements:

1. A channel with 1,000,000 updates using naive storage (32 bytes each)?
2. The same channel using shachain (log2(1,000,000) ≈ 20 buckets)?
3. At what update count does shachain save more than 1 GB?

### Exercise 5: Simulate a Breach

Walk through the breach detection flow:

1. Read `contractcourt/breach_arbitrator.go` and find the main loop
2. What triggers breach detection?
3. Why does LND split the justice TX after 4 blocks?
4. What happens to HTLC outputs during a breach sweep?

---

## Cross-References

- **Chapter 5**: [HTLCs, Routing & the Switch](05-htlc-switch-routing.md) —
  How HTLCs referenced in commitments are routed through the network
- **Chapter 6**: [Watchtowers](06-watchtowers.md) — Outsourcing breach
  detection when your node is offline
- **Chapter 7**: [Channel Backups (SCB)](07-channel-backups.md) — What
  happens when you lose your commitment state entirely

---

*Next: [Chapter 5 — HTLCs, Routing & the Switch →](05-htlc-switch-routing.md)*
