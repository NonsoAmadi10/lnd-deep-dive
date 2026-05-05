# Chapter 7: Channel Backups (SCB)

> *"Your channels live in a database. If that database disappears, your
> channels — and your funds — go with it. Unless you have a backup."*

---

## Table of Contents

1. [Why SCBs Exist](#why-scbs-exist)
2. [Design Philosophy: Deliberately Stateless](#design-philosophy-deliberately-stateless)
3. [The Single Backup Struct](#the-single-backup-struct)
4. [Backup Versions (0–7)](#backup-versions-07)
5. [Multi-Backup Format & Encryption](#multi-backup-format--encryption)
6. [Atomic File Updates](#atomic-file-updates)
7. [Archive Directory](#archive-directory)
8. [Recovery Flow](#recovery-flow)
9. [CloseTxInputs: Dangerous But Powerful](#closetxinputs-dangerous-but-powerful)
10. [Exercises](#-exercises)
11. [Cross-References](#cross-references)

---

## Why SCBs Exist

### 🔰 For Beginners

Your Lightning node stores everything in a database: channel states,
commitment transactions, HTLC data, revocation secrets. If you lose that
database — hardware failure, corrupted disk, accidental deletion — you
lose your channels.

Without a backup, here's what happens:

```
┌─────────────────────────────────────────────────────────┐
│                  WITHOUT BACKUP                         │
│                                                         │
│  Your Node (database lost)     Your Peer                │
│  ┌──────────────┐             ┌──────────────┐         │
│  │  "I have no  │             │  "I have a   │         │
│  │   idea what  │             │   channel    │         │
│  │   channels   │             │   with you"  │         │
│  │   I had"     │             │              │         │
│  └──────────────┘             └──────────────┘         │
│                                                         │
│  Options:                                               │
│  1. Hope your peer force-closes (they keep the fees)    │
│  2. Wait indefinitely (funds locked forever)            │
│  3. Lose the funds entirely                             │
│                                                         │
│  None of these are good.                                │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

With an SCB backup:

```
┌─────────────────────────────────────────────────────────┐
│                  WITH SCB BACKUP                        │
│                                                         │
│  Your Node (restored from SCB)  Your Peer               │
│  ┌──────────────┐              ┌──────────────┐        │
│  │  "I know I   │              │  "They lost  │        │
│  │   had a      │              │   their data │        │
│  │   channel    │  DLP protocol│   — I'll     │        │
│  │   with you"  │◄────────────►│   force-close│        │
│  └──────────────┘              │   with latest│        │
│                                │   state"     │        │
│                                └──────────────┘        │
│                                                         │
│  Result: Peer force-closes with the most recent state.  │
│  You get your funds back (minus on-chain fees).         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

📝 **Key Takeaway**: SCBs are your insurance policy against database loss.
They don't store the full channel state — just enough information to
trigger a recovery protocol with your peers.

---

## Design Philosophy: Deliberately Stateless

The most important thing to understand about SCBs is what they are **NOT**:

```
┌──────────────────────────────────────────────────┐
│  SCB is NOT a full channel state backup.          │
│                                                  │
│  ✗ Does NOT store commitment transactions        │
│  ✗ Does NOT store HTLC data                      │
│  ✗ Does NOT store revocation secrets             │
│  ✗ Does NOT store payment history                │
│  ✗ Does NOT let you resume a channel             │
│                                                  │
│  SCB IS a minimal recovery seed.                 │
│                                                  │
│  ✓ DOES store who your peers are                 │
│  ✓ DOES store channel funding outpoints          │
│  ✓ DOES store channel configurations             │
│  ✓ DOES enable the DLP recovery protocol         │
│  ✓ DOES let your peer force-close safely         │
│                                                  │
└──────────────────────────────────────────────────┘
```

### Why Not Store Everything?

If SCBs stored the full channel state, there would be a horrifying risk:
restoring an **old** backup would give you an **old** commitment
transaction. Broadcasting that old commitment is equivalent to cheating —
your peer could punish you and take all your funds!

By being stateless, SCBs avoid this entirely. The backup never contains
data that could be "stale" in a dangerous way. Instead, it triggers the
**Data Loss Protection (DLP)** protocol, where your peer force-closes
with the **latest** state.

⚠️ **Security Note**: Never try to "improve" SCBs by adding channel state.
The stateless design is a deliberate safety feature. A stale state backup
is worse than no backup at all — it could lead to total fund loss through
the punishment mechanism (see [Chapter 4](04-channels-commitments.md)).

---

## The Single Backup Struct

> **Source**: `chanbackup/single.go:120-202`

The `Single` struct is the fundamental unit of backup — one struct per
channel:

```go
// chanbackup/single.go:120
type Single struct {
    // Version identifies the backup format and channel type.
    Version SingleBackupVersion

    // IsInitiator is true if we opened the channel.
    IsInitiator bool

    // ChainHash identifies which blockchain (mainnet, testnet).
    ChainHash chainhash.Hash

    // FundingOutpoint is the on-chain location of the
    // funding transaction output.
    FundingOutpoint wire.OutPoint

    // ShortChannelID is the compact representation:
    // block_height || tx_index || output_index
    ShortChannelID lnwire.ShortChannelID

    // RemoteNodePub is the peer's identity public key.
    RemoteNodePub *btcec.PublicKey

    // Addresses are known network addresses for the peer.
    Addresses []net.Addr

    // Capacity is the total channel capacity in satoshis.
    Capacity btcutil.Amount

    // LocalChanCfg holds our channel configuration:
    // CSV delay, key descriptors, etc.
    LocalChanCfg channeldb.ChannelConfig

    // RemoteChanCfg holds the peer's channel configuration.
    RemoteChanCfg channeldb.ChannelConfig

    // ShaChainRootDesc is the key descriptor for deriving
    // the shachain root (used for revocation secrets).
    ShaChainRootDesc keychain.KeyDescriptor

    // LeaseExpiry is the maturity height for leased channels.
    LeaseExpiry uint32

    // CloseTxInputs optionally stores data for producing
    // a force-close transaction directly from the backup.
    CloseTxInputs fn.Option[CloseTxInputs]
}
```

### Field-by-Field Breakdown

```
┌─────────────────────────────────────────────────────────┐
│                 Single Backup Anatomy                    │
│                                                         │
│  ┌─ Identity ─────────────────────────────────────────┐ │
│  │  Version:          Which backup format (0-7)       │ │
│  │  ChainHash:        Bitcoin mainnet/testnet         │ │
│  │  IsInitiator:      Did we open this channel?       │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─ Channel Location ─────────────────────────────────┐ │
│  │  FundingOutpoint:  txid:vout of funding TX         │ │
│  │  ShortChannelID:   block:tx:output compact form    │ │
│  │  Capacity:         Total channel size              │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─ Peer Info ────────────────────────────────────────┐ │
│  │  RemoteNodePub:    Peer's 33-byte public key       │ │
│  │  Addresses:        IP addresses to reach peer      │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─ Channel Config ──────────────────────────────────┐ │
│  │  LocalChanCfg:     Our keys, CSV delay, etc.      │ │
│  │  RemoteChanCfg:    Their keys, CSV delay, etc.    │ │
│  │  ShaChainRootDesc: Revocation chain root key      │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─ Optional ─────────────────────────────────────────┐ │
│  │  LeaseExpiry:      Lease channel maturity height   │ │
│  │  CloseTxInputs:    Force-close TX data (⚠️)       │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

📝 **Key Takeaway**: The `Single` struct contains everything needed to
*identify* a channel and *contact* the peer — but NOT enough to *operate*
the channel. This is the stateless design in action.

---

## Backup Versions (0–7)

> **Source**: `chanbackup/single.go`

LND supports 8 backup versions, each corresponding to a different
channel commitment format:

```go
const (
    // DefaultSingleVersion is the original backup format.
    DefaultSingleVersion = 0

    // TweaklessCommitVersion uses tweakless commitments
    // (static remote key).
    TweaklessCommitVersion = 1

    // AnchorsCommitVersion adds anchor outputs for
    // fee bumping.
    AnchorsCommitVersion = 2

    // AnchorsZeroFeeHtlcTxCommitVersion uses zero-fee
    // HTLC transactions with anchors.
    AnchorsZeroFeeHtlcTxCommitVersion = 3

    // ScriptEnforcedLeaseVersion adds CLTV constraints
    // for channel leases.
    ScriptEnforcedLeaseVersion = 4

    // SimpleTaprootVersion uses MuSig2 for taproot channels.
    SimpleTaprootVersion = 5

    // TapscriptRootVersion adds top-level tapscript support.
    TapscriptRootVersion = 6

    // SimpleTaprootFinalVersion is the production taproot
    // format using OP_CHECKSIGVERIFY.
    SimpleTaprootFinalVersion = 7
)
```

### Version Evolution Timeline

```
Version 0: DefaultSingle        │  Original Lightning
    │                            │  P2WSH commitments
    ▼                            │
Version 1: Tweakless             │  Static remote key
    │                            │  (simpler recovery)
    ▼                            │
Version 2: Anchors               │  Anchor outputs for
    │                            │  fee bumping (CPFP)
    ▼                            │
Version 3: ZeroFeeHtlc           │  Zero-fee HTLC TXs
    │                            │  (more efficient)
    ▼                            │
Version 4: ScriptEnforcedLease   │  Channel leases with
    │                            │  CLTV maturity
    ▼                            │
Version 5: SimpleTaproot         │  MuSig2 taproot
    │                            │  (Schnorr signatures)
    ▼                            │
Version 6: TapscriptRoot         │  Tapscript tree support
    │                            │  (overlay taproot)
    ▼                            │
Version 7: SimpleTaprootFinal    │  Production taproot
                                 │  (OP_CHECKSIGVERIFY)
```

### Version Encoding with CloseTxInputs Flag

The version byte's high bit (bit 7) indicates `CloseTxInputs` presence:

```go
// chanbackup/single.go
const closeTxVersionMask = 1 << 7  // e.g., 0b10000011 = version 3 + CloseTxInputs
```

---

## Multi-Backup Format & Encryption

> **Source**: `chanbackup/multi.go`

A `Multi` backup bundles all channel backups into a single encrypted file:

```go
// chanbackup/multi.go
type Multi struct {
    // Version is the multi-backup format version (currently 0).
    Version MultiBackupVersion

    // StaticBackups contains one Single per channel.
    StaticBackups []Single
}
```

### Serialization Format

```
┌─────────────────────────────────────────────────────────┐
│              MULTI BACKUP WIRE FORMAT                    │
│                                                         │
│  ┌──────────────────────────────────────────┐           │
│  │  Plaintext (before encryption):          │           │
│  │                                          │           │
│  │  version     [1 byte]   = 0x00           │           │
│  │  numBackups  [4 bytes]  = N              │           │
│  │  backup_1    [variable] = Single #1      │           │
│  │  backup_2    [variable] = Single #2      │           │
│  │  ...                                     │           │
│  │  backup_N    [variable] = Single #N      │           │
│  └──────────────────────────────────────────┘           │
│                     │                                   │
│                     │  ChaCha20-Poly1305 encrypt        │
│                     ▼                                   │
│  ┌──────────────────────────────────────────┐           │
│  │  Ciphertext (on disk):                   │           │
│  │                                          │           │
│  │  nonce       [24 bytes]  random          │           │
│  │  ciphertext  [variable]  encrypted data  │           │
│  │  MAC tag     [16 bytes]  authentication  │           │
│  └──────────────────────────────────────────┘           │
│                                                         │
│  Minimum size (empty backup):                           │
│  NilMultiSizePacked = 45 bytes                          │
│  = 24 (nonce) + 16 (MAC) + 1 (version) + 4 (zero count)│
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 🔰 For Beginners: What Is ChaCha20-Poly1305?

**ChaCha20-Poly1305** is an authenticated encryption algorithm that provides
both confidentiality (ChaCha20 encrypts) and integrity (Poly1305 verifies
the data hasn't been tampered with).

The **nonce** (number used once) is 24 bytes of random data. Using a random
nonce (instead of a counter) means each encryption produces different
ciphertext, even for identical plaintext. This is important because backups
are re-encrypted every time they're updated.

### Key Derivation

The encryption key is derived from LND's keychain:

```go
// Uses lnencrypt.KeyRingEncrypter
// Key = SHA256(KeyFamilyBaseEncryption private key)
// This ties the backup to your node's seed
```

⚠️ **Security Note**: The encryption key is derived from your node's HD
seed. If you lose your seed AND your backup, you cannot recover. Always
keep your seed phrase safe — it's the master key to everything.

---

## Atomic File Updates

> **Source**: `chanbackup/backupfile.go`

LND uses **atomic file operations** to ensure that the backup file is
never in a corrupted state, even if the node crashes mid-write.

### 🔰 For Beginners: What Are Atomic File Operations?

"Atomic" means "all or nothing." When writing a file atomically, either
the entire new file is written successfully, or the old file remains
completely intact. There's no in-between state where the file is half-written
and corrupted.

How it works:

```
┌─────────────────────────────────────────────────────────┐
│              ATOMIC FILE UPDATE PROCESS                  │
│                                                         │
│  Step 1: Remove old temp file (if exists)               │
│                                                         │
│  Step 2: Create new temp file                           │
│          "temp-dont-use.backup"                         │
│                                                         │
│  Step 3: Write encrypted backup to temp file            │
│                                                         │
│  Step 4: fsync temp file to disk                        │
│          (ensures bytes are physically written)          │
│                                                         │
│  Step 5: Close temp file                                │
│          (required on Windows before rename)            │
│                                                         │
│  Step 6: Archive old backup                             │
│          (copy to chan-backup-archives/ with timestamp)  │
│                                                         │
│  Step 7: Atomic rename                                  │
│          temp-dont-use.backup → channel.backup          │
│          (this is the atomic step — instant swap)        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### The Code

```go
// chanbackup/backupfile.go
const (
    // DefaultBackupFileName is the main backup file.
    DefaultBackupFileName = "channel.backup"

    // DefaultTempBackupFileName is the staging file.
    DefaultTempBackupFileName = "temp-dont-use.backup"

    // DefaultChanBackupArchiveDirName is the archive directory.
    DefaultChanBackupArchiveDirName = "chan-backup-archives"
)
```

The `UpdateAndSwap` method implements the atomic update:

```go
// Simplified flow from chanbackup/backupfile.go
func (b *MultiFile) UpdateAndSwap(newBackup PackedMulti) error {
    // Step 1: Remove old temp file
    os.Remove(tempFileName)

    // Step 2: Create temp file
    tempFile, _ := os.Create(tempFileName)

    // Step 3: Write backup data
    tempFile.Write(newBackup)

    // Step 4: Sync to disk
    tempFile.Sync()

    // Step 5: Close (required for Windows)
    tempFile.Close()

    // Step 6: Archive old backup
    b.createArchiveFile(fileName)

    // Step 7: Atomic rename
    os.Rename(tempFileName, fileName)
}
```

### Why `fsync` Matters

Without `fsync`, the operating system might buffer the write. If the node
crashes before the buffer is flushed to disk, the temp file could be empty
or incomplete. `fsync` forces the OS to write everything to physical storage
before proceeding.

### Why Rename Is Atomic

On most filesystems, `os.Rename` is guaranteed to be atomic: the old file
is replaced with the new file in a single operation. There's no window
where neither file exists or both exist under the same name.

📝 **Key Takeaway**: The atomic update process ensures that `channel.backup`
is always a valid, complete backup. Even if your node crashes at any point
during the update, you'll have either the old valid backup or the new one —
never a corrupted file.

---

## Archive Directory

> **Source**: `chanbackup/backupfile.go:176-200`

Every time the backup is updated, the old version is archived:

```
data/chain/bitcoin/mainnet/
├── channel.backup                      ← current backup
└── chan-backup-archives/
    ├── channel.backup-2024-01-15-10-30-00
    ├── channel.backup-2024-01-15-11-45-22
    ├── channel.backup-2024-01-15-14-00-05
    └── channel.backup-2024-01-16-09-15-33
```

### Archive File Naming

```
{baseFileName}-{YYYY-MM-DD-HH-MM-SS}

Example: channel.backup-2024-01-15-10-30-00
         ├── base name ──┘         └── timestamp
```

### Disabling Archives

For nodes with limited storage, archiving can be disabled:

```go
// chanbackup/backupfile.go
func NewMultiFile(fileName string, noBackupArchive bool) *MultiFile
```

When `noBackupArchive = true`, old backups are deleted instead of archived.
This saves disk space but means you can't roll back to a previous backup
version.

⚠️ **Security Note**: Archives are useful for debugging but are NOT more
secure than the current backup. All SCBs are stateless — any version
triggers the same DLP recovery. However, an older backup might be missing
recently opened channels, so always use the most recent backup.

---

## Recovery Flow

### The Big Picture

```
┌──────────────────────────────────────────────────────────┐
│              SCB RECOVERY FLOW                            │
│                                                          │
│  1. DISASTER                                             │
│     Your node's database is lost                         │
│     You have: seed phrase + channel.backup               │
│                                                          │
│  2. RESTORE NODE                                         │
│     Create new LND node from seed phrase                 │
│     Import channel.backup                                │
│                                                          │
│  3. CREATE SHELL CHANNELS                                │
│     For each Single in the backup:                       │
│     ├── Create a "shell" channel (metadata only)         │
│     ├── Mark it as needing recovery                      │
│     └── No state, no commitments — just identity         │
│                                                          │
│  4. CONNECT TO PEERS                                     │
│     For each shell channel:                              │
│     ├── Look up peer from RemoteNodePub                  │
│     ├── Connect using Addresses                          │
│     └── Initiate channel_reestablish                     │
│                                                          │
│  5. DLP PROTOCOL                                         │
│     ├── Send channel_reestablish with height=0           │
│     ├── Peer detects data loss                           │
│     ├── Peer sends their latest commitment point         │
│     └── Peer force-closes with latest state              │
│                                                          │
│  6. ON-CHAIN SETTLEMENT                                  │
│     ├── Wait for force-close TX to confirm               │
│     ├── Wait for CSV delay (e.g., 144 blocks)            │
│     └── Sweep funds to your wallet                       │
│                                                          │
│  Result: Funds recovered! (minus on-chain fees)          │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Step-by-Step Detail

#### Step 3: Shell Channels

A "shell channel" is a minimal channel entry in the database. It contains:
- The funding outpoint (so LND knows which UTXO to watch)
- The remote peer's public key (so LND knows who to contact)
- A flag marking it as "recovery pending"

It does NOT contain any commitment state, HTLC data, or revocation secrets.

#### Step 5: The DLP Protocol

**DLP** (Data Loss Protection) is defined in BOLT #2. When nodes reconnect,
they exchange `channel_reestablish` messages:

```
Your Node (recovered)              Peer
     │                               │
     │  channel_reestablish          │
     │  next_commitment_number: 1    │  ← "I think we're at
     │  next_revocation_number: 0    │     the beginning"
     │  ────────────────────────►   │
     │                               │
     │  channel_reestablish          │
     │  next_commitment_number: 500  │  ← "We're actually
     │  next_revocation_number: 499  │     at update #499"
     │  my_current_per_commitment:   │
     │    <commitment_point>         │
     │  ◄────────────────────────   │
     │                               │
     │  Your node detects:           │
     │  500 >> 1 → DATA LOSS!        │
     │                               │
     │  Peer detects: you're behind  │
     │  → Force-closes with latest   │
     │    state (the most favorable  │
     │    to you)                    │
     │                               │
     ▼                               ▼
```

### 🔰 For Beginners: Why Does the Peer Force-Close?

When your peer detects that you've lost data, they know you can't safely
operate the channel anymore. You don't have the revocation secrets for
recent states, so you can't detect breaches. The safest thing for everyone
is to close the channel on-chain.

The peer force-closes with the **latest** state because:
1. It's the correct thing to do (they'd lose money if they used an old state
   and you somehow still had the revocation secret)
2. The protocol requires it
3. It preserves the most recent balances for both parties

📝 **Key Takeaway**: SCB recovery always results in all channels being
force-closed. You cannot resume normal channel operation from an SCB.
After recovery, you'll need to open new channels. Any in-flight HTLCs
at the time of data loss may be lost.

---

## CloseTxInputs: Dangerous But Powerful

> **Source**: `chanbackup/single.go:204-230`

```go
// chanbackup/single.go:204
type CloseTxInputs struct {
    // CommitTx is the unsigned force-close commitment TX.
    CommitTx *wire.MsgTx

    // CommitSig is the remote party's signature.
    CommitSig []byte

    // CommitHeight is the commitment update number.
    // Only used for taproot channels.
    CommitHeight uint64

    // TapscriptRoot is the tapscript tree root hash.
    // Only present for overlay taproot channels.
    TapscriptRoot fn.Option[chainhash.Hash]
}
```

### What CloseTxInputs Does

Unlike standard SCB recovery (where you ask your peer to force-close),
`CloseTxInputs` lets you force-close **from the backup itself** — without
contacting your peer.

```
Standard SCB Recovery:
  Backup → Connect to peer → Peer force-closes → Wait → Sweep

CloseTxInputs Recovery:
  Backup → Broadcast commitment TX directly → Wait → Sweep
  (No peer contact needed!)
```

### ⚠️ DANGER: Stale CloseTxInputs

This feature is **extremely dangerous** if the backup is stale:

```
┌──────────────────────────────────────────────────────────┐
│                    ⚠️ DANGER ZONE ⚠️                    │
│                                                          │
│  If CloseTxInputs contains an OLD commitment TX:         │
│                                                          │
│  1. You broadcast the old commitment                     │
│  2. Your peer detects the breach                         │
│  3. Your peer broadcasts a JUSTICE TRANSACTION           │
│  4. Your peer takes ALL the funds                        │
│  5. You get NOTHING                                      │
│                                                          │
│  This is the punishment mechanism from Chapter 4          │
│  working AGAINST you!                                    │
│                                                          │
│  ONLY use CloseTxInputs if you are CERTAIN the           │
│  backup contains the LATEST state, or if your             │
│  peer is permanently unreachable.                         │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### When CloseTxInputs Is Useful

1. **Peer is permanently offline**: If your peer's node is gone forever
   and will never force-close, CloseTxInputs lets you recover funds
   unilaterally.

2. **Emergency recovery**: Combined with tools like `chantools scbforceclose`,
   this allows last-resort fund recovery.

3. **DLP is not active**: When the backup was created at the latest state
   and no further updates occurred.

⚠️ **Security Note**: The `CloseTxInputs` feature stores the last known
commitment transaction. If ANY state updates occurred after the backup was
created, using CloseTxInputs could trigger punishment. This is why the
standard DLP-based recovery is always preferred.

---

## SCB vs Watchtower Comparison

| Feature | SCB | Watchtower |
|---------|-----|-----------|
| Protects against | Database loss | Breach while offline |
| Requires peer cooperation | Yes (DLP) | No (autonomous) |
| Channels after recovery | All closed | Remain open |
| In-flight HTLCs | Lost | Protected (to_local/to_remote) |
| Storage location | Local file | Remote server |
| Encryption | ChaCha20-Poly1305 | AES-256 (blob) |
| Update frequency | On channel open/close | On every state update |

---

## 💡 Exercises

### Exercise 1: Read the Backup

1. Find `chanbackup/single.go` and read the `Serialize` method
2. Calculate the approximate size of a Single backup for a channel with
   3 known peer addresses
3. How does the serialization handle variable-length fields?

### Exercise 2: Understand the Encryption

1. Find the encryption logic in `chanbackup/single.go:501-531`
2. Why is a 24-byte random nonce used instead of a counter?
3. What would happen if the same nonce were reused?
4. How is the encryption key derived from the HD seed?

### Exercise 3: Atomic File Safety

Consider these failure scenarios during `UpdateAndSwap`:

1. Crash after step 2 (temp file created) but before step 3 (write)?
2. Crash after step 3 (write) but before step 4 (fsync)?
3. Crash after step 4 (fsync) but before step 7 (rename)?
4. Crash during step 7 (rename)?
5. For each scenario, what is the state of `channel.backup`?

### Exercise 4: DLP Protocol Analysis

1. Read the `channel_reestablish` message in the BOLT #2 specification
2. What fields are exchanged?
3. How does the peer determine that data loss has occurred?
4. Why does the peer send `my_current_per_commitment_point`?
5. How does this relate to `ErrCommitSyncLocalDataLoss` from
   [Chapter 4](04-channels-commitments.md)?

### Exercise 5: CloseTxInputs Risk Assessment

A node operator has a `channel.backup` with `CloseTxInputs` from 3 days
ago. Since then, the channel has had 50 state updates.

1. If they broadcast the `CloseTxInputs` commitment, what happens?
2. How many revocation secrets has the peer accumulated?
3. How much money could the peer claim via the justice transaction?
4. What should the operator do instead?

---

## Cross-References

- **Chapter 4**: [Channels & Commitment Transactions](04-channels-commitments.md) —
  Understanding commitment state and why stale backups are dangerous
- **Chapter 5**: [HTLCs, Routing & the Switch](05-htlc-switch-routing.md) —
  What happens to in-flight HTLCs during recovery
- **Chapter 6**: [Watchtowers](06-watchtowers.md) — Complementary protection
  mechanism that works while your node is offline

---

*← Previous: [Chapter 6 — Watchtowers](06-watchtowers.md)*
