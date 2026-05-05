# Chapter 11: Consolidated Security Findings

## A Comprehensive Security Audit of LND's Core Subsystems

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Methodology](#methodology)
3. [Severity Classification](#severity-classification)
4. [Consolidated Findings Table](#consolidated-findings-table)
5. [Severity Distribution](#severity-distribution)
6. [Findings by Subsystem](#findings-by-subsystem)
7. [Prioritized Remediation Roadmap](#prioritized-remediation-roadmap)
8. [Detailed Finding Write-Ups](#detailed-finding-write-ups)
9. [Conclusion](#conclusion)

---

## Executive Summary

This chapter consolidates all **18 security findings** identified throughout our
deep-dive audit of the LND codebase (Chapters 1–10). The audit examined LND's
cryptographic primitives, key management, network privacy, channel state
machines, access control, and ancillary subsystems.

### Key Statistics

```
┌─────────────────────────────────────────────────┐
│           SECURITY AUDIT SUMMARY                │
├─────────────────────────────────────────────────┤
│  Total Findings:          18                    │
│  Critical:                 1  (5.6%)            │
│  High:                     5  (27.8%)           │
│  Medium:                   7  (38.9%)           │
│  Low:                      3  (16.7%)           │
│  Informational:            2  (11.1%)           │
│                                                 │
│  Subsystems Affected:      8                    │
│  Files Affected:          15+                   │
│  Findings Requiring Code: 14                    │
│  Findings Already Mitig.:  1                    │
└─────────────────────────────────────────────────┘
```

The single **Critical** finding (#13 — SkipProxy leaks real IP) poses an
immediate threat to node operator anonymity and physical safety. Five **High**
severity findings affect key material security, watchtower reliability, gossip
integrity, and Tor authentication. Together, these demand urgent attention from
both operators and developers.

### Risk Posture

LND's overall security posture is **strong for a production-grade Lightning
implementation**, but the findings reveal recurring themes:

1. **Memory safety for key material** — Secret keys are not memory-locked in
   multiple subsystems, creating a class of swap-to-disk vulnerabilities.
2. **Tor integration gaps** — The Tor subsystem contains the highest density of
   findings (6 of 18), indicating that privacy integration needs hardening.
3. **State persistence gaps** — Critical state (bans, justice transactions) is
   not always persisted to disk, creating restart-related vulnerabilities.
4. **Default configurations favor usability over security** — Several defaults
   (passphrase, file permissions, proxy settings) trade security for ease of
   setup.

---

## Methodology

### Audit Scope

The audit covered the following LND subsystems:

```
┌──────────────────────────────────────────────────────────┐
│                    LND CODEBASE                          │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │ aezeed/  │  │brontide/ │  │  tor/    │               │
│  │ Key Gen  │  │  Noise   │  │ Privacy  │               │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘               │
│       │              │             │                     │
│  ┌────▼─────┐  ┌─────▼────┐  ┌────▼─────┐               │
│  │keychain/ │  │discovery/│  │ lncfg/  │               │
│  │ HD Keys  │  │ Gossip   │  │ Config  │               │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘               │
│       │              │             │                     │
│  ┌────▼─────┐  ┌─────▼────┐  ┌────▼─────┐               │
│  │macaroons/│  │watchtower│  │htlcswitch│               │
│  │ Access   │  │ Justice  │  │ Routing  │               │
│  └──────────┘  └──────────┘  └──────────┘               │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │chanbackup│  │rpcperms/ │  │  lnd.go  │               │
│  │ Backups  │  │Middleware│  │  Main    │               │
│  └──────────┘  └──────────┘  └──────────┘               │
└──────────────────────────────────────────────────────────┘
```

### Approach

The audit followed a **source-code-driven, threat-model-aware** methodology:

1. **Static Analysis** — Line-by-line review of security-critical code paths.
2. **Data Flow Tracing** — Following sensitive data (keys, secrets, tokens)
   through the codebase from creation to destruction.
3. **Threat Modeling** — Identifying adversary capabilities and attack surfaces
   for each subsystem.
4. **Configuration Review** — Examining default values and their security
   implications.
5. **Cross-Reference** — Checking findings against known Lightning Network
   attack vectors from academic literature and BOLT specifications.

### Limitations

- The audit focused on the Go source code and did not include fuzzing or
  dynamic analysis.
- Third-party dependencies (btcd, neutrino, macaroon libraries) were examined
  only at their integration boundaries.
- Performance and denial-of-service resilience were assessed qualitatively,
  not through load testing.

---

## Severity Classification

| Severity        | Definition                                                                     | SLA Target  |
|-----------------|--------------------------------------------------------------------------------|-------------|
| **Critical**    | Immediate risk of fund loss, key compromise, or identity exposure              | Fix in 24h  |
| **High**        | Significant risk; exploitable under realistic conditions                       | Fix in 1 wk |
| **Medium**      | Moderate risk; requires specific conditions or partial attacker capability      | Fix in 1 mo |
| **Low**         | Minor risk; defense-in-depth improvement                                       | Fix in 3 mo |
| **Info**        | Observation; no immediate risk but worth tracking                              | Backlog     |

---

## Consolidated Findings Table

| #  | Finding                              | Severity     | Location                           | Chapter |
|----|--------------------------------------|--------------|------------------------------------|---------|
| 1  | Secret key not memory-locked         | **High**     | `brontide/noise.go:117`            | Ch. 2   |
| 2  | Default passphrase "aezeed"          | **Medium**   | `aezeed/cipherseed.go:119`         | Ch. 1   |
| 3  | 5-byte salt in aezeed                | **Low**      | `aezeed/cipherseed.go:77`          | Ch. 1   |
| 4  | Macaroon perms hardcoded 0640        | **Info**     | `lnd.go`                           | Ch. 5   |
| 5  | No justice tx rebroadcast on restart | **High**     | `watchtower/lookout/lookout.go:299` | Ch. 7   |
| 6  | CloseTxInputs stale backup           | **Medium**   | `chanbackup/single.go:204`         | Ch. 8   |
| 7  | Fail-closed middleware crash          | **Medium**   | `rpcperms/`                        | Ch. 5   |
| 8  | SafeCopyMacaroon clone bug           | **Low**      | `macaroons/`                       | Ch. 5   |
| 9  | In-memory-only ban list              | **Medium**   | `discovery/ban.go`                 | Ch. 6   |
| 10 | AssumeChannelValid skips UTXO        | **High**     | `discovery/gossiper.go:394`        | Ch. 6   |
| 11 | Onion key unencrypted by default     | **High**     | `tor/`                             | Ch. 4   |
| 12 | NULL auth fallback for Tor control   | **High**     | `tor/controller.go:470`            | Ch. 4   |
| 13 | SkipProxy leaks real IP              | **Critical** | `tor/`                             | Ch. 4   |
| 14 | Tor control password in process list | **Medium**   | `lncfg/tor.go:14`                  | Ch. 4   |
| 15 | DeletePrivateKey doesn't zero disk   | **Medium**   | `tor/`                             | Ch. 4   |
| 16 | No mlock for onion private key       | **Medium**   | `tor/`                             | Ch. 4   |
| 17 | Dust fee exposure                    | **Info**     | `htlcswitch/switch.go:2577`        | Ch. 9   |
| 18 | DefaultConnTimeout 120s DoS          | **Low**      | `tor/net.go:16`                    | Ch. 4   |

---

## Severity Distribution

```
  Severity Distribution of Security Findings
  ════════════════════════════════════════════

  Critical (1) │████                                          5.6%
               │
  High     (5) │████████████████████                         27.8%
               │
  Medium   (7) │████████████████████████████                 38.9%
               │
  Low      (3) │████████████                                 16.7%
               │
  Info     (2) │████████                                     11.1%
               │
               └──────────────────────────────────────────
                0    1    2    3    4    5    6    7    8

  Total: 18 findings
```

### Risk Heat Map

```
                        IMPACT
              Low      Medium      High
         ┌──────────┬──────────┬──────────┐
   High  │          │  #9,#14  │ #5,#10   │
         │          │  #15,#16 │ #11,#12  │
L        ├──────────┼──────────┼──────────┤
I  Med   │  #3,#18  │  #2,#6  │  ═#13═   │
K        │          │  #7     │(CRITICAL)│
E        ├──────────┼──────────┼──────────┤
L  Low   │  #4,#17  │  #8     │  #1      │
I        │          │          │          │
H        └──────────┴──────────┴──────────┘
O
O
D
```

---

## Findings by Subsystem

```
  Subsystem Breakdown
  ═══════════════════

  tor/           │██████████████████████████████████  6 findings (#11-16,#18)
  discovery/     │████████████                        2 findings (#9,#10)
  aezeed/        │████████████                        2 findings (#2,#3)
  brontide/      │██████                              1 finding  (#1)
  watchtower/    │██████                              1 finding  (#5)
  chanbackup/    │██████                              1 finding  (#6)
  rpcperms/      │██████                              1 finding  (#7)
  macaroons/     │██████                              1 finding  (#8)
  htlcswitch/    │██████                              1 finding  (#17)
  lnd.go         │██████                              1 finding  (#4)
  lncfg/         │██████                              1 finding  (#14)
                 └────────────────────────────────
                  0  1  2  3  4  5  6  7
```

### Observations

- **Tor subsystem** accounts for **33%** of all findings — the highest density
  of any subsystem. This is expected: Tor integration involves network privacy,
  key storage, authentication, and process management — all security-sensitive.
- **Cryptographic subsystems** (aezeed, brontide) have well-contained findings
  that reflect design trade-offs rather than implementation bugs.
- **State management** issues span multiple subsystems (watchtower, discovery,
  chanbackup), suggesting a systemic pattern worth addressing holistically.

---

## Prioritized Remediation Roadmap

### Phase 1: Immediate (Week 1) — Critical & High Exploitable

```
  WEEK 1 — STOP THE BLEEDING
  ┌─────────────────────────────────────────────────────────┐
  │                                                         │
  │  #13  SkipProxy leaks real IP              [CRITICAL]   │
  │   └─> Remove SkipProxy or gate behind --unsafe flag     │
  │                                                         │
  │  #12  NULL auth fallback for Tor control   [HIGH]       │
  │   └─> Fail hard if no secure auth method available      │
  │                                                         │
  │  #11  Onion key unencrypted by default     [HIGH]       │
  │   └─> Encrypt with wallet key on disk                   │
  │                                                         │
  │  #5   No justice tx rebroadcast            [HIGH]       │
  │   └─> Persist decrypted state to watchtower DB          │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
```

### Phase 2: Short-Term (Month 1) — High & Medium

```
  MONTH 1 — HARDEN CORE
  ┌─────────────────────────────────────────────────────────┐
  │                                                         │
  │  #1   mlock() for brontide secret keys     [HIGH]       │
  │  #10  Restrict AssumeChannelValid          [HIGH]       │
  │  #9   Persist ban list to disk             [MEDIUM]     │
  │  #2   Require explicit passphrase          [MEDIUM]     │
  │  #6   Stale backup detection               [MEDIUM]     │
  │  #7   Middleware health monitoring         [MEDIUM]     │
  │  #14  Tor password via env/file            [MEDIUM]     │
  │  #15  Zero disk before delete              [MEDIUM]     │
  │  #16  mlock() for onion keys               [MEDIUM]     │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
```

### Phase 3: Long-Term (Quarter 1) — Low & Info

```
  QUARTER 1 — POLISH & DEFENSE-IN-DEPTH
  ┌─────────────────────────────────────────────────────────┐
  │                                                         │
  │  #3   Increase aezeed salt size            [LOW]        │
  │  #8   Upstream macaroon library fix        [LOW]        │
  │  #18  Lower DefaultConnTimeout             [LOW]        │
  │  #4   Tighten macaroon file perms          [INFO]       │
  │  #17  Monitor dust fee exposure            [INFO]       │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
```

---

## Detailed Finding Write-Ups

---

### Finding #1: Secret Key Not Memory-Locked

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-001                              |
| **Severity**     | High                                 |
| **Location**     | `brontide/noise.go:117`              |
| **Chapter**      | Chapter 2 — Brontide & Noise         |
| **Status**       | Open                                 |

#### Description

The Brontide handshake stores the node's static private key (`localStatic`) in
regular heap-allocated memory. This memory is subject to the operating system's
virtual memory management, meaning it can be swapped to disk under memory
pressure.

#### Vulnerable Code

```go
// brontide/noise.go — Machine initialization
func NewBrontideMachine(initiator bool, localStatic keychain.SingleKeyECDH,
    remoteStatic *btcec.PublicKey) *Machine {

    handshake := newHandshakeState(initiator, localStatic, remoteStatic)

    return &Machine{
        handshakeState: handshake,
        // localStatic lives in regular memory — not mlock()'d
    }
}
```

#### Exploit Scenario

```
  ┌──────────────┐     Memory        ┌──────────────┐
  │  LND Process │     Pressure      │  Swap File   │
  │              │ ──────────────▶   │              │
  │  localStatic │                   │  localStatic │
  │  (secret key)│                   │  (on disk!)  │
  └──────────────┘                   └──────┬───────┘
                                           │
                                    ┌──────▼───────┐
                                    │   Attacker   │
                                    │  reads swap  │
                                    │  recovers    │
                                    │  private key │
                                    └──────────────┘
```

1. LND runs on a system with limited RAM (common for Raspberry Pi nodes).
2. Under memory pressure, the OS swaps the page containing `localStatic` to
   disk.
3. An attacker with physical access (or remote access to the filesystem) reads
   the swap partition.
4. The attacker extracts the node's static private key.
5. With the static key, the attacker can impersonate the node and potentially
   access channel funds.

#### Recommended Fix

Use the `mlock()` syscall to pin secret key pages in physical RAM:

```go
import "golang.org/x/sys/unix"

// LockKeyInMemory prevents the key from being swapped to disk.
func LockKeyInMemory(key []byte) error {
    return unix.Mlock(key)
}

// UnlockKeyInMemory releases the memory lock.
func UnlockKeyInMemory(key []byte) error {
    return unix.Munlock(key)
}
```

Additionally, keys should be zeroed when no longer needed:

```go
func ZeroKey(key []byte) {
    for i := range key {
        key[i] = 0
    }
}
```

---

### Finding #2: Default Passphrase "aezeed"

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-002                              |
| **Severity**     | Medium                               |
| **Location**     | `aezeed/cipherseed.go:119`           |
| **Chapter**      | Chapter 1 — Aezeed                   |
| **Status**       | Open                                 |

#### Description

When a user does not provide a passphrase during wallet creation, LND uses the
string `"aezeed"` as a default passphrase. This means any attacker who obtains
the 24-word mnemonic can derive the wallet's master key by trying the default
passphrase first.

#### Vulnerable Code

```go
// aezeed/cipherseed.go
const (
    // DefaultPassphrase is the default passphrase used if none is provided.
    DefaultPassphrase = "aezeed"
)
```

#### Exploit Scenario

1. A user creates an LND wallet and skips the passphrase prompt.
2. They back up their 24 mnemonic words on paper.
3. An attacker discovers the paper backup (physical theft, photo, etc.).
4. The attacker knows the default passphrase is `"aezeed"` (it's in the source
   code and well-documented).
5. Using the mnemonic + default passphrase, the attacker derives the master
   seed and steals all funds.

#### Recommended Fix

```go
// Option A: Require explicit passphrase (breaking change)
func (c *CipherSeed) Encipher(pass []byte) ([EncipheredCipherSeedSize]byte, error) {
    if len(pass) == 0 {
        return [EncipheredCipherSeedSize]byte{},
            fmt.Errorf("passphrase is required; empty passphrase not allowed")
    }
    // ... existing logic
}

// Option B: Warn prominently (non-breaking)
func (c *CipherSeed) Encipher(pass []byte) ([EncipheredCipherSeedSize]byte, error) {
    if len(pass) == 0 {
        log.Warnf("WARNING: Using default passphrase. Your wallet " +
            "is protected ONLY by the mnemonic words. Set a " +
            "passphrase for additional security.")
        pass = []byte(DefaultPassphrase)
    }
    // ... existing logic
}
```

---

### Finding #3: 5-Byte Salt in Aezeed

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-003                              |
| **Severity**     | Low                                  |
| **Location**     | `aezeed/cipherseed.go:77`            |
| **Chapter**      | Chapter 1 — Aezeed                   |
| **Status**       | Open (by design)                     |

#### Description

The aezeed cipher seed uses a 5-byte (40-bit) salt for the scrypt key
derivation function. While this is smaller than the typical 16-byte
recommendation, the salt is paired with scrypt's high computational cost
parameters (N=32768, r=8, p=1), which significantly mitigate brute-force risk.

#### Context

```go
// aezeed/cipherseed.go
const (
    // CipherSeedSaltSize is the size of the salt used for scrypt.
    CipherSeedSaltSize = 5
)
```

The 5-byte salt was chosen as a space optimization: the entire aezeed must fit
in a compact binary format that maps cleanly to 24 mnemonic words. Every byte
matters in this encoding.

#### Risk Assessment

- 40 bits = ~1 trillion possible salt values.
- Combined with scrypt (N=32768), precomputation attacks are impractical.
- The salt prevents identical passphrases from producing identical derived keys.
- Risk is theoretical; no practical exploit path exists today.

#### Recommended Fix

In a future version of the aezeed format (v1 → v2), increase the salt to 16
bytes. This would require changing the encoding format and mnemonic word count.

---

### Finding #4: Macaroon Permissions Hardcoded 0640

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-004                              |
| **Severity**     | Informational                        |
| **Location**     | `lnd.go`                             |
| **Chapter**      | Chapter 5 — Macaroons                |
| **Status**       | Open                                 |

#### Description

Macaroon files (admin.macaroon, readonly.macaroon, invoice.macaroon) are
created with permission mode `0640`, which allows group-read access. In shared
hosting environments, other users in the same group could read macaroon files
and gain API access to the LND node.

#### Recommended Fix

```go
// Change file permissions from 0640 to 0600
const macaroonFilePermissions = 0600  // owner read/write only
```

---

### Finding #5: No Justice Transaction Rebroadcast on Restart

| Attribute        | Value                                          |
|------------------|-------------------------------------------------|
| **ID**           | SEC-005                                         |
| **Severity**     | High                                            |
| **Location**     | `watchtower/lookout/lookout.go:299`              |
| **Chapter**      | Chapter 7 — Watchtower                           |
| **Status**       | Open                                            |

#### Description

When a watchtower detects a breach and decrypts the justice transaction blob,
the decrypted state is held only in memory. If the watchtower process crashes
or restarts after decryption but before the justice transaction confirms on
chain, the decrypted state is lost. The tower will not re-attempt broadcasting.

#### Exploit Scenario

```
  Timeline:
  ═════════

  t0: Breach tx broadcast by malicious counterparty
       │
  t1: Watchtower detects breach, decrypts blob
       │                                    ┌──────────────┐
  t2: Justice tx broadcast ─────────────▶  │  Mempool     │
       │                                    └──────┬───────┘
  t3: ═══ WATCHTOWER CRASHES ═══                   │
       │                                           │
  t4: Watchtower restarts                          │
       │   └─ Decrypted state LOST                 │
       │   └─ No rebroadcast attempted             │
       │                                           │
  t5: Justice tx dropped from mempool    ◀─────────┘
       │   (RBF'd, expired, or fee too low)
       │
  t6: Breach tx CONFIRMS ──▶ Funds stolen!
```

#### Recommended Fix

Persist decrypted justice transaction state to the watchtower database:

```go
// watchtower/lookout/lookout.go

// PersistDecryptedState saves the decrypted blob to DB before broadcasting.
func (l *Lookout) PersistDecryptedState(id blob.BreachHint,
    justice *lnwallet.BreachRetribution) error {

    return l.cfg.DB.PersistJusticeState(id, justice)
}

// On startup, check for pending justice transactions
func (l *Lookout) rebroadcastPending() error {
    pending, err := l.cfg.DB.FetchPendingJustice()
    if err != nil {
        return err
    }
    for _, p := range pending {
        l.dispatchJustice(p)
    }
    return nil
}
```

---

### Finding #6: CloseTxInputs Force-Close from Stale Backup

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-006                              |
| **Severity**     | Medium                               |
| **Location**     | `chanbackup/single.go:204`           |
| **Chapter**      | Chapter 8 — Channel Backup           |
| **Status**       | Open                                 |

#### Description

Static Channel Backups (SCBs) capture channel state at a point in time. If a
user restores from a stale (outdated) backup, LND triggers a force-close using
old state. While the Data Loss Protection (DLP) protocol is designed to handle
this, restoring with truly stale state could result in the counterparty
broadcasting a penalty transaction, causing the restoring party to lose funds.

#### Recommended Fix

- Add backup timestamp and sequence number to SCB metadata.
- On restore, warn if the backup is older than a configurable threshold.
- Implement a backup freshness check against the channel's known state.

---

### Finding #7: Fail-Closed Middleware Crash

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-007                              |
| **Severity**     | Medium                               |
| **Location**     | `rpcperms/`                          |
| **Chapter**      | Chapter 5 — Macaroons & RPC          |
| **Status**       | Open                                 |

#### Description

LND supports mandatory RPC middleware interceptors. If a mandatory middleware
is registered and then crashes, all RPC calls fail because the middleware
pipeline cannot complete. This is a "fail-closed" design, which is
security-positive but creates availability risk.

#### Recommended Fix

```go
// Add middleware health monitoring
type MiddlewareHealth struct {
    Name        string
    LastPing    time.Time
    Healthy     bool
    RestartCnt  int
}

// Auto-restart crashed mandatory middleware with backoff
func (m *MiddlewareManager) monitorHealth(ctx context.Context) {
    ticker := time.NewTicker(healthCheckInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            for _, mw := range m.mandatory {
                if !mw.IsAlive() {
                    log.Warnf("Mandatory middleware %s unresponsive, "+
                        "attempting restart", mw.Name)
                    mw.Restart()
                }
            }
        case <-ctx.Done():
            return
        }
    }
}
```

---

### Finding #8: SafeCopyMacaroon Clone Bug Workaround

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-008                              |
| **Severity**     | Low                                  |
| **Location**     | `macaroons/`                         |
| **Chapter**      | Chapter 5 — Macaroons                |
| **Status**       | Open (upstream)                      |

#### Description

LND implements a `SafeCopyMacaroon` function that works around a bug in the
underlying macaroon library's `Clone()` method. The clone operation can
produce macaroons that fail validation, so LND re-serializes and re-
deserializes instead.

#### Recommended Fix

File an upstream fix with the `go-macaroon` library. In the interim, the
workaround is sufficient and introduces no additional risk.

---

### Finding #9: In-Memory-Only Ban List

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-009                              |
| **Severity**     | Medium                               |
| **Location**     | `discovery/ban.go`                   |
| **Chapter**      | Chapter 6 — Gossip & Discovery       |
| **Status**       | Open                                 |

#### Description

The gossip subsystem maintains a ban list for peers that send invalid or
malicious gossip messages. This ban list exists only in memory. When LND
restarts, the ban list is cleared, allowing previously banned malicious peers
to reconnect immediately.

#### Exploit Scenario

1. Malicious peer floods node with invalid channel announcements.
2. LND bans the peer after detecting the invalid messages.
3. LND restarts (routine maintenance, crash, or forced by attacker).
4. Ban list is empty — malicious peer reconnects.
5. Attack cycle repeats, causing persistent resource consumption.

#### Recommended Fix

```go
// Persist bans to the channel database
type PersistentBanStore struct {
    db kvdb.Backend
}

func (s *PersistentBanStore) AddBan(peer route.Vertex,
    reason string, duration time.Duration) error {

    return kvdb.Update(s.db, func(tx kvdb.RwTx) error {
        bucket, err := tx.CreateTopLevelBucket(banBucketKey)
        if err != nil {
            return err
        }
        ban := BanEntry{
            Peer:      peer,
            Reason:    reason,
            ExpiresAt: time.Now().Add(duration),
        }
        return bucket.Put(peer[:], ban.Serialize())
    }, func() {})
}
```

---

### Finding #10: AssumeChannelValid Skips UTXO Validation

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-010                              |
| **Severity**     | High                                 |
| **Location**     | `discovery/gossiper.go:394`          |
| **Chapter**      | Chapter 6 — Gossip & Discovery       |
| **Status**       | Open                                 |

#### Description

The `AssumeChannelValid` flag causes LND to skip UTXO validation for channel
announcements received via gossip. This is intended for Neutrino (light client)
mode where full UTXO set access is unavailable, but the flag can be enabled
on any node type.

#### Exploit Scenario

```
  Normal Validation:
  ┌────────────┐  announce  ┌─────────┐  verify  ┌──────────┐
  │ Malicious  │ ─────────▶ │   LND   │ ───────▶ │ Bitcoin  │
  │   Peer     │            │  Node   │          │ UTXO Set │
  └────────────┘            └─────────┘          └──────────┘
                               │                      │
                               │  "UTXO not found!"   │
                               │◀─────────────────────┘
                               │
                               ▼
                            REJECT ✓

  With AssumeChannelValid:
  ┌────────────┐  announce  ┌─────────┐
  │ Malicious  │ ─────────▶ │   LND   │ ──▶ ACCEPT (no UTXO check!)
  │   Peer     │            │  Node   │
  └────────────┘            └─────────┘
                               │
                               ▼
                        Fake channels in graph!
                        Routing attempts fail!
                        Payment reliability drops!
```

#### Recommended Fix

```go
// Only allow AssumeChannelValid for Neutrino backends
func validateAssumeChannelValid(cfg *Config) error {
    if cfg.Routing.AssumeChannelValid && cfg.Node.BackendName != "neutrino" {
        return fmt.Errorf("--routing.assumechanvalid is only safe " +
            "with Neutrino backend; full nodes should validate UTXOs")
    }
    return nil
}
```

---

### Finding #11: Onion Key Unencrypted by Default

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-011                              |
| **Severity**     | High                                 |
| **Location**     | `tor/`                               |
| **Chapter**      | Chapter 4 — Tor                      |
| **Status**       | Open                                 |

#### Description

When LND creates a Tor hidden service, the onion service private key is stored
in plaintext on disk. Any process or user with file-read access can steal the
key and impersonate the hidden service.

#### Recommended Fix

Encrypt the onion private key at rest using the wallet's encryption key:

```go
func EncryptOnionKey(key []byte, walletKey []byte) ([]byte, error) {
    block, err := aes.NewCipher(walletKey)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }
    return gcm.Seal(nonce, nonce, key, nil), nil
}
```

---

### Finding #12: NULL Auth Fallback for Tor Control

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-012                              |
| **Severity**     | High                                 |
| **Location**     | `tor/controller.go:470`              |
| **Chapter**      | Chapter 4 — Tor                      |
| **Status**       | Open                                 |

#### Description

When LND connects to the Tor control port, it queries available authentication
methods. If neither cookie nor hashed-password authentication is available, LND
falls back to `NULL` authentication — meaning no authentication at all. Any
local process could then control the Tor daemon.

#### Vulnerable Code Pattern

```go
// tor/controller.go — authentication fallback
func (c *Controller) authenticate() error {
    authMethods, err := c.getAuthMethods()
    if err != nil {
        return err
    }

    switch {
    case authMethods.hasCookie:
        return c.authenticateCookie()
    case authMethods.hasHashedPassword:
        return c.authenticatePassword()
    default:
        // Falls back to NULL auth — no authentication!
        return c.authenticateNull()
    }
}
```

#### Recommended Fix

```go
default:
    return fmt.Errorf("no secure authentication method available " +
        "for Tor control port; configure cookie or password auth")
```

---

### Finding #13: SkipProxy Leaks Real IP ⚠️ CRITICAL

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-013                              |
| **Severity**     | **CRITICAL**                         |
| **Location**     | `tor/`                               |
| **Chapter**      | Chapter 4 — Tor                      |
| **Status**       | Open                                 |

#### Description

This is the **only Critical-severity finding** in the entire audit. The
`SkipProxy` configuration option allows LND to bypass the SOCKS5 proxy (Tor)
for certain connections. When enabled, outbound connections use the host's
real network interface, revealing the node operator's true IP address.

For a node configured to run over Tor for privacy, this completely undermines
the anonymity guarantees. The operator's physical location and identity become
discoverable.

#### Threat Model

```
  WITH TOR (expected):
  ┌──────┐     ┌─────────┐     ┌───────┐     ┌──────────┐
  │ LND  │────▶│  SOCKS5  │────▶│  Tor  │────▶│  Peer    │
  │ Node │     │  Proxy   │     │Network│     │  Node    │
  └──────┘     └─────────┘     └───────┘     └──────────┘
  IP: hidden                                  Sees: Tor exit

  WITH SkipProxy (VULNERABLE):
  ┌──────┐                                    ┌──────────┐
  │ LND  │───────────────────────────────────▶│  Peer    │
  │ Node │          DIRECT CONNECTION          │  Node    │
  └──────┘                                    └──────────┘
  IP: 203.0.113.42                   Sees: 203.0.113.42 !!!
       │
       ▼
  Physical location revealed!
  Operator identity exposed!
  Targeted attacks possible!
```

#### Real-World Impact

- **Physical safety**: Operators in adversarial jurisdictions could face legal
  or physical threats if their Lightning node is linked to their identity.
- **Targeted attacks**: Knowing the real IP enables DDoS, eclipse attacks, and
  network-level surveillance.
- **Deanonymization cascade**: Linking a real IP to a node pubkey can
  deanonymize on-chain transactions and payment routes.

#### Recommended Fix

```go
// Option A: Remove SkipProxy entirely
// Delete the SkipProxy configuration option and all code paths that use it.

// Option B: Gate behind explicit unsafe flag with prominent warnings
func validateSkipProxy(cfg *Config) error {
    if cfg.Tor.SkipProxy {
        if !cfg.UnsafeDisablePrivacy {
            return fmt.Errorf(
                "--tor.skip-proxy-for-clearnet-targets requires " +
                "--unsafe-disable-privacy flag; this WILL leak your " +
                "real IP address to clearnet peers")
        }
        log.Criticalf("╔═══════════════════════════════════════════╗")
        log.Criticalf("║  WARNING: SkipProxy ENABLED               ║")
        log.Criticalf("║  Your real IP address WILL be revealed     ║")
        log.Criticalf("║  to clearnet peers. This defeats the       ║")
        log.Criticalf("║  purpose of running LND over Tor.          ║")
        log.Criticalf("╚═══════════════════════════════════════════╝")
    }
    return nil
}
```

---

### Finding #14: Tor Control Password in Process List

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-014                              |
| **Severity**     | Medium                               |
| **Location**     | `lncfg/tor.go:14`                    |
| **Chapter**      | Chapter 4 — Tor                      |
| **Status**       | Open                                 |

#### Description

The Tor control port password can be passed via command-line argument. On
Unix systems, command-line arguments are visible to all users via `ps aux` or
`/proc/<pid>/cmdline`.

#### Example Exposure

```bash
$ ps aux | grep lnd
user  1234  lnd --tor.password=MySuperSecretPassword123
#                               ^^^^^^^^^^^^^^^^^^^^^^^^
#                               Visible to ALL users on the system!
```

#### Recommended Fix

Support environment variable or file-based password:

```go
// lncfg/tor.go
type Tor struct {
    // PasswordFile is a path to a file containing the Tor control password.
    PasswordFile string `long:"password-file" description:"Path to file containing Tor control password"`

    // PasswordEnv is the environment variable name containing the password.
    PasswordEnv string `long:"password-env" description:"Environment variable containing Tor control password"`
}

func (t *Tor) ResolvePassword() (string, error) {
    switch {
    case t.PasswordFile != "":
        data, err := os.ReadFile(t.PasswordFile)
        return strings.TrimSpace(string(data)), err
    case t.PasswordEnv != "":
        return os.Getenv(t.PasswordEnv), nil
    default:
        return t.Password, nil
    }
}
```

---

### Finding #15: DeletePrivateKey Doesn't Zero Disk

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-015                              |
| **Severity**     | Medium                               |
| **Location**     | `tor/`                               |
| **Chapter**      | Chapter 4 — Tor                      |
| **Status**       | Open                                 |

#### Description

When LND deletes the Tor onion service private key, it uses `os.Remove()`,
which unlinks the file from the directory. However, the actual data remains on
disk until the filesystem overwrites those sectors. A forensic attacker could
recover the key.

#### Recommended Fix

```go
// SecureDelete overwrites a file with zeros before removing it.
func SecureDelete(path string) error {
    f, err := os.OpenFile(path, os.O_WRONLY, 0)
    if err != nil {
        return err
    }

    info, err := f.Stat()
    if err != nil {
        f.Close()
        return err
    }

    zeros := make([]byte, info.Size())
    if _, err := f.Write(zeros); err != nil {
        f.Close()
        return err
    }

    if err := f.Sync(); err != nil {
        f.Close()
        return err
    }

    f.Close()
    return os.Remove(path)
}
```

---

### Finding #16: No mlock for Onion Private Key

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-016                              |
| **Severity**     | Medium                               |
| **Location**     | `tor/`                               |
| **Chapter**      | Chapter 4 — Tor                      |
| **Status**       | Open                                 |

#### Description

Same class of vulnerability as Finding #1 (brontide secret key), but for Tor
onion service private keys. When loaded into memory, the key is not pinned
with `mlock()` and can be swapped to disk.

#### Recommended Fix

Apply the same `mlock()` pattern as recommended for Finding #1. Consider
creating a shared `securekey` package that handles memory-locked key storage
for all subsystems:

```go
// securekey/securekey.go
package securekey

import "golang.org/x/sys/unix"

// LockedBuffer is a byte slice pinned in physical RAM.
type LockedBuffer struct {
    data []byte
}

func NewLockedBuffer(size int) (*LockedBuffer, error) {
    buf := make([]byte, size)
    if err := unix.Mlock(buf); err != nil {
        return nil, fmt.Errorf("mlock failed: %w", err)
    }
    return &LockedBuffer{data: buf}, nil
}

func (b *LockedBuffer) Destroy() {
    for i := range b.data {
        b.data[i] = 0
    }
    unix.Munlock(b.data)
}
```

---

### Finding #17: Dust Fee Exposure (Already Mitigated)

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-017                              |
| **Severity**     | Informational (mitigated)            |
| **Location**     | `htlcswitch/switch.go:2577`          |
| **Chapter**      | Chapter 9 — HTLC Switch              |
| **Status**       | Mitigated                            |

#### Description

Dust-value HTLCs (below the dust threshold) are not represented as outputs in
commitment transactions. Instead, their value is added to miner fees. A
malicious counterparty could theoretically send many dust HTLCs to increase the
fee exposure of the commitment transaction.

#### Current Mitigation

LND already implements a `dustExceedsFeeThreshold` check that rejects HTLCs
when cumulative dust exposure exceeds a configurable threshold:

```go
// htlcswitch/switch.go
if dustExceedsFeeThreshold(...) {
    return ErrDustThresholdExceeded
}
```

#### Status

No additional action needed. The existing mitigation is effective. Continue
monitoring for new dust-related attack vectors as the protocol evolves.

---

### Finding #18: DefaultConnTimeout 120s DoS Potential

| Attribute        | Value                                |
|------------------|--------------------------------------|
| **ID**           | SEC-018                              |
| **Severity**     | Low                                  |
| **Location**     | `tor/net.go:16`                      |
| **Chapter**      | Chapter 4 — Tor                      |
| **Status**       | Open                                 |

#### Description

The default connection timeout for Tor connections is 120 seconds. An attacker
could open many connections simultaneously, each holding resources for up to
2 minutes, potentially exhausting connection slots or memory.

#### Recommended Fix

```go
const (
    // Reduce default timeout
    DefaultConnTimeout = 30 * time.Second

    // Add connection rate limiting
    MaxPendingConns    = 50
)
```

---

## Conclusion

### Summary of Themes

The 18 findings cluster around four recurring security themes:

```
  ┌─────────────────────────────────────────────────────────┐
  │              RECURRING SECURITY THEMES                  │
  │                                                         │
  │  1. MEMORY SAFETY         Findings: #1, #16             │
  │     └─ Secret keys in swappable memory                  │
  │                                                         │
  │  2. STATE PERSISTENCE     Findings: #5, #9              │
  │     └─ Critical state lost on restart                   │
  │                                                         │
  │  3. PRIVACY LEAKS         Findings: #11, #12, #13, #14  │
  │     └─ Tor integration gaps                             │
  │                                                         │
  │  4. DEFAULT CONFIGS       Findings: #2, #4, #10, #18    │
  │     └─ Insecure defaults                                │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
```

### Final Assessment

LND is a mature, well-engineered Lightning Network implementation. The findings
identified here represent opportunities for hardening rather than fundamental
design flaws. The development team's existing mitigations (e.g., dust fee
threshold, DLP protocol) demonstrate a strong security awareness.

By addressing the Critical and High findings in Phase 1, operators can
significantly improve their security posture. The Medium and Low findings
should be tracked and addressed as part of ongoing maintenance.

The next chapter provides a complete glossary of all security terms referenced
throughout this audit, and the final chapter outlines a toolkit for automated
security scanning of LND installations.

---

*End of Chapter 11*
