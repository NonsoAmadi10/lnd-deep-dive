# Chapter 3: Key Management & Wallet

```
 ┌──────────────────────────────────────────────────────────────┐
 │  Chapter 3: Key Management & Wallet                          │
 │  "The cryptographic foundation of your Lightning node"       │
 └──────────────────────────────────────────────────────────────┘
```

*Previous: [02 — Brontide Transport](./02-brontide-transport.md) | Next: 04 — Channel Lifecycle*

---

## Overview

Every Lightning node needs cryptographic keys — lots of them. Keys are used
for signing transactions, encrypting communications, creating payment hashes,
deriving channel secrets, and authenticating to watchtowers.

In this chapter, we explore how LND generates, stores, derives, and uses its
keys. This is arguably the most security-critical code in the entire codebase.

By the end of this chapter, you will understand:

- The **aezeed** seed format and how it differs from BIP-39
- **Hierarchical Deterministic (HD)** key derivation in LND
- The **10 key families** and what each one is used for
- The **KeyRing** and **SecretKeyRing** interfaces
- Security findings related to default passphrases and salt sizes

> 🔰 **For Beginners: What Are Cryptographic Keys?**
>
> A **private key** is a secret random number (256 bits in Bitcoin/Lightning).
> It must never be shared. From a private key, you can compute a **public key**
> using elliptic curve multiplication (a one-way mathematical operation).
>
> ```
> Private Key (secret)  →  Public Key (shareable)  →  Address
>     256-bit number        33-byte compressed          Bitcoin/LN ID
>
> You can go:    Private → Public       ✅
> You CANNOT go: Public  → Private      ❌ (computationally infeasible)
> ```
>
> In Lightning, your node's identity IS its public key. When someone says
> "connect to node 02abc...def", that hex string is a public key.

---

## 3.1 The aezeed Seed Format

### File: `aezeed/cipherseed.go`

LND uses its own custom seed format called **aezeed** (pronounced "A-Z seed"),
designed by Olaoluwa Osuntokun (roasbeef). It encodes a wallet seed as 24
mnemonic words, similar to BIP-39, but with important differences.

> 🔰 **For Beginners: What Is a Mnemonic Seed?**
>
> A **mnemonic seed** is a set of words (usually 12 or 24) that encode a
> random number from which all your wallet's keys are derived. The words are
> easier to write down and back up than a raw 256-bit number.
>
> Example: `abandon ability able about above absent absorb abstract ...`
>
> If you lose your device but have the seed words, you can restore all your
> keys and recover your funds. If someone else gets your seed words, they can
> steal all your funds.
>
> **NEVER** share your seed words. **NEVER** store them digitally (screenshots,
> notes apps, emails). Write them on paper and store them securely.

### Why Not BIP-39?

BIP-39 is the most common mnemonic standard used by Bitcoin wallets (Electrum,
Ledger, Trezor, etc.). LND chose to create aezeed instead for several reasons:

| Feature | BIP-39 | aezeed |
|---------|--------|--------|
| Version field | ❌ None | ✅ 1 byte — allows future upgrades |
| Birthday timestamp | ❌ None | ✅ 2 bytes — faster wallet sync |
| Encryption | ❌ Optional passphrase (no default) | ✅ Always encrypted (scrypt + aes) |
| Checksum | 4-8 bits | 32-bit CRC |

The **version field** is critical for forward compatibility. If the key
derivation scheme ever changes, the version byte tells the software how to
interpret the seed.

The **birthday timestamp** records when the seed was created. This allows LND
to skip scanning blocks before the birthday when restoring a wallet, which
can save hours of sync time.

```
┌────────────────────────────────────────────────────────────┐
│               aezeed Internal Structure                    │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Deciphered Seed (19 bytes):                               │
│  ┌──────────┬─────────────┬────────────────────────────┐   │
│  │ Version  │  Birthday   │        Entropy             │   │
│  │  1 byte  │   2 bytes   │       16 bytes             │   │
│  └──────────┴─────────────┴────────────────────────────┘   │
│       │           │                    │                    │
│       │           │                    └─ Random seed       │
│       │           │                       material          │
│       │           └─ Days since Bitcoin                     │
│       │              genesis block                          │
│       └─ Seed format version                               │
│          (currently 0)                                      │
│                                                            │
│  Enciphered Seed (33 bytes):                               │
│  ┌──────────┬───────────────┬────────┬──────────────┐     │
│  │ Version  │  Ciphertext   │  Salt  │   Checksum   │     │
│  │  1 byte  │   23 bytes    │ 5 bytes│   4 bytes    │     │
│  └──────────┴───────────────┴────────┴──────────────┘     │
│                                                            │
│  Mnemonic: 33 bytes → 264 bits → 24 words (11 bits each)  │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### The CipherSeed Struct

```go
// aezeed/cipherseed.go:180
type CipherSeed struct {
    // InternalVersion is the version of the seed format.
    InternalVersion uint8       // line 184

    // Birthday is the time the seed was created, in days since
    // the Bitcoin genesis block (January 3, 2009).
    Birthday uint16             // line 190

    // Entropy is 16 bytes of random data — the actual seed material
    // from which all keys are derived.
    Entropy [EntropySize]byte   // line 195, EntropySize = 16

    // salt is a random value used in the scrypt key derivation.
    salt [SaltSize]byte         // line 199, SaltSize = 5
}
```

### Seed Sizes (Constants)

```go
// aezeed/cipherseed.go — key constants
const (
    // CipherSeedVersion is the current version of the cipher seed.
    CipherSeedVersion uint8 = 0                    // line 26

    // DecipheredCipherSeedSize is the size of the deciphered seed:
    // 1 byte version + 2 bytes birthday + 16 bytes entropy = 19
    DecipheredCipherSeedSize = 19                   // line 37

    // EncipheredCipherSeedSize is the total enciphered size:
    // 1 byte version + 23 bytes ciphertext + 5 bytes salt + 4 bytes checksum = 33
    EncipheredCipherSeedSize = 33                   // line 58
)
```

---

## 3.2 Seed Encryption: scrypt + AES-256-GCM

The seed is encrypted before being encoded as mnemonic words. This prevents
anyone who sees the words from using them without the passphrase.

### The Encryption Process

```
                    User Passphrase
                          │
                          ▼
┌──────────────────────────────────────────────┐
│  scrypt(passphrase, salt, N=32768, r=8, p=1) │
│  Key derivation: slow by design               │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
                 32-byte key
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  AES-256-GCM Encrypt(key, seed_data)         │
│  Authenticated encryption                     │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
              23-byte ciphertext
                       │
                       ▼
┌──────────────────────────────────────────────┐
│  Encode: version + ciphertext + salt + CRC   │
│  33 bytes total → 24 mnemonic words          │
└──────────────────────────────────────────────┘
```

### scrypt Parameters

```go
// aezeed/cipherseed.go:108-110
const (
    scryptN = 32768  // CPU/memory cost parameter
    scryptR = 8      // block size parameter
    scryptP = 1      // parallelization parameter
)
```

> 🔰 **For Beginners: What Is scrypt?**
>
> **scrypt** is a password-based key derivation function designed to be
> **expensive** — it deliberately uses a lot of memory and CPU time. This
> makes brute-force attacks (trying every possible password) very slow.
>
> The parameters control how expensive it is:
> - **N (32768)**: Determines memory usage. Memory = 128 * r * N bytes = 32 MB.
>   Higher N = more memory = harder to brute-force.
> - **r (8)**: Block size. Affects both memory and CPU usage.
> - **p (1)**: Parallelization. Can be increased for multi-core CPUs but
>   doesn't help with scrypt resistance to GPUs/ASICs.
>
> For comparison, bcrypt is CPU-hard but memory-light. scrypt is both CPU-hard
> AND memory-hard, making it resistant to GPU/ASIC attacks where memory is
> limited per core.

---

## 3.3 Security Findings: Default Passphrase

> ⚠️ **Security Note: Default Passphrase "aezeed"**
>
> ```go
> // aezeed/cipherseed.go:119
> var defaultPassphrase = []byte("aezeed")
> ```
>
> When a user creates a new wallet without specifying a passphrase, the seed
> is encrypted using the string `"aezeed"` as the password.
>
> **Why this matters**: If someone finds your 24 mnemonic words (e.g., from a
> backup), they can try the default passphrase first. Since many users don't
> set a custom passphrase, this is likely to work.
>
> **Recommendation**: Always set a strong, unique passphrase when creating your
> LND wallet:
>
> ```bash
> lncli create
> # When prompted for passphrase, use a strong one!
> # Don't just press Enter (which uses the default)
> ```
>
> **Defense in depth**: Even with the default passphrase, an attacker still
> needs your 24 mnemonic words. But if your backup is compromised, the default
> passphrase provides no additional protection.

---

## 3.4 Security Findings: Small Salt

> ⚠️ **Security Note: 5-Byte Salt**
>
> ```go
> // aezeed/cipherseed.go:77
> const SaltSize = 5
> ```
>
> The salt used in the scrypt key derivation is only **5 bytes** (40 bits).
> Standard security practice recommends at least **16 bytes** (128 bits).
>
> **Why salts matter**: A salt ensures that two users with the same passphrase
> get different encryption keys. Without a salt (or with a short one), an
> attacker can precompute a "rainbow table" of scrypt outputs for common
> passwords.
>
> **Risk analysis**:
> - 5 bytes = 2^40 ≈ 1 trillion possible salts
> - This makes rainbow tables impractical for targeted attacks (too many salts)
> - But compared to 16 bytes (2^128), it's much smaller
> - For most users, the combination of scrypt cost + 5-byte salt provides
>   adequate protection, but it's below cryptographic best practices
>
> **Why only 5 bytes?** The constraint comes from the mnemonic encoding. The
> total enciphered seed must fit into 33 bytes (to encode as 24 words with 11
> bits each = 264 bits). Every byte added to the salt is a byte taken from
> something else.
>
> ```
> Budget: 33 bytes total
> ┌──────────┬───────────────┬────────┬──────────────┐
> │ Version  │  Ciphertext   │  Salt  │   Checksum   │
> │  1 byte  │   23 bytes    │ 5 bytes│   4 bytes    │
> └──────────┴───────────────┴────────┴──────────────┘
>                              ▲
>                              │
>                    Only 5 bytes left
>                    for salt after
>                    allocating the rest
> ```

---

## 3.5 HD Key Derivation

### What Is HD Key Derivation?

> 🔰 **For Beginners: Hierarchical Deterministic Wallets**
>
> An **HD wallet** (BIP-32) generates all keys from a single seed. "Hierarchical"
> means keys are organized in a tree structure. "Deterministic" means the same
> seed always produces the same keys.
>
> ```
> Seed (aezeed entropy)
>   │
>   └── Master Key
>         │
>         ├── Key Family 0 (MultiSig)
>         │     ├── Key 0
>         │     ├── Key 1
>         │     └── Key 2 ...
>         │
>         ├── Key Family 1 (Revocation)
>         │     ├── Key 0
>         │     ├── Key 1
>         │     └── Key 2 ...
>         │
>         └── Key Family 6 (NodeKey)
>               ├── Key 0  ← your node identity!
>               └── Key 1 ...
> ```
>
> The advantage: back up one seed, recover ALL keys. The tree structure lets
> different subsystems use different branches without interfering with each
> other.

### LND's Derivation Path

LND uses a custom BIP-32 derivation path:

```
m / 1017' / coinType' / keyFamily' / 0 / index
│    │         │            │        │     │
│    │         │            │        │     └─ Sequential key index
│    │         │            │        └─ Always 0 (no change addresses)
│    │         │            └─ Key family (0-9, see below)
│    │         └─ Bitcoin=0, Testnet=1, Litecoin=2
│    └─ LND's registered BIP-43 purpose (1017)
└─ Master key
```

> 📝 **Key Takeaway**
>
> The purpose `1017` is LND's registered BIP-43 purpose number. It ensures
> that LND-derived keys don't collide with keys derived by other wallet
> software (e.g., BIP-44 uses purpose `44`, BIP-84 uses purpose `84`).
>
> The `'` (prime/hardened) notation means these are **hardened derivation** steps.
> Hardened derivation prevents a compromised child key from revealing its parent.
> This is a critical security property for HD wallets.

> 🔰 **For Beginners: BIP-32 Derivation Paths**
>
> BIP-32 defines how to derive child keys from parent keys. A **derivation
> path** is like a file system path that tells you which branch of the key tree
> to follow.
>
> ```
> m/44'/0'/0'/0/0   ← BIP-44 Bitcoin wallet, first address
> m/84'/0'/0'/0/0   ← BIP-84 SegWit wallet, first address
> m/1017'/0'/6'/0/0 ← LND node key (key family 6, index 0)
> ```
>
> The `'` means **hardened derivation**. Without it, knowing a child public key
> AND the parent public key could allow computing other child private keys.
> Hardened derivation prevents this by requiring the parent private key for
> derivation.

---

## 3.6 The 10 Key Families

### File: `keychain/derivation.go:71-122`

LND defines 10 distinct key families, each serving a specific purpose in the
protocol. This separation ensures that keys used for different purposes are
cryptographically independent.

```go
// keychain/derivation.go:71-122
const (
    // KeyFamilyMultiSig (0) — keys for the 2-of-2 multisig funding output
    // that locks channel funds on-chain.
    KeyFamilyMultiSig KeyFamily = 0          // line 71

    // KeyFamilyRevocationBase (1) — base keys for computing revocation keys.
    // Used to punish cheating counterparties.
    KeyFamilyRevocationBase KeyFamily = 1    // line 76

    // KeyFamilyHtlcBase (2) — base keys for HTLC scripts in commitment
    // transactions.
    KeyFamilyHtlcBase KeyFamily = 2          // line 81

    // KeyFamilyPaymentBase (3) — keys for the to_remote output in
    // commitment transactions (immediate payment to counterparty).
    KeyFamilyPaymentBase KeyFamily = 3       // line 86

    // KeyFamilyDelayBase (4) — keys for the to_local output in commitment
    // transactions (time-locked payment to self).
    KeyFamilyDelayBase KeyFamily = 4         // line 92

    // KeyFamilyRevocationRoot (5) — root key for deriving per-commitment
    // revocation secrets using the shachain scheme.
    KeyFamilyRevocationRoot KeyFamily = 5    // line 96

    // KeyFamilyNodeKey (6) — the node's identity key. This IS your node's
    // public identity on the Lightning Network.
    KeyFamilyNodeKey KeyFamily = 6           // line 103

    // KeyFamilyBaseEncryption (7) — key for encrypting data at rest,
    // such as channel backups.
    KeyFamilyBaseEncryption KeyFamily = 7    // line 109

    // KeyFamilyTowerSession (8) — keys for authenticating to
    // watchtower servers.
    KeyFamilyTowerSession KeyFamily = 8      // line 115

    // KeyFamilyTowerID (9) — identity key for watchtower servers.
    KeyFamilyTowerID KeyFamily = 9           // line 122
)
```

### Key Family Usage Map

```
┌──────────────────────────────────────────────────────────────────────┐
│                   Key Family Usage in LND                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Family 0: MultiSig ──────────► Funding transactions (2-of-2 output)│
│                                 See: Chapter 4 (Channel Lifecycle)   │
│                                                                      │
│  Family 1: RevocationBase ────► Revocation keys for penalty tx       │
│                                 See: Chapter 5 (Commitments)         │
│                                                                      │
│  Family 2: HtlcBase ─────────► HTLC outputs in commitment txs       │
│                                 See: Chapter 6 (HTLC Forwarding)     │
│                                                                      │
│  Family 3: PaymentBase ──────► to_remote output (counterparty pays)  │
│                                 See: Chapter 5 (Commitments)         │
│                                                                      │
│  Family 4: DelayBase ────────► to_local output (self, time-locked)   │
│                                 See: Chapter 5 (Commitments)         │
│                                                                      │
│  Family 5: RevocationRoot ───► Shachain revocation tree root         │
│                                 See: Chapter 5 (Commitments)         │
│                                                                      │
│  Family 6: NodeKey ──────────► NODE IDENTITY (your LN pubkey)        │
│                                 See: Chapter 1 (Architecture)        │
│                                                                      │
│  Family 7: BaseEncryption ───► Encrypting SCBs and other data        │
│                                 See: Chapter 4 (Channel Lifecycle)   │
│                                                                      │
│  Family 8: TowerSession ────► Watchtower session authentication      │
│                                 See: Chapter 10 (Watchtowers)        │
│                                                                      │
│  Family 9: TowerID ─────────► Watchtower server identity             │
│                                 See: Chapter 10 (Watchtowers)        │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

> 📝 **Key Takeaway**
>
> Key family **6 (NodeKey)** at index 0 is your node's identity. This single
> key pair defines your node's public key on the Lightning Network. Losing this
> key means losing your node's identity; anyone who obtains it can impersonate
> your node.
>
> Key family **0 (MultiSig)** is used for channel funding. Each channel uses a
> new key from this family (incrementing the index). The key at index N is used
> for the Nth channel your node opens.

---

## 3.7 The Full Key Tree

Here's the complete HD key derivation tree for an LND node on Bitcoin mainnet:

```
Seed (16 bytes entropy from aezeed)
  │
  └── Master Key (BIP-32 root)
        │
        └── m/1017' (LND purpose)
              │
              └── m/1017'/0' (Bitcoin mainnet, coinType=0)
                    │
                    ├── m/1017'/0'/0'/0/0   ← MultiSig key #0 (first channel)
                    ├── m/1017'/0'/0'/0/1   ← MultiSig key #1 (second channel)
                    ├── m/1017'/0'/0'/0/2   ← MultiSig key #2 (third channel)
                    │   ...
                    │
                    ├── m/1017'/0'/1'/0/0   ← RevocationBase key #0
                    ├── m/1017'/0'/1'/0/1   ← RevocationBase key #1
                    │   ...
                    │
                    ├── m/1017'/0'/2'/0/0   ← HtlcBase key #0
                    │   ...
                    │
                    ├── m/1017'/0'/3'/0/0   ← PaymentBase key #0
                    │   ...
                    │
                    ├── m/1017'/0'/4'/0/0   ← DelayBase key #0
                    │   ...
                    │
                    ├── m/1017'/0'/5'/0/0   ← RevocationRoot key #0
                    │   ...
                    │
                    ├── m/1017'/0'/6'/0/0   ← NodeKey (YOUR NODE IDENTITY)
                    │
                    ├── m/1017'/0'/7'/0/0   ← BaseEncryption key #0
                    │   ...
                    │
                    ├── m/1017'/0'/8'/0/0   ← TowerSession key #0
                    │   ...
                    │
                    └── m/1017'/0'/9'/0/0   ← TowerID key #0
                        ...
```

---

## 3.8 The KeyRing Interface

### File: `keychain/derivation.go:189`

The `KeyRing` interface defines the basic key derivation operations:

```go
// keychain/derivation.go:189
type KeyRing interface {
    // DeriveNextKey derives the next key in the given key family.
    // The index is automatically incremented.
    DeriveNextKey(keyFam KeyFamily) (KeyDescriptor, error)  // line 193

    // DeriveKey derives a specific key identified by its KeyLocator
    // (family + index).
    DeriveKey(keyLoc KeyLocator) (KeyDescriptor, error)     // line 199
}
```

### Key Types

```go
// KeyLocator identifies a specific key in the HD tree.
type KeyLocator struct {
    // Family is the key family (0-9).
    Family KeyFamily

    // Index is the specific key index within the family.
    Index uint32
}

// KeyDescriptor wraps a KeyLocator with the actual public key.
type KeyDescriptor struct {
    KeyLocator

    // PubKey is the derived public key.
    PubKey *btcec.PublicKey
}
```

### Usage Example

```go
// Derive the node's identity key (family 6, index 0)
nodeKeyDesc, err := keyRing.DeriveKey(keychain.KeyLocator{
    Family: keychain.KeyFamilyNodeKey,  // 6
    Index:  0,
})
// nodeKeyDesc.PubKey is your node's public identity

// Derive the next multisig key for a new channel
multiSigDesc, err := keyRing.DeriveNextKey(keychain.KeyFamilyMultiSig)
// multiSigDesc.Index is auto-incremented
```

---

## 3.9 The SecretKeyRing Interface

### File: `keychain/derivation.go:208`

The `SecretKeyRing` extends `KeyRing` with operations that require the
private key:

```go
// keychain/derivation.go:208
type SecretKeyRing interface {
    // Embed the basic key derivation interface.
    KeyRing                                           // line 209

    // ECDHRing provides Elliptic Curve Diffie-Hellman operations.
    ECDHRing                                          // line 211

    // MessageSignerRing provides message signing operations.
    MessageSignerRing                                 // line 213

    // DerivePrivKey derives the private key for a given key descriptor.
    DerivePrivKey(keyDesc KeyDescriptor) (
        *btcec.PrivateKey, error,
    )                                                 // line 220
}
```

### Interface Composition

```
┌──────────────────────────────────────────────┐
│            SecretKeyRing                      │
│         (derivation.go:208)                   │
│                                               │
│  ┌────────────────────┐                       │
│  │     KeyRing        │  DeriveKey()          │
│  │  (derivation.go    │  DeriveNextKey()      │
│  │     :189)          │                       │
│  └────────────────────┘                       │
│                                               │
│  ┌────────────────────┐                       │
│  │     ECDHRing       │  ECDH()               │
│  │                    │  (Diffie-Hellman)      │
│  └────────────────────┘                       │
│                                               │
│  ┌────────────────────┐                       │
│  │ MessageSignerRing  │  SignMessage()         │
│  │                    │  SignMessageCompact()  │
│  └────────────────────┘                       │
│                                               │
│  DerivePrivKey()  — extract raw private key   │
│                                               │
└──────────────────────────────────────────────┘
```

> ⚠️ **Security Note**
>
> The `DerivePrivKey` method returns a raw `*btcec.PrivateKey`. This is the
> most sensitive operation in the key management system. Code that calls
> `DerivePrivKey` should:
>
> 1. Use the private key immediately for signing
> 2. Not store the returned key in any persistent data structure
> 3. Not log or serialize the key
>
> The `ECDHRing` interface is the safer alternative — it performs the
> Diffie-Hellman operation internally without exposing the private key.

---

## 3.10 Wallet Restoration

One of the key advantages of HD wallets is the ability to restore all keys
from a single seed. Here's how LND wallet restoration works:

```
Wallet Restoration Flow
━━━━━━━━━━━━━━━━━━━━━━━

1. User provides 24 mnemonic words + passphrase

2. LND decodes words → 33-byte enciphered seed
   (24 words × 11 bits = 264 bits = 33 bytes)

3. Extract salt (5 bytes) from enciphered seed

4. scrypt(passphrase, salt, N=32768, r=8, p=1) → 32-byte key

5. AES-256-GCM decrypt → 19-byte deciphered seed

6. Extract: version (1 byte) + birthday (2 bytes) + entropy (16 bytes)

7. BIP-32 master key derivation from entropy

8. Scan blockchain from birthday forward for:
   - Funding transactions using MultiSig keys
   - Sweep transactions using Delay/Payment keys
   - HTLC transactions using HtlcBase keys

9. Reconstruct channel state from on-chain data + SCB (if available)
```

> 📝 **Key Takeaway**
>
> The birthday field in the aezeed seed allows LND to skip scanning blocks
> before the wallet was created. For a wallet created in 2024, this could
> save scanning ~800,000 blocks (~15 years of Bitcoin history), dramatically
> reducing restoration time.

> ⚠️ **Security Note**
>
> Wallet restoration from seed alone can only recover **on-chain funds**. It
> cannot recover the current state of **Lightning channels** without a Static
> Channel Backup (SCB) file.
>
> If you lose your node and only have your seed:
> - ✅ On-chain Bitcoin: fully recoverable
> - ⚠️ Lightning channels: can initiate force-close (with SCB)
> - ❌ Lightning channels: cannot continue normally (state is lost)
>
> **Always keep an up-to-date SCB file** in addition to your seed backup.
> LND automatically writes SCB files to `~/.lnd/data/chain/bitcoin/mainnet/channel.backup`.

---

## Summary

LND's key management system is built on three layers:

```
┌─────────────────────────────────────────────────────┐
│  Layer 3: Key Families (10 families × N keys each)  │
│  keychain/derivation.go                             │
│  Organized by purpose: MultiSig, Revocation, HTLC,  │
│  Payment, Delay, NodeKey, Encryption, Watchtower     │
├─────────────────────────────────────────────────────┤
│  Layer 2: HD Derivation (BIP-32)                    │
│  Path: m/1017'/coinType'/keyFamily'/0/index         │
│  Deterministic: same seed → same keys               │
├─────────────────────────────────────────────────────┤
│  Layer 1: aezeed Seed (24 words)                    │
│  aezeed/cipherseed.go                               │
│  1 byte version + 2 bytes birthday + 16 bytes entropy│
│  Encrypted with scrypt + AES-256-GCM                 │
└─────────────────────────────────────────────────────┘
```

Key security findings:

1. **Default passphrase "aezeed"** (cipherseed.go:119) — provides no
   additional protection if mnemonic words are compromised.

2. **5-byte salt** (cipherseed.go:77) — below cryptographic best practices
   of 16+ bytes, constrained by the mnemonic encoding format.

3. The **KeyRing/SecretKeyRing** interface separation is good practice —
   most code only needs public key operations (KeyRing), with private key
   access (SecretKeyRing) restricted to signing code.

*Next chapter explores how these keys are used in practice to create and
manage Lightning channels.*

---

> 💡 **Exercises**
>
> **⭐ Easy:**
> 1. Open `aezeed/cipherseed.go` and find the `CipherSeed` struct (line 180).
>    Verify that the fields match the description in this chapter.
> 2. Find the `defaultPassphrase` constant (line 119). What is its value?
> 3. Open `keychain/derivation.go` and list all 10 key families with their
>    numeric values.
>
> **⭐⭐ Medium:**
> 4. Trace the `KeyRing` interface (derivation.go:189). Find a concrete
>    implementation of this interface in the codebase. What struct implements
>    it? What file is it in?
> 5. The aezeed salt is 5 bytes. Calculate how many possible salt values exist
>    (2^40). Compare this with a 16-byte salt (2^128). Express the difference
>    as a ratio.
> 6. Find the `DerivePrivKey` method in a concrete implementation. What
>    safeguards (if any) are in place to protect the returned private key?
>
> **⭐⭐⭐ Challenging:**
> 7. Write a Go program that creates an aezeed seed with a custom passphrase,
>    encodes it as 24 mnemonic words, then decodes it back and verifies the
>    entropy matches. Use the `aezeed` package directly.
> 8. Analyze the scrypt parameters (N=32768, r=8, p=1). How many bytes of
>    memory does scrypt use with these parameters? How long does one scrypt
>    computation take on your machine? Based on this, estimate how long a
>    brute-force attack on a 4-character passphrase would take.
> 9. Design an alternative to aezeed that uses a 16-byte salt while still
>    fitting into 24 mnemonic words. What trade-offs would you need to make?
>    (Hint: consider reducing entropy, ciphertext, or checksum size.)

---

*Previous: [02 — Brontide Transport](./02-brontide-transport.md) | Next: 04 — Channel Lifecycle*
