# Chapter 12: Complete Glossary

## Every Term You Need to Know for LND Security

---

This glossary provides comprehensive definitions for all technical terms used
throughout this security audit guide. Terms are sorted alphabetically. Each
entry includes a brief definition, an extended explanation, cross-references
to relevant chapters, and examples where helpful.

---

## How to Use This Glossary

- **Bold terms** in definitions link to other glossary entries.
- **Chapter references** point to where the term is discussed in depth.
- **See also** sections link to related concepts.
- Use `Ctrl+F` / `Cmd+F` to search for specific terms.

---

## A

### **Aezeed**

> *LND's custom mnemonic seed format for wallet backup and recovery.*

Aezeed is a 24-word mnemonic seed scheme designed specifically for LND. Unlike
**BIP-39**, aezeed includes a version byte, a birthday timestamp (for
efficient chain rescanning), and uses **scrypt** for key derivation with a
5-byte **salt**. The mnemonic encodes a 16-byte internal entropy value that,
combined with a user passphrase, derives the wallet's master **HD wallet**
root key.

- **Chapter Reference**: Chapter 1 — Aezeed Deep Dive
- **Related Findings**: #2 (default passphrase), #3 (salt size)
- **See also**: BIP-39, scrypt, HD wallet

**Example**: When you run `lncli create`, LND generates an aezeed mnemonic:

```
ability noise olive abandon ...(24 words)
```

---

### **Alias SCID**

> *A Short Channel ID that does not correspond to a real on-chain funding
> transaction.*

Alias SCIDs are used in **zero-conf** channels and the `option_scid_alias`
feature. They provide privacy by hiding the real funding transaction outpoint
and allow channels to be usable before on-chain confirmation. An alias SCID
is negotiated between peers and is only meaningful to those two peers — it is
not gossiped to the broader network.

- **Chapter Reference**: Chapter 6 — Gossip & Discovery
- **See also**: SCID, zero-conf, channel announcement

---

### **Anchor Output**

> *A special output in commitment transactions that enables fee bumping via
> Child-Pays-for-Parent (CPFP).*

Anchor outputs solve the problem of pre-signed commitment transactions having
stale fee rates. Each party in a channel has an anchor output (typically 330
satoshis) that they can spend with a high-fee child transaction to "bump" the
commitment transaction's effective fee rate. This is critical for timely
confirmation of **justice transactions** and force-close transactions.

- **Chapter Reference**: Chapter 9 — HTLC Switch & Commitment Transactions
- **See also**: commitment transaction, justice transaction, CPFP

**Analogy**: Think of an anchor output as a "tow hook" on the commitment
transaction — you can attach additional fee weight to pull it into a block
faster.

---

## B

### **Bearer Token**

> *A credential where possession alone grants access, with no additional
> identity verification required.*

In LND, **macaroons** function as bearer tokens. Anyone who holds a valid
macaroon can make API calls to the LND node with the permissions encoded in
that macaroon. This is why macaroon file permissions and secure storage are
critical — if an attacker obtains your `admin.macaroon`, they have full
control of your node.

- **Chapter Reference**: Chapter 5 — Macaroons & Access Control
- **Related Finding**: #4 (file permissions)
- **See also**: macaroon, caveat

---

### **BIP-32**

> *Bitcoin Improvement Proposal 32: Hierarchical Deterministic Wallets.*

BIP-32 defines the standard for deriving a tree of cryptographic key pairs
from a single master seed. LND uses BIP-32 derivation extensively through its
**key family** and **key derivation path** system. All channel keys, on-chain
keys, and identity keys are derived from the wallet's master seed using BIP-32
derivation paths like `m/1017'/0'/N'/0/index`.

- **Chapter Reference**: Chapter 3 — Keychain & Key Derivation
- **See also**: HD wallet, key derivation path, key family

```
  Master Seed
       │
       ├── m/1017'/0'/0'/0/0  (MultiSigKey)
       ├── m/1017'/0'/1'/0/0  (RevocationBaseKey)
       ├── m/1017'/0'/2'/0/0  (HtlcBaseKey)
       ├── m/1017'/0'/3'/0/0  (PaymentBaseKey)
       ├── m/1017'/0'/4'/0/0  (DelayBaseKey)
       ├── m/1017'/0'/5'/0/0  (RevocationRootKey)
       └── m/1017'/0'/6'/0/0  (NodeKey / identity)
```

---

### **BIP-39**

> *Bitcoin Improvement Proposal 39: Mnemonic code for generating
> deterministic keys.*

BIP-39 defines the standard 12/24-word mnemonic seed used by most Bitcoin
wallets. LND does **not** use BIP-39 — it uses **aezeed** instead, which
offers a version field and wallet birthday that BIP-39 lacks. However, LND
can import BIP-39 seeds for compatibility.

- **Chapter Reference**: Chapter 1 — Aezeed
- **See also**: aezeed, HD wallet

---

### **BOLT**

> *Basis of Lightning Technology — the specification documents for the
> Lightning Network protocol.*

BOLTs are the Lightning Network's equivalent of Bitcoin's BIPs. They define
the wire protocol, channel lifecycle, onion routing, gossip, and payment
encoding. Key BOLTs for security include BOLT-7 (gossip), BOLT-8 (encrypted
transport / **Noise protocol**), and BOLT-11 (payment requests).

- **Chapter Reference**: Referenced throughout; Chapter 6 (BOLT-7), Chapter 2
  (BOLT-8)
- **See also**: Noise protocol, gossip, channel announcement

**Reference**: https://github.com/lightning/bolts

---

### **Breach**

> *A protocol violation where a counterparty publishes a revoked commitment
> transaction, attempting to steal funds.*

When a channel state is updated, both parties revoke the previous state by
exchanging **revocation** keys. If a party later broadcasts a revoked state
(a breach), the counterparty can use the revocation key to sweep all channel
funds via a **justice transaction**. **Watchtowers** monitor for breaches on
behalf of offline nodes.

- **Chapter Reference**: Chapter 7 — Watchtower
- **Related Finding**: #5 (justice tx rebroadcast)
- **See also**: justice transaction, revocation, watchtower, commitment
  transaction

```
  Normal Update:
  State N  ──revoke──▶  State N+1

  Breach Attempt:
  Malicious party publishes State N (revoked)
       │
       ▼
  Counterparty detects, broadcasts justice tx
       │
       ▼
  All funds swept to honest party ✓
```

---

### **Brontide**

> *LND's implementation of the Noise Protocol Framework for encrypted
> peer-to-peer communication.*

Brontide provides authenticated, encrypted connections between Lightning
nodes using the **Noise protocol**'s XK handshake pattern. It uses
**ECDH** key exchange over **secp256k1**, **ChaCha20-Poly1305** for symmetric
encryption, and **SHA-256** for hashing. Every message between LND peers is
encrypted via Brontide.

- **Chapter Reference**: Chapter 2 — Brontide & Noise Protocol
- **Related Finding**: #1 (secret key not memory-locked)
- **See also**: Noise protocol, ChaCha20-Poly1305, ECDH, secp256k1

---

## C

### **Caveat**

> *A conditional restriction embedded in a macaroon that limits its
> capabilities.*

Caveats are the key innovation of macaroons over simple API tokens. They
allow attenuating (restricting) a macaroon's permissions without needing the
server's secret key. LND supports first-party caveats for time-based
expiration, IP address binding, and custom application-level constraints.

- **Chapter Reference**: Chapter 5 — Macaroons & Access Control
- **See also**: macaroon, bearer token

**Example**: Adding a time-based caveat:
```
Original macaroon: full admin access
  + caveat: "expiry = 2025-01-01T00:00:00Z"
  = Macaroon that expires on Jan 1, 2025
```

---

### **ChaCha20-Poly1305**

> *An authenticated encryption with associated data (AEAD) cipher combining
> the ChaCha20 stream cipher with the Poly1305 message authentication code.*

ChaCha20-Poly1305 is used by **Brontide** for all post-handshake encrypted
communication between LND peers. It provides both confidentiality (encryption)
and integrity (authentication) in a single operation. It was chosen over AES
because it performs well in software without hardware acceleration, making it
ideal for the diverse hardware that runs Lightning nodes (including Raspberry
Pi).

- **Chapter Reference**: Chapter 2 — Brontide & Noise Protocol
- **See also**: Brontide, Noise protocol, HMAC

---

### **Channel Announcement**

> *A gossip message (BOLT-7) that advertises a new payment channel to the
> Lightning Network.*

A `channel_announcement` message includes the channel's **SCID**, both nodes'
public keys, the Bitcoin keys used in the **funding transaction**, and
cryptographic signatures from all four keys. Nodes validate the announcement
by checking signatures and (optionally) verifying the **UTXO** on chain.

- **Chapter Reference**: Chapter 6 — Gossip & Discovery
- **Related Finding**: #10 (AssumeChannelValid skips UTXO check)
- **See also**: SCID, gossip, channel update, UTXO

---

### **Channel Update**

> *A gossip message (BOLT-7) that updates a channel's routing parameters.*

A `channel_update` carries fee rates, CLTV delta, minimum/maximum HTLC
amounts, and a timestamp. It is signed by the node on one side of the channel.
Updates propagate through the gossip network and are used by pathfinding
algorithms to construct payment routes.

- **Chapter Reference**: Chapter 6 — Gossip & Discovery
- **See also**: channel announcement, gossip, HTLC, CLTV

---

### **Circuit**

> *A logical construct in the HTLC switch that links an incoming HTLC to an
> outgoing HTLC, enabling payment forwarding.*

When LND forwards a payment, it creates a circuit that maps the incoming
channel + HTLC ID to the outgoing channel + HTLC ID. Circuits are persisted to
disk so they survive restarts. When the outgoing HTLC settles, the circuit is
used to propagate the settlement back to the incoming side.

- **Chapter Reference**: Chapter 9 — HTLC Switch
- **See also**: HTLC, onion routing

---

### **CLTV (CheckLockTimeVerify)**

> *A Bitcoin Script opcode that makes a transaction output unspendable until
> a specific block height.*

In Lightning, CLTV is used to enforce timeouts on **HTLCs**. If a payment is
not settled within the CLTV expiry, the sender can reclaim their funds. The
CLTV delta (the number of blocks added at each hop) is a critical routing
parameter — too low risks loss of funds; too high locks up capital.

- **Chapter Reference**: Chapter 9 — HTLC Switch
- **See also**: HTLC, CSV, commitment transaction

---

### **Commitment Transaction**

> *A pre-signed Bitcoin transaction representing the current state of a
> payment channel.*

Each party in a channel holds their own version of the commitment transaction.
It can be broadcast unilaterally to close the channel and claim funds. The
commitment transaction distributes the channel balance between the two parties
and includes outputs for all pending **HTLCs**. **Anchor outputs** enable fee
bumping.

- **Chapter Reference**: Chapter 9 — HTLC Switch & Commitment Transactions
- **See also**: breach, revocation, HTLC, anchor output, justice transaction

---

### **CSV (CheckSequenceVerify)**

> *A Bitcoin Script opcode that enforces a relative timelock, making an
> output unspendable until a certain number of blocks have passed since its
> confirmation.*

In Lightning channels, CSV timelocks are used for the `to_local` output of
commitment transactions. This delay gives the counterparty time to detect a
**breach** and broadcast a **justice transaction**. Typical CSV delays range
from 144 blocks (1 day) to 2016 blocks (2 weeks).

- **Chapter Reference**: Chapter 9 — HTLC Switch
- **See also**: CLTV, commitment transaction, breach, justice transaction

---

## D

### **Diffie-Hellman**

> *A key exchange protocol that allows two parties to derive a shared secret
> over an insecure channel.*

In LND, **ECDH** (Elliptic Curve Diffie-Hellman) is used in the **Brontide**
handshake to establish shared symmetric encryption keys. Both parties combine
their private key with the other's public key to derive the same shared
secret without transmitting any secret material.

- **Chapter Reference**: Chapter 2 — Brontide & Noise Protocol
- **See also**: ECDH, Brontide, Noise protocol

---

### **DLP (Data Loss Protection)**

> *A protocol extension that helps recover channel state when a node has lost
> data.*

DLP allows a node that has lost its channel database to reconnect with its
counterparty and negotiate a cooperative close based on the counterparty's
version of the channel state. This prevents the data-loss node from
accidentally broadcasting an old state (which would be a **breach**).
**SCB** (Static Channel Backup) triggers the DLP protocol on restore.

- **Chapter Reference**: Chapter 8 — Channel Backup (SCB)
- **Related Finding**: #6 (stale backup)
- **See also**: SCB, breach, commitment transaction

---

### **Dust**

> *A transaction output with a value so small that the fee to spend it
> exceeds its value.*

In Lightning, dust-value **HTLCs** are not represented as separate outputs
in **commitment transactions**. Instead, their value is added to miner fees.
This creates a "dust fee exposure" attack vector where an adversary sends
many tiny HTLCs to inflate the fee of the counterparty's commitment
transaction.

- **Chapter Reference**: Chapter 9 — HTLC Switch
- **Related Finding**: #17 (dust fee exposure, mitigated)
- **See also**: HTLC, commitment transaction

---

## E

### **ECDH (Elliptic Curve Diffie-Hellman)**

> *A key agreement protocol using elliptic curve cryptography to establish
> a shared secret between two parties.*

LND uses ECDH over the **secp256k1** curve for multiple purposes:
**Brontide** handshake key exchange, **Sphinx** onion routing shared secret
derivation, and peer authentication. The `keychain.SingleKeyECDH` interface
abstracts ECDH operations, allowing them to be performed by hardware security
modules if available.

- **Chapter Reference**: Chapter 2 (Brontide), Chapter 3 (Keychain)
- **See also**: Diffie-Hellman, secp256k1, Brontide, Sphinx

---

### **Eclipse Attack**

> *An attack where a malicious actor surrounds a node with attacker-controlled
> peers, isolating it from the honest network.*

In an eclipse attack, the victim node only receives information from the
attacker, who can feed false data (fake blocks, fake gossip) or withhold
legitimate data. In the Lightning context, eclipse attacks can prevent a
node from seeing **breach** transactions or time-sensitive **HTLC** resolutions,
potentially leading to fund loss.

- **Chapter Reference**: Chapter 6 — Gossip & Discovery
- **See also**: gossip, channel announcement, watchtower

---

## F

### **Funding Transaction**

> *The on-chain Bitcoin transaction that opens a payment channel by locking
> funds in a 2-of-2 multisig output.*

The funding transaction is the on-chain anchor of a Lightning channel. Both
channel parties must sign it. The **SCID** (Short Channel ID) encodes the
funding transaction's block height, transaction index, and output index.
**Channel announcements** reference the funding transaction for **UTXO**
validation.

- **Chapter Reference**: Chapter 6 (Gossip), Chapter 9 (Channel Lifecycle)
- **See also**: multisig, SCID, channel announcement, UTXO

---

## G

### **Gossip**

> *The peer-to-peer protocol (BOLT-7) for propagating channel and node
> information across the Lightning Network.*

The gossip protocol distributes three message types: **channel announcements**
(new channels), **channel updates** (routing parameters), and **node
announcements** (node metadata). Gossip is how pathfinding algorithms discover
routes. The gossip subsystem includes rate limiting, validation, and ban
mechanisms to prevent abuse.

- **Chapter Reference**: Chapter 6 — Gossip & Discovery
- **Related Findings**: #9 (ban list), #10 (UTXO validation)
- **See also**: channel announcement, channel update, node announcement,
  zombie channel

---

### **gRPC**

> *Google Remote Procedure Call — the protocol framework used for LND's
> API.*

LND exposes its functionality through a gRPC API, which supports streaming,
bidirectional communication, and protocol buffer serialization. The API is
protected by **TLS** for transport encryption and **macaroons** for
authentication and authorization.

- **Chapter Reference**: Chapter 5 — Macaroons & Access Control
- **See also**: macaroon, TLS, RPC

---

## H

### **HD Wallet (Hierarchical Deterministic Wallet)**

> *A wallet that derives all keys from a single master seed using a tree
> structure defined by BIP-32.*

LND's HD wallet derives all keys — channel keys, on-chain keys, identity keys,
and backup encryption keys — from the master seed generated by the **aezeed**
mnemonic. This means backing up the 24-word mnemonic (and passphrase) is
sufficient to recover the node's key material (though channel state requires
separate **SCB** backups).

- **Chapter Reference**: Chapter 1 (Aezeed), Chapter 3 (Keychain)
- **See also**: aezeed, BIP-32, key derivation path, key family

---

### **Hidden Service**

> *A Tor network service accessible via a .onion address that hides the
> server's real IP address.*

LND can run as a Tor hidden service (v3), making the node accessible over the
Tor network without revealing the operator's IP address. The hidden service is
identified by a .onion address derived from the **onion service** private key.

- **Chapter Reference**: Chapter 4 — Tor Integration
- **Related Findings**: #11 (key encryption), #13 (SkipProxy)
- **See also**: onion service, SOCKS5, Tor

---

### **HMAC (Hash-Based Message Authentication Code)**

> *A cryptographic construct that combines a hash function with a secret key
> to verify both data integrity and authenticity.*

HMACs are used extensively in LND: in **macaroon** verification (binding
caveats to the root key), in **Sphinx** onion packet construction (ensuring
hop data integrity), and in **Brontide** message authentication. LND primarily
uses HMAC-SHA256.

- **Chapter Reference**: Chapter 2 (Brontide), Chapter 5 (Macaroons)
- **See also**: SHA-256, macaroon, Sphinx

---

### **HTLC (Hash Time-Locked Contract)**

> *A conditional payment mechanism that uses hash locks and time locks to
> enable trustless multi-hop payments.*

HTLCs are the fundamental building block of Lightning payments. A sender locks
funds with a hash lock (requiring the preimage to claim) and a time lock
(allowing reclaim after expiry). Each hop in a payment route has an HTLC.
The preimage propagates backward through the route when the final recipient
reveals it.

- **Chapter Reference**: Chapter 9 — HTLC Switch
- **Related Finding**: #17 (dust fee exposure)
- **See also**: circuit, onion routing, CLTV, commitment transaction, dust

```
  HTLC Flow:
  Alice ──HTLC──▶ Bob ──HTLC──▶ Carol
                                  │
                            reveal preimage
                                  │
  Alice ◀──settle── Bob ◀──settle─┘
```

---

## J

### **Justice Transaction**

> *A penalty transaction that sweeps all channel funds when a counterparty
> publishes a revoked commitment transaction (breach).*

When a **breach** is detected, the honest party (or their **watchtower**)
constructs a justice transaction using the **revocation** key for the revoked
state. The justice transaction spends all outputs of the revoked commitment
transaction — both the cheater's balance and the pending HTLCs — to the honest
party's wallet. It is the enforcement mechanism that makes Lightning channels
trustless.

- **Chapter Reference**: Chapter 7 — Watchtower
- **Related Finding**: #5 (rebroadcast on restart)
- **See also**: breach, revocation, watchtower, commitment transaction

---

## K

### **Key Derivation Path**

> *The hierarchical path used to derive a specific key from a master seed
> in an HD wallet.*

LND uses BIP-43 purpose `1017'` for its key derivation. The full path
format is `m/1017'/coinType'/keyFamily'/0/index`, where `keyFamily` identifies
the key's purpose (multisig, revocation, HTLC, payment, delay, node identity)
and `index` is incremented for each new key of that family.

- **Chapter Reference**: Chapter 3 — Keychain & Key Derivation
- **See also**: BIP-32, HD wallet, key family

---

### **Key Family**

> *A category of keys within LND's key derivation hierarchy, defining the
> key's intended purpose.*

LND defines the following key families:

| Family | ID | Purpose                          |
|--------|----|----------------------------------|
| 0      | 0  | MultiSigKey (funding outputs)    |
| 1      | 1  | RevocationBaseKey                |
| 2      | 2  | HtlcBaseKey                      |
| 3      | 3  | PaymentBaseKey                   |
| 4      | 4  | DelayBaseKey                     |
| 5      | 5  | RevocationRootKey                |
| 6      | 6  | NodeKey (identity)               |
| 7      | 7  | StaticBackupKey                  |
| 8      | 8  | TowerSessionKey                  |

Each family has its own branch in the BIP-32 tree, providing cryptographic
isolation between key types.

- **Chapter Reference**: Chapter 3 — Keychain & Key Derivation
- **See also**: key derivation path, BIP-32, HD wallet

---

## M

### **Macaroon**

> *A bearer token format that supports decentralized attenuation through
> chained caveats, used by LND for API access control.*

Macaroons are LND's authentication and authorization mechanism. Unlike
traditional API keys, macaroons can be attenuated (restricted) by adding
**caveats** without needing the server's root key. LND generates three default
macaroons: `admin.macaroon` (full access), `readonly.macaroon` (read-only),
and `invoice.macaroon` (invoice-only).

- **Chapter Reference**: Chapter 5 — Macaroons & Access Control
- **Related Findings**: #4 (permissions), #7 (middleware), #8 (clone bug)
- **See also**: bearer token, caveat, gRPC, RPC

---

### **mlock**

> *A POSIX system call that pins memory pages in physical RAM, preventing
> them from being swapped to disk.*

`mlock()` is a critical defense for protecting secret key material in memory.
Without mlock, the operating system may swap memory pages containing private
keys to disk under memory pressure, where they could be recovered by an
attacker. LND currently does **not** use mlock for its cryptographic keys.

- **Chapter Reference**: Chapter 2 (Brontide), Chapter 4 (Tor)
- **Related Findings**: #1 (brontide key), #16 (onion key)
- **See also**: Brontide, onion service

---

### **Multisig**

> *A Bitcoin script that requires multiple signatures (typically 2-of-2) to
> spend funds.*

Lightning channels use 2-of-2 multisig outputs in the **funding transaction**.
Both channel parties must cooperatively sign to spend the funds. Unilateral
closes (force-closes) are possible because each party pre-signs **commitment
transactions** that spend the multisig output.

- **Chapter Reference**: Chapter 9 — Channel Lifecycle
- **See also**: funding transaction, commitment transaction, key family

---

## N

### **Neutrino**

> *A lightweight Bitcoin client (BIP-157/158) that validates block headers
> and uses compact block filters instead of downloading full blocks.*

LND supports Neutrino as an alternative to full Bitcoin node backends (btcd,
bitcoind). Neutrino nodes cannot validate **UTXOs** directly, which is why the
`AssumeChannelValid` flag exists — and why it's dangerous on non-Neutrino
backends.

- **Chapter Reference**: Chapter 6 — Gossip & Discovery
- **Related Finding**: #10 (AssumeChannelValid)
- **See also**: UTXO, channel announcement, gossip

---

### **Node Announcement**

> *A gossip message (BOLT-7) that advertises a node's metadata: alias, color,
> addresses, and features.*

Nodes periodically broadcast `node_announcement` messages to make themselves
discoverable for payments. The announcement includes the node's public key,
network addresses (including **onion service** addresses), and supported
feature flags.

- **Chapter Reference**: Chapter 6 — Gossip & Discovery
- **See also**: gossip, channel announcement, hidden service

---

### **Noise Protocol**

> *A framework for building cryptographic protocols with handshakes,
> authenticated encryption, and forward secrecy.*

The Noise Protocol Framework defines patterns for key exchange and symmetric
encryption. LND implements the **XK handshake pattern** in its **Brontide**
library: the initiator knows the responder's static public key (from the
node's public key), and the responder learns the initiator's key during the
handshake. This provides mutual authentication and forward secrecy.

- **Chapter Reference**: Chapter 2 — Brontide & Noise Protocol
- **See also**: Brontide, ChaCha20-Poly1305, ECDH, Diffie-Hellman

```
  XK Handshake Pattern:
  ──────────────────────
  Initiator (knows responder's pubkey):
    → e                          (ephemeral key)
    ← e, ee, se                  (ephemeral + DH results)
    → s, se                      (static key, encrypted)
    [handshake complete — encrypted channel established]
```

---

## O

### **Onion Routing**

> *A technique for anonymous communication where messages are encrypted in
> layers, each layer peeled by successive hops.*

LND uses onion routing (via **Sphinx**) for Lightning payments. The sender
constructs a multi-layered encrypted packet where each intermediate node can
only decrypt its own layer, learning only the previous and next hop. This
prevents intermediate nodes from knowing the payment's origin, destination,
or total amount.

- **Chapter Reference**: Chapter 9 — HTLC Switch, Chapter 10 — Onion Messages
- **See also**: Sphinx, HTLC, circuit

---

### **Onion Service**

> *A Tor hidden service that allows a server to receive connections without
> revealing its IP address.*

LND can operate as a Tor v3 onion service, making the node accessible via a
`.onion` address. The onion service private key is stored on disk and should
be encrypted for security. Onion services provide strong anonymity but
introduce dependencies on the Tor network's availability.

- **Chapter Reference**: Chapter 4 — Tor Integration
- **Related Findings**: #11 (unencrypted key), #15 (deletion), #16 (mlock)
- **See also**: hidden service, Tor, SOCKS5

---

## P

### **Pinning Attack**

> *An attack where a malicious party prevents a time-sensitive transaction
> from confirming by exploiting mempool policies.*

In Lightning, pinning attacks can prevent **justice transactions** or HTLC
timeout/success transactions from confirming before their deadlines. The
attacker broadcasts conflicting transactions that consume the victim's UTXO
input, making the legitimate transaction unrelayable. **Anchor outputs** and
CPFP partially mitigate this.

- **Chapter Reference**: Chapter 9 — HTLC Switch
- **See also**: justice transaction, anchor output, HTLC, commitment
  transaction

---

## R

### **Revocation**

> *The mechanism by which old channel states are invalidated, enabling
> penalty enforcement.*

When a channel state is updated, both parties exchange revocation secrets for
the previous state. These secrets allow construction of **justice
transactions** if the revoked state is ever broadcast. LND uses **shachain**
(a hash chain) for efficient revocation key storage, requiring O(log n) space
for n state updates.

- **Chapter Reference**: Chapter 7 (Watchtower), Chapter 9 (Commitments)
- **See also**: breach, justice transaction, shachain, commitment transaction

---

### **RPC (Remote Procedure Call)**

> *A protocol for executing functions on a remote server as if they were
> local.*

LND's API is built on **gRPC** and exposes hundreds of RPC methods for wallet
management, channel operations, payments, and administration. RPCs are
protected by **TLS** encryption and **macaroon** authentication.

- **Chapter Reference**: Chapter 5 — Macaroons & Access Control
- **See also**: gRPC, macaroon, TLS

---

## S

### **SCB (Static Channel Backup)**

> *A compact backup format that stores the minimum information needed to
> trigger channel recovery via the DLP protocol.*

SCBs contain channel point, remote node pubkey, and encrypted channel
parameters — but **not** the current channel state. They are designed to
trigger force-closes via the **DLP** protocol, allowing the remote party to
provide the latest state. SCBs are updated atomically on every channel state
change.

- **Chapter Reference**: Chapter 8 — Channel Backup (SCB)
- **Related Finding**: #6 (stale backup)
- **See also**: DLP, chanbackup, commitment transaction

---

### **SCID (Short Channel ID)**

> *A compact identifier for a Lightning channel, encoding its position in
> the blockchain.*

An SCID encodes three values: block height (3 bytes), transaction index
(3 bytes), and output index (2 bytes). This provides a globally unique,
compact reference to the channel's **funding transaction**. **Alias SCIDs**
provide an alternative for privacy and pre-confirmation channels.

- **Chapter Reference**: Chapter 6 — Gossip & Discovery
- **See also**: alias SCID, funding transaction, channel announcement

```
  SCID format (8 bytes):
  ┌──────────────┬──────────────┬──────────┐
  │ Block Height │   Tx Index   │ Out Idx  │
  │   (3 bytes)  │   (3 bytes)  │ (2 bytes)│
  └──────────────┴──────────────┴──────────┘
  Example: 700000:1234:0
```

---

### **Scrypt**

> *A password-based key derivation function designed to be computationally
> and memory-intensive, resisting brute-force attacks.*

LND's **aezeed** uses scrypt with parameters N=32768, r=8, p=1 to derive the
encryption key from the user's passphrase and a 5-byte salt. Scrypt's memory
hardness makes it expensive to parallelize on GPUs or ASICs, providing strong
protection against offline brute-force attacks.

- **Chapter Reference**: Chapter 1 — Aezeed
- **Related Finding**: #3 (salt size)
- **See also**: aezeed, salt

---

### **secp256k1**

> *The elliptic curve used by Bitcoin and Lightning for digital signatures
> and key exchange.*

Secp256k1 is used throughout LND: node identity keys, channel funding keys,
**ECDH** key exchange in **Brontide**, and **Sphinx** onion routing. All
public/private key pairs in LND are secp256k1 curve points.

- **Chapter Reference**: Chapter 2 (Brontide), Chapter 3 (Keychain)
- **See also**: ECDH, BIP-32, Brontide

---

### **SHA-256**

> *Secure Hash Algorithm 256-bit — a cryptographic hash function producing
> a 32-byte digest.*

SHA-256 is used in LND for **HMAC** construction, **shachain** revocation
derivation, hash locks in **HTLCs**, and as the hash function in the
**Noise protocol** handshake. Bitcoin's proof-of-work also uses double-SHA-256.

- **Chapter Reference**: Referenced throughout
- **See also**: HMAC, shachain, HTLC, Noise protocol

---

### **Shachain**

> *An efficient hash-chain construction for deriving and storing revocation
> secrets.*

Shachain allows storing O(log n) elements while being able to derive any of
n previously revealed elements. LND uses shachain to store **revocation**
secrets efficiently: instead of storing every revocation key for every state
update (which could be millions), it stores only ~49 hash preimages and
derives the rest on demand.

- **Chapter Reference**: Chapter 7 (Watchtower), Chapter 9 (Commitments)
- **See also**: revocation, SHA-256, breach

---

### **SOCKS5**

> *A proxy protocol that routes network traffic through an intermediary,
> used with Tor for anonymity.*

LND can route all outbound connections through a SOCKS5 proxy (typically
the Tor daemon's SOCKS port at 127.0.0.1:9050). This hides the node's real
IP address from peers. **Stream isolation** can be enabled for per-connection
circuit isolation.

- **Chapter Reference**: Chapter 4 — Tor Integration
- **Related Finding**: #13 (SkipProxy bypasses SOCKS5)
- **See also**: Tor, stream isolation, hidden service

---

### **Sphinx**

> *The onion routing packet format used for Lightning payments, based on
> the Sphinx cryptographic construction.*

Sphinx packets allow a payment sender to construct a single encrypted packet
that each hop can partially decrypt. Each hop learns only the previous hop,
next hop, and per-hop payload (amount, CLTV, next SCID). Sphinx provides
sender/receiver unlinkability and prevents intermediate nodes from
determining their position in the route.

- **Chapter Reference**: Chapter 9 — HTLC Switch
- **See also**: onion routing, HTLC, ECDH, HMAC

---

### **Stream Isolation**

> *A Tor feature that uses separate circuits for different connections,
> preventing traffic correlation.*

When stream isolation is enabled, LND creates a new Tor circuit for each
outbound connection. This prevents a malicious Tor exit node from correlating
different connections to the same LND node. Without stream isolation, multiple
connections may share the same circuit, creating a traffic analysis vector.

- **Chapter Reference**: Chapter 4 — Tor Integration
- **See also**: SOCKS5, Tor, hidden service

---

## T

### **TLS (Transport Layer Security)**

> *A cryptographic protocol providing encrypted communication between
> client and server.*

LND uses TLS to encrypt its **gRPC** API connections. The TLS certificate
is auto-generated and self-signed by default. LND also supports custom
certificates and automatic certificate rotation. TLS protects the API
independently of (and in addition to) the **macaroon** authentication layer.

- **Chapter Reference**: Chapter 5 — Macaroons & Access Control
- **See also**: gRPC, macaroon, RPC

---

## U

### **UTXO (Unspent Transaction Output)**

> *A Bitcoin transaction output that has not yet been spent, representing
> available funds.*

In the gossip protocol context, UTXO validation means checking that a
**channel announcement** references a real, unspent 2-of-2 multisig output
on the Bitcoin blockchain. This prevents fake channel injection.
`AssumeChannelValid` skips this check.

- **Chapter Reference**: Chapter 6 — Gossip & Discovery
- **Related Finding**: #10 (AssumeChannelValid)
- **See also**: funding transaction, channel announcement, Neutrino

---

## W

### **Watchtower**

> *A third-party service that monitors the blockchain for channel breaches
> on behalf of offline nodes.*

Watchtowers receive encrypted **justice transaction** blobs from their clients.
When a **breach** is detected (a revoked **commitment transaction** appears on
chain), the watchtower decrypts the blob and broadcasts the justice transaction
to penalize the cheating party. This protects nodes that cannot be online 24/7.

- **Chapter Reference**: Chapter 7 — Watchtower
- **Related Finding**: #5 (rebroadcast failure)
- **See also**: breach, justice transaction, revocation

```
  Watchtower Architecture:
  ┌────────┐  encrypted  ┌────────────┐  monitor  ┌────────────┐
  │  LND   │  ─blob───▶  │ Watchtower │  ───────▶ │ Blockchain │
  │  Node  │             │  Server    │           │            │
  └────────┘             └────────────┘           └─────┬──────┘
                                │                       │
                                │  breach detected!     │
                                │◀──────────────────────┘
                                │
                                ▼
                         Broadcast justice tx
```

---

## Z

### **Zero-Conf (Zero-Confirmation Channel)**

> *A Lightning channel that is usable for payments immediately, without
> waiting for on-chain confirmation of the funding transaction.*

Zero-conf channels sacrifice some security (the funding transaction could be
double-spent) for instant usability. They use **alias SCIDs** since the real
SCID (which encodes block height) is not yet known. Zero-conf is typically
used between trusted parties, such as a user and their LSP (Lightning Service
Provider).

- **Chapter Reference**: Chapter 6 — Gossip & Discovery
- **See also**: alias SCID, SCID, funding transaction

---

### **Zombie Channel**

> *A channel in the gossip graph that has not received a channel_update
> for an extended period, presumed inactive.*

LND periodically prunes zombie channels from its routing graph to reduce
memory usage and improve pathfinding efficiency. A channel is considered
a zombie if neither side has sent a **channel update** within a configurable
time window (default: 2 weeks). Zombie pruning prevents stale routing data
from degrading payment reliability.

- **Chapter Reference**: Chapter 6 — Gossip & Discovery
- **See also**: gossip, channel update, channel announcement

---

## Quick Reference: Term to Chapter Map

| Term                    | Primary Chapter(s)     |
|-------------------------|------------------------|
| Aezeed                  | Ch. 1                  |
| Anchor Output           | Ch. 9                  |
| Bearer Token            | Ch. 5                  |
| BIP-32                  | Ch. 3                  |
| BIP-39                  | Ch. 1                  |
| BOLT                    | Ch. 2, 6               |
| Breach                  | Ch. 7                  |
| Brontide                | Ch. 2                  |
| Caveat                  | Ch. 5                  |
| ChaCha20-Poly1305       | Ch. 2                  |
| Channel Announcement    | Ch. 6                  |
| Channel Update          | Ch. 6                  |
| Circuit                 | Ch. 9                  |
| CLTV                    | Ch. 9                  |
| Commitment Transaction  | Ch. 9                  |
| CSV                     | Ch. 9                  |
| Diffie-Hellman          | Ch. 2                  |
| DLP                     | Ch. 8                  |
| Dust                    | Ch. 9                  |
| ECDH                    | Ch. 2, 3               |
| Eclipse Attack          | Ch. 6                  |
| Funding Transaction     | Ch. 6, 9               |
| Gossip                  | Ch. 6                  |
| gRPC                    | Ch. 5                  |
| HD Wallet               | Ch. 1, 3               |
| Hidden Service          | Ch. 4                  |
| HMAC                    | Ch. 2, 5               |
| HTLC                    | Ch. 9                  |
| Justice Transaction     | Ch. 7                  |
| Key Derivation Path     | Ch. 3                  |
| Key Family              | Ch. 3                  |
| Macaroon                | Ch. 5                  |
| mlock                   | Ch. 2, 4               |
| Multisig                | Ch. 9                  |
| Neutrino                | Ch. 6                  |
| Node Announcement       | Ch. 6                  |
| Noise Protocol          | Ch. 2                  |
| Onion Routing           | Ch. 9, 10              |
| Onion Service           | Ch. 4                  |
| Pinning Attack          | Ch. 9                  |
| Revocation              | Ch. 7, 9               |
| RPC                     | Ch. 5                  |
| SCB                     | Ch. 8                  |
| SCID                    | Ch. 6                  |
| Scrypt                  | Ch. 1                  |
| secp256k1               | Ch. 2, 3               |
| SHA-256                 | All                    |
| Shachain                | Ch. 7, 9               |
| SOCKS5                  | Ch. 4                  |
| Sphinx                  | Ch. 9                  |
| Stream Isolation        | Ch. 4                  |
| TLS                     | Ch. 5                  |
| UTXO                    | Ch. 6                  |
| Watchtower              | Ch. 7                  |
| Zero-Conf               | Ch. 6                  |
| Zombie Channel          | Ch. 6                  |

---

*End of Chapter 12*
