# Chapter 2: Brontide Encrypted Transport (BOLT-8)

```
 ┌──────────────────────────────────────────────────────────────┐
 │  Chapter 2: Brontide Encrypted Transport (BOLT-8)            │
 │  "How Lightning nodes talk in secret"                        │
 └──────────────────────────────────────────────────────────────┘
```

*Previous: [01 — Node Architecture](./01-node-architecture.md) | Next: [03 — Key Management](./03-key-management.md)*

---

## Overview

When two Lightning nodes communicate, they need to ensure that:

1. **No one can read their messages** (confidentiality)
2. **No one can modify their messages** (integrity)
3. **Each node is who it claims to be** (authentication)

LND solves this with **Brontide** — a custom encrypted transport protocol
built on the Noise Protocol Framework. Brontide implements BOLT-8 (the
Lightning specification for transport encryption).

By the end of this chapter, you will understand:

- Why Lightning needs its own encrypted transport (not just TLS)
- How the Noise Protocol Framework works
- The three-act handshake that establishes an encrypted session
- How keys are rotated during communication
- Security properties and potential concerns

> 🔰 **For Beginners: Why Not Just Use TLS?**
>
> TLS (used for HTTPS) relies on **Certificate Authorities (CAs)** — trusted
> third parties that vouch for a server's identity. Lightning nodes are
> peer-to-peer — there is no central authority to issue certificates.
>
> Instead, Lightning uses the **Noise Protocol Framework**, which authenticates
> peers using their public keys directly. Every Lightning node has a public key
> (its "node ID"), and Brontide uses this key for mutual authentication without
> needing any certificate authority.
>
> ```
> TLS (Web):     Client ←→ CA ←→ Server
>                (Trust depends on certificate authority)
>
> Brontide (LN): Node A ←→ Node B
>                (Trust based on known public keys)
> ```

---

## 2.1 The Protocol Name Explained

Brontide uses the protocol descriptor:

```
Noise_XK_secp256k1_ChaChaPoly_SHA256
```

Let's break down each component:

```
┌──────────────────────────────────────────────────────────────────┐
│        Noise_XK_secp256k1_ChaChaPoly_SHA256                     │
│        ─────┬──┬─────────┬──────────┬──────                     │
│             │  │         │          │                            │
│             │  │         │          └─ SHA256: hash function     │
│             │  │         │             used for key derivation   │
│             │  │         │                                       │
│             │  │         └─ ChaChaPoly: ChaCha20-Poly1305       │
│             │  │            symmetric encryption cipher          │
│             │  │                                                 │
│             │  └─ secp256k1: elliptic curve for key exchange    │
│             │     (same curve Bitcoin uses)                      │
│             │                                                    │
│             └─ XK: handshake pattern                            │
│                X = initiator transmits key                       │
│                K = responder's key is Known to initiator         │
│                                                                  │
│     Noise: the protocol framework                                │
│     (designed by Trevor Perrin, co-creator of Signal)           │
└──────────────────────────────────────────────────────────────────┘
```

> 🔰 **For Beginners: Symmetric vs Asymmetric Encryption**
>
> **Asymmetric encryption** uses a key pair (public + private). It's slow but
> allows two parties to establish a shared secret without ever meeting.
> Example: RSA, Elliptic Curve Diffie-Hellman (ECDH).
>
> **Symmetric encryption** uses a single shared key for both encryption and
> decryption. It's fast but requires both parties to already have the same key.
> Example: ChaCha20, AES.
>
> Brontide uses **both**: asymmetric crypto (secp256k1 ECDH) during the
> handshake to establish a shared secret, then switches to symmetric crypto
> (ChaCha20-Poly1305) for all subsequent messages. This is the same approach
> used by TLS, Signal, and WireGuard.

> 🔰 **For Beginners: Diffie-Hellman Key Exchange**
>
> The Diffie-Hellman (DH) protocol allows two parties to create a shared secret
> over an insecure channel. Here's the intuition:
>
> ```
> Alice picks secret a, computes A = g^a (public)
> Bob picks secret b, computes B = g^b (public)
>
> Alice and Bob exchange A and B publicly.
>
> Alice computes: shared = B^a = g^(b*a)
> Bob computes:   shared = A^b = g^(a*b)
>
> Both arrive at the same shared secret!
> An eavesdropper sees A and B but cannot compute g^(a*b).
> ```
>
> In LND, this is done using **Elliptic Curve Diffie-Hellman (ECDH)** on the
> secp256k1 curve. The `btcec` library handles the math.

---

## 2.2 Source Files

The Brontide implementation lives in the `brontide/` package:

```
brontide/
├── noise.go        # Core: handshake, encryption, key rotation
├── noise_test.go   # Tests for the Noise protocol
├── conn.go         # Encrypted connection wrapper (net.Conn)
├── listener.go     # TCP listener with handshake limits
└── log.go          # Package-level logger
```

The main file is `noise.go`, which contains all the cryptographic primitives
and the `Machine` struct that manages an encrypted session.

---

## 2.3 Key Structs

### cipherState (`noise.go:103`)

Holds the symmetric encryption state for one direction of communication:

```go
// noise.go:103
type cipherState struct {
    // nonce is the nonce used for encrypting messages.
    nonce uint64

    // secretKey is the symmetric key used for encrypting messages.
    // TODO(roasbeef): m-lock??
    secretKey [32]byte

    // salt is an additional secret used during key rotation.
    salt [32]byte

    // cipher is the AEAD cipher instance using secretKey.
    cipher cipher.AEAD
}
```

> ⚠️ **Security Note: Missing Memory Lock**
>
> Notice the TODO at line ~117: `// TODO(roasbeef): m-lock??`
>
> The `secretKey` field holds the symmetric encryption key in plain memory.
> Ideally, this memory should be **locked** using `mlock()` (a Unix system
> call that prevents the OS from swapping the memory page to disk).
>
> **Why this matters**: If the OS swaps this memory to disk (swap space), the
> encryption key could persist on the hard drive long after the process exits.
> An attacker with physical access to the disk could potentially recover it.
>
> **`mlock()` explained**: The `mlock()` system call tells the operating system
> "never write this memory page to the swap file on disk." It's commonly used
> for encryption keys, passwords, and other sensitive data. Go doesn't have
> built-in `mlock()` support, which is why this remains a TODO.
>
> **Practical risk**: Low for most deployments. Swap-based key recovery requires
> physical access to the machine and the ability to read raw disk sectors. But
> for high-security environments, this is worth noting.

### symmetricState (`noise.go:215`)

Manages the evolving handshake state, building upon `cipherState`:

```go
// noise.go:215
type symmetricState struct {
    cipherState

    // chainingKey is used to derive new keys during the handshake.
    chainingKey [32]byte

    // tempKey is used as an intermediate encryption key.
    tempKey [32]byte

    // handshakeDigest accumulates the handshake transcript.
    handshakeDigest [32]byte
}
```

The `symmetricState` is the Noise framework's concept of evolving cryptographic
state. As the handshake progresses, new key material is mixed in, making each
step dependent on all previous steps.

### handshakeState (`noise.go:310`)

Holds the state for the in-progress handshake:

```go
// noise.go:310
type handshakeState struct {
    symmetricState

    // localStatic is our node's long-term key pair.
    localStatic keychain.SingleKeyECDH

    // localEphemeral is a one-time key pair for this handshake.
    localEphemeral *btcec.PrivateKey

    // remoteStatic is the remote node's long-term public key.
    remoteStatic *btcec.PublicKey

    // remoteEphemeral is the remote's one-time public key.
    remoteEphemeral *btcec.PublicKey

    // initiator indicates whether we initiated the connection.
    initiator bool
}
```

### Machine (`noise.go:392`)

The top-level struct that manages a complete encrypted session:

```go
// noise.go:392
type Machine struct {
    sendCipher cipherState
    recvCipher cipherState

    // ephemeralGen generates ephemeral key pairs for each handshake.
    ephemeralGen func() (*btcec.PrivateKey, error)

    handshakeState

    // nextCipherHeader and nextCipherBody are used to read
    // encrypted messages in two steps (length prefix + body).
    nextCipherHeader [lengthHeaderSize]byte
    nextCipherBody   [math.MaxUint16 + macSize]byte

    // nextHeaderSend and nextHeaderBody are write buffers.
    nextHeaderSend [lengthHeaderSize + macSize]byte
    nextHeaderBody []byte
}
```

Here's how these structs compose:

```
┌──────────────────────────────────────────┐
│              Machine                      │
│          (noise.go:392)                   │
│                                           │
│  ┌─────────────────┐ ┌─────────────────┐ │
│  │  sendCipher     │ │  recvCipher     │ │
│  │ (cipherState)   │ │ (cipherState)   │ │
│  │  - secretKey    │ │  - secretKey    │ │
│  │  - nonce        │ │  - nonce        │ │
│  │  - salt         │ │  - salt         │ │
│  └─────────────────┘ └─────────────────┘ │
│                                           │
│  ┌──────────────────────────────────────┐ │
│  │         handshakeState               │ │
│  │        (noise.go:310)                │ │
│  │                                      │ │
│  │  ┌────────────────────────────────┐  │ │
│  │  │       symmetricState           │  │ │
│  │  │      (noise.go:215)            │  │ │
│  │  │                                │  │ │
│  │  │  ┌──────────────────────────┐  │  │ │
│  │  │  │     cipherState          │  │  │ │
│  │  │  │    (noise.go:103)        │  │  │ │
│  │  │  └──────────────────────────┘  │  │ │
│  │  └────────────────────────────────┘  │ │
│  └──────────────────────────────────────┘ │
└──────────────────────────────────────────┘
```

---

## 2.4 The Three-Act Handshake

The Brontide handshake consists of three "acts" — carefully choreographed
message exchanges that establish mutual authentication and a shared secret.

```
┌──────────────┐                              ┌──────────────┐
│   Initiator  │                              │  Responder   │
│   (Alice)    │                              │   (Bob)      │
│              │                              │              │
│  Knows:      │                              │  Knows:      │
│  - own keys  │                              │  - own keys  │
│  - Bob's     │                              │              │
│    pubkey    │                              │              │
├──────────────┤                              ├──────────────┤
│              │                              │              │
│  GenActOne() │───── Act 1 (50 bytes) ──────►│ RecvActOne() │
│              │   ephemeral_key + tag         │              │
│              │                              │              │
│  RecvActTwo()│◄──── Act 2 (50 bytes) ───────│ GenActTwo()  │
│              │   ephemeral_key + tag         │              │
│              │                              │              │
│ GenActThree()│──── Act 3 (66 bytes) ────────►│RecvActThree()│
│              │   static_key + tag            │              │
│              │                              │              │
├──────────────┤                              ├──────────────┤
│              │                              │              │
│  ✅ Session   │◄═══ Encrypted Channel ══════►│  ✅ Session   │
│  Established │      (ChaCha20-Poly1305)     │  Established │
│              │                              │              │
└──────────────┘                              └──────────────┘
```

### Act One: Initiator → Responder (50 bytes)

```go
// noise.go:490
func (b *Machine) GenActOne() ([ActOneSize]byte, error)
```

The initiator:
1. Generates an **ephemeral key pair** (one-time use, discarded after handshake)
2. Performs ECDH with the responder's **static public key** (known in advance)
3. Sends: `version (1 byte) + ephemeral_pubkey (33 bytes) + MAC tag (16 bytes)`

Total: **50 bytes** (defined as `ActOneSize`)

```go
// Act One message layout:
// ┌─────────┬────────────────────┬──────────────┐
// │ version │  ephemeral_pubkey  │   MAC tag    │
// │ 1 byte  │     33 bytes       │   16 bytes   │
// └─────────┴────────────────────┴──────────────┘
// Total: 50 bytes
```

### Act Two: Responder → Initiator (50 bytes)

```go
// noise.go:569
func (b *Machine) GenActTwo() ([ActTwoSize]byte, error)
```

The responder:
1. Generates its own **ephemeral key pair**
2. Performs ECDH with the initiator's **ephemeral public key** (received in Act One)
3. Sends: `version (1 byte) + ephemeral_pubkey (33 bytes) + MAC tag (16 bytes)`

Total: **50 bytes** (same structure as Act One)

### Act Three: Initiator → Responder (66 bytes)

```go
// noise.go:646
func (b *Machine) GenActThree() ([ActThreeSize]byte, error)
```

The initiator:
1. **Encrypts** its own **static public key** with the derived session key
2. Performs a final ECDH to derive the session encryption keys
3. Sends: `version (1 byte) + encrypted_static_pubkey (33 + 16 bytes) + MAC tag (16 bytes)`

Total: **66 bytes** (note: larger because it includes the encrypted static key)

```go
// Act Three message layout:
// ┌─────────┬──────────────────────────────────┬──────────────┐
// │ version │  encrypted_static_pubkey + MAC   │   MAC tag    │
// │ 1 byte  │         33 + 16 = 49 bytes       │   16 bytes   │
// └─────────┴──────────────────────────────────┴──────────────┘
// Total: 66 bytes
```

> 📝 **Key Takeaway**
>
> After the three acts, both parties have:
> 1. **Authenticated** each other using their static keys
> 2. **Established** a shared secret using three rounds of ECDH
> 3. **Derived** separate encryption keys for sending and receiving
>
> The `XK` pattern means the **initiator's identity is hidden** from passive
> observers (it's only revealed in Act Three, encrypted). The **responder's
> identity is assumed known** by the initiator before connecting.

---

## 2.5 Key Derivation During Handshake

The handshake performs multiple rounds of key derivation. Each ECDH result is
mixed into the handshake state using HKDF (HMAC-based Key Derivation Function):

```
Act One:
  ECDH(initiator_ephemeral, responder_static) → shared_secret_1
  HKDF(chaining_key, shared_secret_1) → new_chaining_key, temp_key_1

Act Two:
  ECDH(responder_ephemeral, initiator_ephemeral) → shared_secret_2
  HKDF(chaining_key, shared_secret_2) → new_chaining_key, temp_key_2

Act Three:
  ECDH(initiator_static, responder_ephemeral) → shared_secret_3
  HKDF(chaining_key, shared_secret_3) → new_chaining_key, temp_key_3

Final:
  HKDF(chaining_key, zero) → send_key, recv_key
```

This cascading derivation ensures **forward secrecy**: if any single key is
compromised, past sessions remain secure because each session uses unique
ephemeral keys.

---

## 2.6 Key Rotation

After the handshake, keys are rotated periodically to limit the damage of a
key compromise:

```go
// noise.go:45
const keyRotationInterval = 1000
```

Every **1000 messages**, the encryption key is rotated by deriving a new key
from the current chaining key:

```go
// Simplified key rotation logic:
func (c *cipherState) maybeRotateKey() {
    if c.nonce == keyRotationInterval {
        // Derive new key from current salt
        newSalt, newKey := hkdf(c.salt, c.secretKey[:])

        c.salt = newSalt
        c.secretKey = newKey
        c.nonce = 0  // Reset nonce

        // Reinitialize cipher with new key
        c.cipher = newCipher(c.secretKey)
    }
}
```

```
┌─────────────────────────────────────────────────────────────┐
│                    Key Rotation Timeline                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Messages 0-999:    Key_0                                   │
│  ──────────────────────────                                 │
│                         │                                   │
│                    ┌────┴────┐                               │
│                    │ ROTATE  │ HKDF(salt, key_0)             │
│                    └────┬────┘                               │
│                         │                                   │
│  Messages 0-999:    Key_1  (nonce resets to 0)              │
│  ──────────────────────────                                 │
│                         │                                   │
│                    ┌────┴────┐                               │
│                    │ ROTATE  │ HKDF(salt, key_1)             │
│                    └────┬────┘                               │
│                         │                                   │
│  Messages 0-999:    Key_2  (nonce resets to 0)              │
│  ──────────────────────────                                 │
│                                                             │
│  ... and so on for the lifetime of the connection           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

> 📝 **Key Takeaway**
>
> Key rotation limits exposure: if an attacker somehow recovers a session key,
> they can only decrypt at most 1000 messages. Combined with ephemeral keys
> (forward secrecy), this provides defense in depth.

---

## 2.7 Connection Limits and Timeouts

### File: `brontide/listener.go`

The Brontide listener enforces limits to prevent denial-of-service attacks:

```go
// listener.go:16
const defaultHandshakes = 50
```

**Maximum 50 concurrent handshakes**: Only 50 connections can be in the
handshake phase simultaneously. Additional connection attempts are queued.

```go
// noise.go:51
const handshakeReadTimeout = time.Second * 5
```

**5-second handshake timeout**: If a peer doesn't complete the handshake
within 5 seconds, the connection is dropped.

```
┌─────────────────────────────────────────────────────┐
│           Connection Flow with Limits                │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Incoming TCP Connection                            │
│         │                                           │
│         ▼                                           │
│  ┌──────────────────┐                               │
│  │ Handshake slots  │  Max 50 concurrent            │
│  │ available?       │                               │
│  └──────┬───────────┘                               │
│     Yes │        No → Queue / Reject                │
│         ▼                                           │
│  ┌──────────────────┐                               │
│  │ Start handshake  │  5-second timeout             │
│  │ (3 acts)         │                               │
│  └──────┬───────────┘                               │
│  Success│     Timeout/Failure → Drop connection     │
│         ▼                                           │
│  ┌──────────────────┐                               │
│  │ Encrypted conn   │  Ready for LN messages        │
│  │ established      │                               │
│  └──────────────────┘                               │
│                                                     │
└─────────────────────────────────────────────────────┘
```

> ⚠️ **Security Note**
>
> The 50-concurrent-handshake limit and 5-second timeout are DoS mitigations.
> A malicious peer could try to exhaust your handshake slots by opening
> connections and never completing the handshake. The timeout ensures that
> stale handshakes are cleaned up quickly.
>
> For a high-traffic routing node, monitor your handshake slot utilization.
> If legitimate connections are being rejected, you may need to tune these
> values (though changing them requires modifying the source code).

---

## 2.8 Message Encryption Format

After the handshake, all messages are encrypted using ChaCha20-Poly1305
in a two-part format:

```
Encrypted Message Format:
┌────────────────────────────────────┬──────────────────────────────────┐
│       Header (18 bytes)            │        Body (variable)           │
├────────────────────────────────────┼──────────────────────────────────┤
│  encrypted_length (2) + MAC (16)  │  encrypted_payload + MAC (16)    │
└────────────────────────────────────┴──────────────────────────────────┘

Step 1: Read and decrypt the 18-byte header to learn the body length.
Step 2: Read and decrypt the body (length + 16 bytes for MAC).
```

This two-step read is important: the recipient first decrypts the length
header to know how many bytes to read for the body. The length itself is
encrypted to prevent traffic analysis (an attacker cannot determine message
sizes without the key).

```go
// Simplified read flow:
func (b *Machine) ReadMessage(r io.Reader) ([]byte, error) {
    // Step 1: Read and decrypt 18-byte header
    io.ReadFull(r, b.nextCipherHeader[:])
    length := b.recvCipher.Decrypt(b.nextCipherHeader[:])

    // Step 2: Read and decrypt the body
    bodyWithMac := length + macSize
    io.ReadFull(r, b.nextCipherBody[:bodyWithMac])
    payload := b.recvCipher.Decrypt(b.nextCipherBody[:bodyWithMac])

    return payload, nil
}
```

> 📝 **Key Takeaway**
>
> Encrypting the message length prevents traffic analysis. Without this, an
> eavesdropper could infer message types by their size (e.g., "a 33-byte
> message is probably a node announcement"). With encrypted lengths, all they
> see is a stream of opaque bytes.

---

## 2.9 Security Properties

Brontide provides several security properties:

| Property | Description | How Achieved |
|----------|-------------|--------------|
| **Confidentiality** | Messages cannot be read by third parties | ChaCha20-Poly1305 encryption |
| **Integrity** | Messages cannot be modified in transit | Poly1305 MAC on every message |
| **Authentication** | Both peers verify each other's identity | Static key exchange in handshake |
| **Forward Secrecy** | Past sessions secure even if keys leak | Ephemeral keys per session |
| **Key Freshness** | Limits exposure from key compromise | Key rotation every 1000 messages |
| **Identity Hiding** | Initiator's identity hidden from observers | Static key encrypted in Act Three |

### What Brontide Does NOT Protect Against

- **Metadata**: An observer can see *that* two IP addresses are communicating,
  even though they cannot read the content.
- **Timing Analysis**: Message timing patterns may reveal information about
  payment activity.
- **Endpoint Compromise**: If an attacker controls one of the nodes, they can
  read all messages on that connection.

---

## 2.10 The Encrypted Connection Wrapper

### File: `brontide/conn.go`

After the handshake, the `Machine` is wrapped in a `Conn` struct that
implements Go's standard `net.Conn` interface:

```go
// conn.go — simplified
type Conn struct {
    conn    net.Conn   // underlying TCP connection
    noise   *Machine   // encryption state machine
}

func (c *Conn) Read(b []byte) (int, error) {
    // Decrypt incoming data
    plaintext, err := c.noise.ReadMessage(c.conn)
    copy(b, plaintext)
    return len(plaintext), err
}

func (c *Conn) Write(b []byte) (int, error) {
    // Encrypt outgoing data
    return c.noise.WriteMessage(c.conn, b)
}
```

Because `Conn` implements `net.Conn`, the rest of LND can use it exactly like
a normal TCP connection — all encryption and decryption happens transparently.

```
┌───────────────────────────────────────────────────────────┐
│                 LND Protocol Stack                        │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  Lightning Messages (BOLT-1)                        │  │
│  │  channel_open, update_add_htlc, gossip, etc.        │  │
│  └──────────────────────┬──────────────────────────────┘  │
│                         │                                 │
│  ┌──────────────────────┴──────────────────────────────┐  │
│  │  Brontide Encrypted Transport (BOLT-8)              │  │
│  │  brontide.Conn (implements net.Conn)                │  │
│  │  Encryption + Authentication + Key Rotation         │  │
│  └──────────────────────┬──────────────────────────────┘  │
│                         │                                 │
│  ┌──────────────────────┴──────────────────────────────┐  │
│  │  TCP/IP                                             │  │
│  │  Standard network transport                         │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

---

## Summary

Brontide provides the secure foundation upon which all Lightning communication
is built:

```
Noise_XK_secp256k1_ChaChaPoly_SHA256
   │   │      │          │        │
   │   │      │          │        └── Hash: key derivation
   │   │      │          └── Cipher: fast symmetric encryption
   │   │      └── Curve: same as Bitcoin (interop)
   │   └── Pattern: initiator identity hidden
   └── Framework: formally verified, battle-tested
```

Key points:
1. Three-act handshake establishes authenticated, encrypted channels
2. Ephemeral keys provide forward secrecy
3. Key rotation every 1000 messages limits exposure
4. The `secretKey` field lacks `mlock()` protection (noise.go:117 TODO)
5. 50 concurrent handshakes + 5s timeout = DoS mitigation

*Next chapter: [03 — Key Management & Wallet](./03-key-management.md) explores
how LND generates, stores, and derives the cryptographic keys that Brontide
(and everything else) depends on.*

---

> 💡 **Exercises**
>
> **⭐ Easy:**
> 1. Open `brontide/noise.go` and find the `Machine` struct (line 392). What
>    two `cipherState` fields does it contain? Why are there two?
> 2. What is the size of Act One, Act Two, and Act Three? Why is Act Three
>    larger?
>
> **⭐⭐ Medium:**
> 3. Read `brontide/listener.go`. Trace how `defaultHandshakes` (line 16) is
>    used to limit concurrent connections. What happens when the limit is
>    reached?
> 4. Find the `keyRotationInterval` constant (noise.go:45). Trace through the
>    code to find where rotation actually occurs. What function performs the
>    rotation?
>
> **⭐⭐⭐ Challenging:**
> 5. Write a standalone Go program that performs a Brontide handshake between
>    two `Machine` instances in memory (no network needed). Verify that
>    encrypted messages can be exchanged after the handshake.
> 6. Analyze the security implications of the missing `mlock()` call. What
>    specific attack scenarios would `mlock()` prevent? What are the
>    limitations of `mlock()` itself?

---

*Previous: [01 — Node Architecture](./01-node-architecture.md) | Next: [03 — Key Management](./03-key-management.md)*
