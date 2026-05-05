# ⚡ LND Deep Dive

**A Security Engineer's Guide to the Lightning Network Daemon**

🌐 **[Read the Guide →](https://nonsoamadi10.github.io/lnd-deep-dive/)**

---

This is a comprehensive, beginner-friendly guide that maps every concept from [*Mastering the Lightning Network*](https://github.com/lnbook/lnbook) (Antonopoulos, Osuntokun, Pickhardt) to actual [LND](https://github.com/lightningnetwork/lnd) source code — with a security engineer's perspective.

## 📚 Chapters

| # | Chapter | Key Package | Security Finding |
|---|---------|------------|-----------------|
| 1 | [Node Architecture & Startup](https://nonsoamadi10.github.io/lnd-deep-dive/#/01-node-architecture) | `lnd.go`, `server.go` | Macaroon file perms hardcoded |
| 2 | [Brontide Encrypted Transport](https://nonsoamadi10.github.io/lnd-deep-dive/#/02-brontide-transport) | `brontide/` | Secret key not memory-locked |
| 3 | [Key Management & Wallet](https://nonsoamadi10.github.io/lnd-deep-dive/#/03-key-management) | `aezeed/`, `keychain/` | Default passphrase "aezeed" |
| 4 | [Channels & Commitments](https://nonsoamadi10.github.io/lnd-deep-dive/#/04-channels-commitments) | `lnwallet/`, `funding/` | Breach arbitrator timing |
| 5 | [HTLCs, Routing & the Switch](https://nonsoamadi10.github.io/lnd-deep-dive/#/05-htlc-switch-routing) | `htlcswitch/`, `routing/` | Dust fee exposure |
| 6 | [Watchtowers](https://nonsoamadi10.github.io/lnd-deep-dive/#/06-watchtowers) | `watchtower/` | No justice tx rebroadcast |
| 7 | [Channel Backups](https://nonsoamadi10.github.io/lnd-deep-dive/#/07-channel-backups) | `chanbackup/` | Stale backup force-close |
| 8 | [Macaroons & RPC](https://nonsoamadi10.github.io/lnd-deep-dive/#/08-macaroons-rpc) | `macaroons/`, `rpcperms/` | Fail-closed middleware |
| 9 | [Gossip & Discovery](https://nonsoamadi10.github.io/lnd-deep-dive/#/09-gossip-discovery) | `discovery/` | In-memory-only bans |
| 10 | [Tor & IP Privacy](https://nonsoamadi10.github.io/lnd-deep-dive/#/10-tor-privacy) | `tor/` | NULL auth fallback |

## 🔐 Security Findings

**18 findings** across the LND codebase, ranging from Critical to Informational:

- [Full Security Report →](https://nonsoamadi10.github.io/lnd-deep-dive/#/11-security-findings)

## 📖 Additional Resources

- [Glossary (55+ terms)](https://nonsoamadi10.github.io/lnd-deep-dive/#/12-glossary)


## How to Use

1. Clone the [LND repository](https://github.com/lightningnetwork/lnd)
2. Read each chapter in order
3. Follow along in the source code (file paths & line numbers provided)
4. Complete the exercises at the end of each chapter
5. Use the security findings to harden your own node

## Tech Stack

- Built with [Docsify](https://docsify.js.org/)
- Hosted on GitHub Pages
- Content based on LND v0.18+

## License

MIT

---

*Built by [Chinonso Amadi](https://github.com/NonsoAmadi10) — Crypto Infrastructure Security Engineer*
