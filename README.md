
# spvisualizer

Visualize the Zcash Orchard / Ironwood key hierarchy.

**Branch: `ironwood`** — updated for NU6.3 (Ironwood).

## What this does

Given a spending key (32-byte hex) or BIP-39 mnemonic, prints the full derivation path:

```
SpendingKey
  → ASK
  → FVK (ak, nk, rivk)
    → IVK / OVK (external + internal)
    → DK
    → diversifier + pk_d
    → Unified Addresses (indices 0–5 + optional DB index)
```

Also emits Bech32m (`orchard-sk1...`) and QR codes for the spending key, UIVKs, UFVK, and selected Unified Addresses.

Ironwood (NU6.3) reuses the exact same key hierarchy and Action/Halo2 circuit as Orchard under `ProtocolVersion::V3`. Only the note commitment tree, nullifier set, and chain value pool differ. This tool therefore remains valid for both pools.

## Build

```bash
git clone https://github.com/dismad/spvisualizer.git
cd spvisualizer
git checkout ironwood
cargo build -r
```

## Usage

```bash
./target/release/spvisualizer <sk_hex or mnemonic>
```

Examples:

```bash
# 32-byte hex spending key
./target/release/spvisualizer 0000000000000000000000000000000000000000000000000000000000000001

# BIP-39 mnemonic
./target/release/spvisualizer "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

Educational use only.

## Dependencies (Ironwood-era)

- `orchard` ≥ 0.15 (`ValuePool`, `ProtocolVersion::V3`)
- `zcash_keys` 0.15
- `zcash_protocol` 0.10
- `zcash_address` 0.13
- `zip32` 0.2
- `bech32`, `qrcode`, `bip39`, etc.

## Sources

- [Zcash Protocol Spec](https://github.com/zcash/zips/tree/main/protocol)
- [ZIP-316](https://zips.z.cash/zip-0316) (Unified keys/addresses)
- [ZIP-032](https://zips.z.cash/zip-0032) (Orchard key derivation)
- orchard 0.15+ (`ValuePool`, `ProtocolVersion`, `BundleVersion`)
- Zebra 6.0.0 / Ironwood activation height 3,428,143 (2026-07-28)

## Status

- [x] Bumped to orchard 0.15 + coordinated crates
- [x] QR codes, Bech32m SK, DK, multi-index UAs preserved
- [x] Dual-pool (Orchard + Ironwood) note in output
- [ ] Optional: explicit `ValuePool` / `ProtocolVersion` printing
- [ ] Optional: Ironwood-specific receiver if/when exposed by `zcash_address`
```
