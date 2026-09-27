# xmtp-mesh (libxmtp fork)

xmtp-mesh runs XMTP v3 messaging (MLS) over a Bluetooth Low Energy mesh, with
**no internet and no XMTP nodes**. Messages are ordinary XMTP MLS messages;
only the transport changes. libxmtp's network client is replaced by an
in-process node (`MeshNode`) that answers libxmtp's API calls from a local
store and syncs with nearby phones over BLE. Phones can also relay sealed
messages for each other (multi-hop, store-carry-forward).

> **Status: experimental.** Not audited. **Not a protest-safety claim**:
> links are private (rotating advert tokens, Noise), but radio
> fingerprinting, ex-contacts and timing remain, and relayed traffic is
> relay-blind but not anonymous. Private discovery and Noise links (§B14)
> are implemented in the Rust core and the FFI and tested in the simulator;
> the Android radio does not use them yet. Multi-hop relay is verified in
> the simulator; multi-hop on three or more real phones is not yet tested.
> Read [DESIGN.md §R9](DESIGN.md#r9-what-this-does-not-protect),
> [§B14.7](DESIGN.md#b147-what-this-does-not-fix) and
> [§B12](DESIGN.md#b12-known-security-limitation-relaying-the-sync-session)
> before relying on it.

## What is here

- **Base:** upstream tag `android-4.10.0-rc2` (the native version the React
  Native SDK 5.7.0 pins).
- **Design:** [DESIGN.md](DESIGN.md) — Part B (base mesh), Part C (restore
  convergence), Part R (multi-hop relay). Code comments cite it as `§B5.2`,
  `§C4.1`, `§R4.5` and decision ids `D1`–`D36`.
- **What changed:** [`PATCHES.md`](../../PATCHES.md) lists every edit to an
  upstream file and every new directory. In short:
  - `crates/xmtp_mesh/` (new): the mesh node, store, sync protocol, restore
    convergence, relay engine, private discovery and Noise links, and the
    loopback simulator used by the tests.
  - `crates/xmtp_mls`, `crates/xmtp_db`, `crates/xmtp_id`: small edits for
    restore convergence (leaf-aware membership diff, identity-log replace,
    guarded cache writes). Some are candidates to send upstream.
  - `bindings/mobile/src/mls/mesh.rs` (new): the uniffi FFI (`FfiMeshNode`,
    `connect_to_mesh`, relay switch and stats, identity events, link keys,
    adverts, contacts and pairing).
  - `sdks/android/library/.../mesh/` (new): the Kotlin BLE radio (GATT
    server + client, reliable chunked links, scan/connect policy, foreground
    service) and the `Mesh` API; `Client.kt` gains the `MESH` environment.
  - `.github/xmtp-mesh/`, `.github/workflows/upstream-drift.yml`: a weekly
    check that replays the fork onto newer upstream releases.

## Building the Android AAR

The upstream Nix build (`nix build .#android-libs`) works. Without Nix, the
dev scripts build with `cargo-ndk`:

Prerequisites: Rust (stable, per `rust-toolchain.toml`; tested with Rust
1.92.0) with the Android targets, `cargo-ndk`, JDK 17, `jq`, and an Android
SDK with NDK 27.1.12297006. `sdks/android/dev/mesh-env` reads `ANDROID_HOME`
(default `~/android-sdk`) and `ANDROID_NDK_HOME`.

```sh
# Native libraries + Kotlin bindings into sdks/android/.build/bindings/
sdks/android/dev/bindings-local          # all four ABIs
sdks/android/dev/bindings-local --fast   # arm64-v8a only (physical phones)

# Build all ABIs, run the Kotlin unit tests, and publish
# org.xmtp:android:<version> (from sdks/android/gradle.properties) to ~/.m2
sdks/android/dev/publish-mesh-local
```

A React Native app consumes the result through the companion React Native SDK
fork, which depends on `org.xmtp:android` at the version in
`sdks/android/gradle.properties` (for example `4.10.0-rc2-mesh.10`), resolved
from the local Maven repository that `publish-mesh-local` writes.

## Testing

```sh
cargo test -p xmtp_mesh            # node, sync, convergence, relay simulator
cargo test -p xmtp_mesh --test relay_sim -- --ignored   # 50-node crowd simulation
cd sdks/android && ./gradlew :library:testDebugUnitTest
sdks/android/dev/mesh-two-device-test <serial-a> <serial-b>   # two phones over BLE
```

## Licence

MIT, unchanged from upstream: see [`LICENSE`](../../LICENSE) (Copyright (c)
2023 XMTP (xmtp.org)). Fork changes are released under the same MIT licence.
