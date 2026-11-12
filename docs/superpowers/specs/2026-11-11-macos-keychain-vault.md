# macOS Keychain vault

Use one random key in the user Keychain for the Common container. A vault-aware
Common can read the key once at startup and hold it for its lifetime. Each
protected record is stored as an authenticated encrypted file. A fresh OS nonce
protects each write. The associated data binds the record format, installation
identity and exact namespace. File creation and replacement require the existing
Common owner lock. The macOS vault acquires that lock through
`try_acquire_for_macos_vault`, which pins its directories. This method and
ordinary Common startup exclude each other through the same file and OS lock.
The vault requires an absolute path without symbolic links, a data root owned
by the current user and parent entries other unprivileged users cannot replace.
It requires a filesystem that enforces ownership. It verifies the
pinned identities, uses operations relative to open
directories, and rejects extended ACLs on private entries. A write flushes
the encrypted file before publishing it and the directory before returning.
Opening completes any interrupted directory synchronization and discards
uncommitted staging entries under the owner lock. Read failures, invalid
authentication tags and a missing key for an existing vault require recovery.
Owner initialization uses one reserved staging name for each new directory
and lock file, so a retry can finish publication without leaving debris.

The primitive uses XChaCha20-Poly1305 and stores its 24-byte nonce with each
record. Key provisioning uses the same macOS user Keychain domain as the
current native keyring. Its add-only API fails on duplicate items, preserving
an already provisioned key. [RustCrypto API](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/) · [Apple Keychain API](https://developer.apple.com/documentation/security/seckeychainaddgenericpassword(_:_:_:_:_:_:_:_:))

Keeping one Keychain entry per record retains the legacy reader and its prompts.
A vault holding only operational state would leave the auth entry in Keychain
and require a second item. A shared vault can hold auth and operational state
with a single item, with the migration constraints below.

## Migration and rollback

At f5933d8 startup authenticates the legacy source and reads the protected auth,
exact-version runtime and pending-write records via `SystemRecordFactory`. The
inventory and migration journal determine which namespaces can be read and
which still need cleanup. Stable and latest share one Common auth owner, while
their operational namespaces remain distinct.

1. Under the Common owner lock, validate the signed manifest and the current
   authoritative installation inventory. Bind the vault to a durable
   installation identifier from that authority. Preserve exact validated
   record bytes, including auth broker tickets, ownership metadata, every
   retained runtime with outstanding work and all pending-write records. Keep
   the current Keychain backend authoritative during this copy.
2. Reopen the staged vault, authenticate its binding and verify each record
   against the source and expected namespace inventory. If interrupted before
   activation, revalidate and copy from the current authoritative state. An
   existing incomplete, unreadable or conflicting vault requires explicit
   recovery. An empty or newly generated vault is valid only for a proven
   fresh installation.
3. Switch authority only through a durable, versioned activation decision
   after the full snapshot is verified. Include the inventory in that
   decision. Once active, corruption, a missing key or a missing required
   record must stop startup with a recoverable error. Reading the old Keychain
   as a fallback could resurrect rotated credentials or completed journals.
4. Route CommonHost and the macOS `OpenStorage` IPC handler through the same
   authoritative backend. At f5933d8 that handler constructs a separate
   `SystemRecordFactory` for the exact-version runtime records. Exercise
   embedded stable 0.3.11 with the vault-aware Common and verify that a
   complete latest → stable → latest cycle preserves auth and cleanup
   ownership.
5. Separately support downgrade of the entire Common installation. The old
   Common reads and writes its Keychain records directly. Preserving those
   records only gives it a snapshot from before activation. Once refresh or a
   cleanup transaction advances, that snapshot may be stale. Activation
   requires either a rollback-capable previous Common, or a tested export of
   the latest authoritative state to the old backend under the Common lock
   before the controlled downgrade. Reinstalling an arbitrary older DMG
   cannot be made safe by a marker its code never reads. Continuous writes to
   both stores retain the Keychain prompt problem and need atomic ordering
   across two backends.

The storage primitive is isolated from startup until the downgrade contract
and activation transaction are settled. It does not delete any records or
provide a rollback-resistant counter. With the same installation key an
old authenticated record can be replayed for its original namespace even
when the other records remain current. The first migration may
prompt separately for each legacy item; the prompt count on subsequent signed
updates must be measured in a VM through real Keychain access.
