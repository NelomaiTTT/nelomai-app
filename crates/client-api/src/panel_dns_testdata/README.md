Public loopback HTTPS test fixtures only. The committed server private keys are
intentionally public and must never be used outside tests. The original leaf
certificate covers nelomai.ru; the backup-* leaf covers nelomai.top and uses a
separate test CA. This distinguishes each HTTPS identity and detects retaining
the original Host/SNI or weakening backup certificate validation.

Generated with OpenSSL on 2026-11-02, valid for ten years. CA private keys are not
part of the repository. Production clients never load either test CA.
