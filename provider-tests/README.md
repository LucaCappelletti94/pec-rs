# Provider tests

These tests send PEC messages through a real provider and check the receipts it returns with the crate. They live outside the crate so their SMTP and IMAP clients stay out of its dependency graph, and CI never builds them.

The Aruba test sends two messages from a mailbox to itself, one asking for a short delivery receipt and one for a summary receipt, then reads the receipts back over IMAP without marking them read. It runs only when `PEC_ARUBA_CONFIG` names a TOML file with the mailbox credentials, which never belong in the repository.

```toml
address = "name@pec.it"
password = "..."
```

```sh
PEC_ARUBA_CONFIG=~/.config/pec/aruba.toml cargo test --manifest-path provider-tests/Cargo.toml
```

Each run sends two certified messages, which stay in the mailbox.
