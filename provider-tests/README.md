# Provider tests

These tests send PEC messages through a real provider and check the receipts it returns with the crate. They live outside the crate so their SMTP and IMAP clients stay out of its dependency graph, and the CI of pull requests never builds them.

The Aruba test sends two messages from a mailbox to itself, one asking for a short delivery receipt and one for a summary receipt, then reads the receipts back over IMAP without marking them read. It runs only when `PEC_ARUBA_CONFIG` names a TOML file with the mailbox credentials, which never belong in the repository.

```toml
address = "name@pec.it"
password = "..."
```

```sh
PEC_ARUBA_CONFIG=~/.config/pec/aruba.toml cargo test --manifest-path provider-tests/Cargo.toml
```

Each run sends two certified messages, which stay in the mailbox.

The OpenPEC test runs the same messages through [OpenPEC](https://sourceforge.net/projects/openpec/) 2.2.8, the open-source PEC provider, in a container that is a whole provider for the test domain `pec.test`: Postfix, OpenPEC, its LDAP provider index and Dovecot. Its mailboxes `mittente`, `destinatario` and `posta-certificata` at `pec.test` share the password `prova`. The test runs only when `PEC_OPENPEC_SMTP` and `PEC_OPENPEC_IMAP` name the container's ports.

```sh
docker build -t pec-openpec provider-tests/openpec
docker run -d --rm --name pec-openpec -p 127.0.0.1:2525:25 -p 127.0.0.1:2143:143 pec-openpec
PEC_OPENPEC_SMTP=127.0.0.1:2525 PEC_OPENPEC_IMAP=127.0.0.1:2143 cargo test --manifest-path provider-tests/Cargo.toml --test openpec
```

The Provider tests workflow runs the OpenPEC test this way every Sunday, and on demand from the Actions tab.
