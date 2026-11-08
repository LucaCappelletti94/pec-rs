# Test fixtures

Every party, address and domain is fictitious, under `example.it` and `example.com`.

`daticert/` holds one hand-written `daticert.xml` per message kind, following the DTD of §7.4 of the AgID technical rules annexed to DM 2 November 2005. `original/` holds the two messages the envelopes wrap: `certified.eml`, a message sent from a PEC mailbox, and `ordinary.eml`, an ordinary email that reaches a PEC mailbox.

`messages/` holds the receipts, notices and envelopes a provider would deliver, each with the headers, subject prefix and body text of its section of the rules (§6.3 to §6.5), signed as `multipart/signed` S/MIME (§6.1). `generate.sh` rebuilds all of them from `daticert/` and `original/` with `openssl smime`.

The `.key` files in `pki/` are the private keys of a throwaway test PKI that exists only to sign these fixtures. They protect nothing and are published on purpose. `generate.sh` creates the PKI when `pki/provider.pem` is missing.
