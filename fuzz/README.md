# Fuzz targets

- `message_parse` reads arbitrary bytes as a PEC message and calls every accessor.
- `certification_xml` reads arbitrary text as `daticert.xml`, writes what it read and reads it back unchanged.
- `outgoing_prepare` prepares arbitrary bytes for each receipt form and checks the limits, asserting that what prepares holds no bare line break and names a recipient.
- `message_verify` verifies arbitrary bytes as a PEC message against the test CA and its CRL, so the signature decoding meets fuzzed input.
- `attachment_check` checks arbitrary bytes as a short delivery receipt against a sent message's attachments, with either line end policy.
- `outgoing_build` builds a message from arbitrary builder input, asserting that what builds passes `prepare` unchanged and that mail-parser reads back its subject, display names, bodies and attachments.

```sh
cargo +nightly fuzz run message_parse fuzz/corpus/message_parse fuzz/seeds/message_parse
```

## Seed Corpus

`fuzz/seeds/<target>/` holds one input per file, grown from the test fixtures, or by the fuzzer alone for the structured input of `outgoing_build`, and reduced with `-set_cover_merge=1`. The seeds of `outgoing_prepare`, `message_verify`, `attachment_check` and `outgoing_build` are reduced over edge coverage alone, with `-use_counters=0`.
