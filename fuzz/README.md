# Fuzz targets

- `message_parse` reads arbitrary bytes as a PEC message and calls every accessor.
- `certification_xml` reads arbitrary text as `daticert.xml`, writes what it read and reads it back unchanged.

```sh
cargo +nightly fuzz run message_parse fuzz/corpus/message_parse fuzz/seeds/message_parse
```

## Seed Corpus

`fuzz/seeds/<target>/` holds one input per file, grown from the test fixtures and reduced with `-set_cover_merge=1`.
