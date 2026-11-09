# Fuzz targets

ClusterFuzzLite fuzzes these for an hour every Sunday, after pruning the corpus it keeps on the `fuzz-corpus` branch.

- `message_parse` reads arbitrary bytes as a PEC message and calls every accessor.
- `certification_xml` reads arbitrary text as `daticert.xml`, writes what it read and reads it back unchanged.

```sh
cargo +nightly fuzz run message_parse fuzz/corpus/message_parse fuzz/seeds/message_parse
```

## Seed Corpus

`fuzz/seeds/<target>/` holds one input per file, grown from the test fixtures and reduced with `-set_cover_merge=1`. `.clusterfuzzlite/build.sh` zips it into the starting corpus and fails a target without seeds.
