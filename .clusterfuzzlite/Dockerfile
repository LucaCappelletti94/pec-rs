FROM gcr.io/oss-fuzz-base/base-builder-rust
# The image's own nightly is older than the crate's rust-version (1.98, which mail-parser requires), so the build
# uses a current nightly.
ENV RUSTUP_TOOLCHAIN=nightly
RUN rustup toolchain install $RUSTUP_TOOLCHAIN --profile minimal
COPY . $SRC/pec-rs
WORKDIR $SRC/pec-rs
COPY ./.clusterfuzzlite/build.sh $SRC/
