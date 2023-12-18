# Capability Engine

## Fuzzing

The capability engine crate supports fuzzing using [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html).

To get started fuzzing, first install `cargo-fuzz`:

```sh
cargo install cargo-fuzz
```

Then run the following command:

```sh
cargo fuzz run engine
```

