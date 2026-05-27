# Repository Guidelines

## Project Structure & Module Organization

Suricata is a mixed C/Rust Autotools project. Core engine code lives in `src/`, with C unit test fixtures under `src/tests/`. Rust crates and generated bindings are under `rust/`, including `rust/src/`, `rust/ffi/`, `rust/sys/`, `rust/htp/`, `rust/derive/`, `rust/gen/`, and CLI crates such as `rust/suricatactl/` and `rust/suricatasc/`. Default configuration templates are in `etc/` and root files such as `suricata.yaml.in`; bundled rules are in `rules/`, scripts in `scripts/`, QA tooling in `qa/`, examples in `examples/`, plugins in `plugins/`, eBPF helpers in `ebpf/`, Lua helpers in `lua/`, and user/developer documentation in `doc/userguide/`.

## Build, Test, and Development Commands

- `./autogen.sh`: generate Autotools files from a Git checkout.
- `./configure`: configure the local build; add `--enable-unittests` for C unit tests and `--enable-debug` for verbose debugging.
- `make`: compile Suricata.
- `make check`: run the configured C and Rust unit test suite.
- `./src/suricata -u -U <test-name>`: run a focused C unit test after configuring with `--enable-unittests`.
- `cd rust && cargo test`: run Rust unit tests directly; use `cargo test http2` or `cargo test module::tests::test_name` to narrow scope.
- `scripts/clang-format.sh check-branch --diffstat`: check C formatting for branch changes.

## Coding Style & Naming Conventions

Follow the existing module style before adding new abstractions. C code is formatted with clang-format; CI currently validates with clang-format 14, and `scripts/clang-format.sh` is the preferred wrapper. Format only touched code or branch changes, not unrelated files. Rust code should use normal Rust naming and `cargo fmt`/`rustfmt`; Rust symbols exposed to C through `#[no_mangle]` should follow Suricata C-style naming.

## Testing Guidelines

Use unit tests for isolated parser, structure, and helper behavior. C tests should be deterministic, use `FAIL_*`/`PASS`, avoid leaks on success, and be registered with `UtRegisterTest()`. Rust tests usually live in a `mod tests` block in the same file as the code under test. Use the external Suricata-Verify suite for behavior that depends on pcaps, logging output, alerts, or full protocol flows.

## Commit & Pull Request Guidelines

Recent commits use short subsystem prefixes, for example `output/eve-kafka: retry queue full before dropping` or `doc: design kafka high throughput queue`. Keep the title imperative and scoped. Include the motivation and relevant details in the body, and add `Ticket: <Redmine ticket number>` when applicable. Pull requests should describe the change, explain testing performed, link issues or Redmine tickets, and address GitHub CI failures promptly.

## Security & Configuration Tips

Treat packet and file inputs as untrusted. Changes affecting decode, stream, app-layer parsing, detection, or IPS behavior need careful memory, bounds, and failure-path testing. Avoid committing local build artifacts, generated caches, or private traffic samples.

## AI Agent Workflow

Prefer fast, targeted repository search with `rg` before opening files.

Workflow:

```text
rg --files -> rg -> targeted read
```

Examples:

```bash
rg --files | rg 'output-eve-kafka|suricata.yaml'
rg -n "UtRegisterTest|KafkaDrainQueuesInternal" src
rg -n "stream reassembly" src doc/userguide
```

Read the minimum required context and avoid unrelated subsystem scans.
Prefer preserving existing subsystem architecture and coding style over introducing new abstractions.
