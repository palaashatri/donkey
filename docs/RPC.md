# `donkey-cli serve`: JSON-RPC protocol (`donkey.rpc.v1`)

Status: **partial** (G11-T1). The read methods below work and are tested. `decompile`,
`annotations.list` and every write method are not implemented; the server says so in its
responses. See `docs/IDA_GAP_LEDGER.md` G11 for the plan.

## Running it

```bash
donkey-cli serve
```

The server reads requests from stdin and writes responses to stdout. Nothing else goes to stdout,
and it exits with 0 at end of input. It takes no arguments.

## Framing

- JSON-RPC 2.0. One request per line; one response per line. A line may end in LF or CRLF.
- Empty lines are ignored.
- A request line is limited to 16 MiB. A longer line is discarded to its end and answered with
  `rpc.too_large`; the next request is processed normally.
- A valid request with no `id` member is a notification: it runs, and no response is written,
  even if the method fails. A malformed request always gets a response, with `"id": null` when
  it has no usable id.
- The `id` of a response is the request's `id` (string, number or null), echoed as sent. When a
  request cannot be read well enough to find its id, the response carries `"id": null`.
- Requests are processed one at a time, in order. A method that needs analysis (below) runs to
  completion before the next request is read, so a slow analysis delays the responses after it.
- Batch requests (JSON arrays) are not supported and are answered with `rpc.invalid_request`.

Every response is valid UTF-8 JSON. Names and text taken from a binary are written with invalid
UTF-8 bytes replaced by U+FFFD.

## Session

The server holds one binary at a time. `open` loads a binary and replaces the previous one. The
default analysis (the same one `donkey-cli analyze` runs, with its default options) runs the first
time a method needs it and is kept until the next `open`.

Addresses are JSON strings in hexadecimal (`"0x400100"`) or decimal, or JSON numbers. Responses
write addresses as hexadecimal strings.

## Methods

| Method | Parameters | Result |
|---|---|---|
| `hello` | none | `protocol` (`donkey.rpc.v1`), `tool`, `tool_version`, the implemented `methods`, the `not_implemented` names, and `writes` (`disabled`) |
| `open` | `path` (string, required) | `path`, `format`, `architecture`, `bits`, `endian`, `file_size`, `sha256`, the counts of `sections` and `symbols`, and `partial` |
| `info` | `limit` (1 to 100000, default 1000) | `format`, `architecture`, `bits`, `endian`, `image_base`, `entry_point` (or null), `sha256`, `partial`, `sections`, `symbols_total`, `symbols` (up to `limit`), and `diagnostics` |
| `functions` | `limit` | `status` (`Complete` or `Partial`), `count`, `functions` (name, address, end_address or null, blocks, estimated, exported), and `diagnostics` |
| `strings` | `limit` | `count` and `strings` (address, file_offset, mapped, encoding, text). Strings use the default minimum length of 4 |
| `xrefs` | `address` (optional), `limit` | `count` (matching xrefs, not capped by `limit`) and `xrefs` (from, to, kind). With `address`, only xrefs to that address |
| `disasm` | `address` (required), `count` (1 to 4096, default 64) | `address` and `instructions` (address, bytes, length, mnemonic, operands, class, target or null), starting at the decoded instruction at `address` |
| `callgraph` | `limit` | `edge_count`, `edges` (caller, callee, site), `unresolved` and `orphan_sites` |

Methods that need an open binary return `rpc.no_image` until `open` succeeds. `disasm` returns
`rpc.not_found` when no decoded instruction starts at the address.

### Not implemented

- `decompile` and `annotations.list` return `rpc.not_implemented`.
- `rename`, `comment` and `type.apply` return `rpc.write_disabled`. Writes need a project and an
  explicit `--allow-write` flag, and neither exists yet. Nothing is written to any file.

## Batch mode

`donkey-cli batch <script.json>` runs a JSON array of requests in order, in one session, and
prints one JSON array of responses. The script is limited to 16 MiB. Notifications have no
response, and a malformed element gets its own error in its place. Exit status is 0 when the
script was read and run (even if some requests failed), 1 when the file is missing, is not valid
JSON, or is not an array, and 2 for a usage error.

```bash
donkey-cli batch session.json
```

## Errors

An error response has `error.code`, `error.message` and `error.data.donkey_code`. The codes below
are stable; the messages are for people and may change.

| `code` | `donkey_code` | Meaning |
|---|---|---|
| -32700 | `rpc.parse` | The line is not valid JSON. The message names the JSON error (`json.*`) |
| -32600 | `rpc.invalid_request` | Not a JSON object, `jsonrpc` is not `"2.0"`, `method` is missing or not a string, or `id` has the wrong type |
| -32600 | `rpc.too_large` | The line is over 16 MiB |
| -32601 | `rpc.method_not_found` | Unknown method |
| -32602 | `rpc.invalid_params` | A parameter is missing, has the wrong type, or is out of range |
| -32000 | `rpc.open_failed` | The file could not be loaded. The message carries the loader's code |
| -32001 | `rpc.no_image` | No binary is open |
| -32002 | `rpc.not_implemented` | A planned method (see above) |
| -32003 | `rpc.write_disabled` | A write method (see above) |
| -32005 | `rpc.analysis_failed` | The analysis failed. The message carries its code |
| -32006 | `rpc.not_found` | `disasm` found no decoded instruction at the address |

## Example

```text
→ {"jsonrpc":"2.0","id":1,"method":"open","params":{"path":"tests/fixtures/binaries/tiny-elf-x86_64"}}
← {"jsonrpc": "2.0", "id": 1, "result": {"path": "tests/fixtures/binaries/tiny-elf-x86_64", "format": "ELF", "architecture": "x86_64", "bits": 64, ...}}
→ {"jsonrpc":"2.0","id":2,"method":"xrefs","params":{"address":"0x400109"}}
← {"jsonrpc": "2.0", "id": 2, "result": {"count": 1, "xrefs": [{"from": "0x400104", "to": "0x400109", "kind": "call"}]}}
→ {"jsonrpc":"2.0","method":"hello"}
→ {"jsonrpc":"2.0","id":3,"method":"rename","params":{}}
← {"jsonrpc": "2.0", "id": 3, "error": {"code": -32003, "message": "rename is a write method; writes are disabled (no project, no --allow-write)", "data": {"donkey_code": "rpc.write_disabled"}}}
```

The notification (`hello` with no `id`) produces no line. The check that runs this session is
`cmake/checks/check_serve.cmake` (CTest `cli.serve_session`). `cmake/checks/check_batch.cmake`
(CTest `cli.batch_script`) checks batch mode.

## Limits and what is not covered

- A request is read whole into memory, up to 16 MiB. A binary is loaded and analysed with the
  same bounds as the CLI; the RPC layer adds none of its own beyond the list limits.
- Lists are capped by `limit`; the caps are reported as counts where a count is cheap to give.
- The JSON reader (`include/donkey/core/json.h`) rejects duplicate object keys and nesting deeper
  than 64. It is fuzzed (`fuzz_json`).
- Not covered yet: `decompile`, `annotations.list`, write methods, `--allow-write`, and any
  transport other than stdin/stdout.

## Python client

`bindings/python/donkey` is an optional package that starts `donkey-cli serve` and wraps the
implemented methods (see `bindings/python/README.md`). It is not part of the core build; CTest
runs its pytest suite (`python.rpc_client`) only when Python and pytest are installed.
