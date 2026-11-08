# donkey: Python client (optional)

A small client for `donkey-cli serve`, the JSON-RPC 2.0 interface described in `docs/RPC.md`.
It starts the command-line tool as a child process and sends one request at a time.

```python
from donkey import Client

with Client("/path/to/donkey-cli") as session:   # or set DONKEY_CLI, or put donkey-cli on PATH
    session.open("program")
    for function in session.functions(limit=10)["functions"]:
        print(function["address"], function["name"])
```

Errors from the server raise `RpcError`, with the stable `donkey_code` (for example
`rpc.open_failed`) and the JSON-RPC `code`.

The package is not part of the core build and the analysis core does not depend on it. Its tests
run the built tool with pytest:

```bash
DONKEY_CLI=build/headless-linux/apps/donkey-cli/donkey-cli python3 -m pytest -p no:cacheprovider bindings/python/tests
```

CTest runs the same tests as `python.rpc_client` when Python and pytest are available.
