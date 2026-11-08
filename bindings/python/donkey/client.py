"""A client for `donkey-cli serve`. See docs/RPC.md for the protocol and its error codes."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Optional, Union

PROTOCOL = "donkey.rpc.v1"

Address = Union[int, str]


class RpcError(Exception):
    """An error response from the server. `donkey_code` is the stable `rpc.*` code."""

    def __init__(self, code: int, donkey_code: str, message: str) -> None:
        super().__init__(f"{donkey_code} ({code}): {message}")
        self.code = code
        self.donkey_code = donkey_code
        self.message = message


def find_cli(explicit: Optional[str] = None) -> str:
    """The `donkey-cli` to run: the argument, else $DONKEY_CLI, else the one on PATH."""
    for candidate in (explicit, os.environ.get("DONKEY_CLI")):
        if candidate:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            raise FileNotFoundError(f"donkey-cli is not an executable file: {candidate}")
    found = shutil.which("donkey-cli")
    if found:
        return found
    raise FileNotFoundError("donkey-cli not found: pass cli=, set DONKEY_CLI, or add it to PATH")


def _address(value: Address) -> str:
    """Addresses go over the wire as hexadecimal strings, which survive any integer size."""
    if isinstance(value, bool):
        raise TypeError("an address is an int or a string, not a bool")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("an address cannot be negative")
        return hex(value)
    return value


class Client:
    """One `donkey-cli serve` session. Use it as a context manager so the process is closed."""

    def __init__(self, cli: Optional[str] = None) -> None:
        self._cli = find_cli(cli)
        self._next_id = 1
        self._process = subprocess.Popen(
            [self._cli, "serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        if self._process.poll() is None:
            if self._process.stdin is not None:
                self._process.stdin.close()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()

    def call(self, method: str, **params: Any) -> Any:
        """Send one request and return its result. Raises RpcError for an error response."""
        if self._process.poll() is not None:
            raise RuntimeError(f"donkey-cli serve has exited: {self._stderr()}")
        request_id = self._next_id
        self._next_id += 1
        request: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params:
            request["params"] = params
        assert self._process.stdin is not None and self._process.stdout is not None
        self._process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self._process.stdin.flush()
        line = self._process.stdout.readline()
        if not line:
            raise RuntimeError(f"donkey-cli serve closed its output: {self._stderr()}")
        response = json.loads(line)
        if response.get("id") != request_id:
            raise RuntimeError(f"response id {response.get('id')} does not match request {request_id}")
        if "error" in response:
            error = response["error"]
            data = error.get("data") or {}
            raise RpcError(error["code"], data.get("donkey_code", ""), error["message"])
        return response["result"]

    def _stderr(self) -> str:
        if self._process.stderr is None or self._process.poll() is None:
            return ""
        return self._process.stderr.read().strip()

    # Typed wrappers for the implemented methods.

    def hello(self) -> dict[str, Any]:
        return self.call("hello")

    def open(self, path: str) -> dict[str, Any]:
        return self.call("open", path=path)

    def info(self, limit: Optional[int] = None) -> dict[str, Any]:
        return self.call("info", **_optional(limit=limit))

    def functions(self, limit: Optional[int] = None) -> dict[str, Any]:
        return self.call("functions", **_optional(limit=limit))

    def strings(self, limit: Optional[int] = None) -> dict[str, Any]:
        return self.call("strings", **_optional(limit=limit))

    def xrefs(self, address: Optional[Address] = None, limit: Optional[int] = None) -> dict[str, Any]:
        params: dict[str, Any] = _optional(limit=limit)
        if address is not None:
            params["address"] = _address(address)
        return self.call("xrefs", **params)

    def disasm(self, address: Address, count: Optional[int] = None) -> dict[str, Any]:
        params: dict[str, Any] = _optional(count=count)
        params["address"] = _address(address)
        return self.call("disasm", **params)

    def callgraph(self, limit: Optional[int] = None) -> dict[str, Any]:
        return self.call("callgraph", **_optional(limit=limit))


def _optional(**values: Optional[int]) -> dict[str, int]:
    return {name: value for name, value in values.items() if value is not None}
