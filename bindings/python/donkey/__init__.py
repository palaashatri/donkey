"""Python client for `donkey-cli serve` (JSON-RPC 2.0, protocol `donkey.rpc.v1`).

The client starts the command-line tool as a child process and talks to it over its standard
input and output. It is an optional package: the analysis core never depends on it.
"""

from .client import Client, RpcError, find_cli

__all__ = ["Client", "RpcError", "find_cli"]
__version__ = "0.1.0"
