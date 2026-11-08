"""Tests of the Python client against the built `donkey-cli serve` (G11-T2).

They run the real command-line tool on tests/fixtures/binaries/tiny-elf-x86_64: the same binary
and addresses as the CTest RPC check (cmake/checks/check_serve.cmake). The tool is found through
$DONKEY_CLI, which CTest sets to the built binary.
"""

from pathlib import Path

import pytest

from donkey import Client, RpcError

REPO = Path(__file__).resolve().parents[3]
FIXTURE = REPO / "tests" / "fixtures" / "binaries" / "tiny-elf-x86_64"


@pytest.fixture
def client():
    with Client() as session:
        yield session


@pytest.fixture
def opened(client):
    client.open(str(FIXTURE))
    return client


def test_hello_names_the_protocol(client):
    hello = client.hello()
    assert hello["protocol"] == "donkey.rpc.v1"
    assert "functions" in hello["methods"]
    assert hello["writes"] == "disabled"


def test_open_reports_the_image(opened):
    # The response is the summary of the file that open loaded.
    info = opened.info(limit=2)
    assert info["format"] == "ELF"
    assert info["architecture"] == "x86_64"
    assert info["bits"] == 64
    assert info["entry_point"] == "0x400100"
    assert len(info["symbols"]) == 2
    assert info["symbols_total"] == 3


def test_functions_lists_the_entry_point(opened):
    functions = opened.functions(limit=5)
    assert functions["status"] == "Complete"
    names = {function["name"]: function for function in functions["functions"]}
    assert names["_start"]["address"] == "0x400100"
    assert names["_start"]["end_address"] == "0x40010c"


def test_disasm_takes_an_int_or_a_hex_string(opened):
    by_int = opened.disasm(0x400100, count=2)
    by_text = opened.disasm("0x400100", count=2)
    assert by_int == by_text
    first = by_int["instructions"][0]
    assert first["mnemonic"] == "push"
    assert first["bytes"] == "55"
    assert first["length"] == 1


def test_xrefs_to_the_callee_name_the_call_site(opened):
    xrefs = opened.xrefs(address=0x400109)
    assert xrefs["count"] == 1
    assert xrefs["xrefs"][0] == {"from": "0x400104", "to": "0x400109", "kind": "call"}


def test_callgraph_has_the_call_edge(opened):
    graph = opened.callgraph()
    assert graph["edges"] == [{"caller": "0x400100", "callee": "0x400109", "site": "0x400104"}]


def test_strings_return_the_literal(opened):
    strings = opened.strings(limit=2)
    assert strings["count"] == 1
    assert strings["strings"][0]["text"] == "hello world"


def test_a_method_before_open_is_refused_with_its_code(client):
    with pytest.raises(RpcError) as refused:
        client.info()
    assert refused.value.donkey_code == "rpc.no_image"
    assert refused.value.code == -32001


def test_a_missing_file_is_refused_with_the_loader_code(client):
    with pytest.raises(RpcError) as refused:
        client.open(str(REPO / "does-not-exist"))
    assert refused.value.donkey_code == "rpc.open_failed"
    assert "io.open_failed" in refused.value.message


def test_writes_and_project_methods_are_refused_without_a_project(opened):
    with pytest.raises(RpcError) as write:
        opened.call("rename", address="0x400100", text="entry")
    assert write.value.donkey_code == "rpc.write_disabled"
    with pytest.raises(RpcError) as annotations:
        opened.call("annotations.list")
    assert annotations.value.donkey_code == "rpc.no_project"


def test_decompile_returns_pseudocode_for_a_function(opened):
    result = opened.call("decompile", address="0x400100")
    assert result["address"] == "0x400100"
    assert "pseudocode" in result


def test_an_unknown_method_is_not_found(client):
    with pytest.raises(RpcError) as unknown:
        client.call("no.such.method")
    assert unknown.value.donkey_code == "rpc.method_not_found"


def test_the_server_stops_cleanly_when_the_client_closes():
    session = Client()
    session.hello()
    session.close()
    assert session._process.poll() == 0
