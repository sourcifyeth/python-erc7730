import json
from pathlib import Path
from typing import Any

import pytest

from erc7730.common import client
from erc7730.common.abi import parse_signature
from erc7730.common.output import ListOutputAdder, Output
from erc7730.lint.v2.lint import lint_all
from erc7730.model.input.v2.descriptor import InputERC7730Descriptor
from tests.files import TEST_RESOURCES

RESOURCES = TEST_RESOURCES / "lint" / "v2"


def lint(path: Path, monkeypatch: pytest.MonkeyPatch) -> ListOutputAdder:
    """Lint a descriptor, with a reference ABI built from its format keys."""
    abis = [parse_signature(key) for key in InputERC7730Descriptor.load(path).display.formats]
    monkeypatch.setattr(client, "get_contract_abis", lambda chain_id, contract_address: abis)
    out = ListOutputAdder()
    lint_all([path], out)
    return out


def errors(out: ListOutputAdder) -> list[Output]:
    return [output for output in out.outputs if output.level == Output.Level.ERROR]


@pytest.mark.parametrize(
    "name",
    [
        # calldata with a constant chainId
        "calldata-base-OptimismPortal2.json",
        "calldata-blast-L2ToL1MessagePasser.json",
        # tokenAmount and tokenTicker with a relative chainIdPath
        "calldata-across-SpokePool-relative-chain-id-path.json",
        # tokenAmount with map references, from the ERC
        "calldata-example-maps.json",
        # addressName and tokenTicker on bytes32 arguments
        "calldata-bytes32-address.json",
    ],
)
def test_descriptor_lints_without_errors(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    assert errors(lint(RESOURCES / name, monkeypatch)) == []


def write_descriptor(tmp_path: Path, fields: list[dict[str, Any]]) -> Path:
    path = tmp_path / "calldata-test.json"
    path.write_text(
        json.dumps(
            {
                "$schema": "../../specs/erc7730-v2.schema.json",
                "context": {
                    "contract": {
                        "deployments": [{"chainId": 1, "address": "0x0000000000000000000000000000000000000001"}]
                    }
                },
                "metadata": {
                    "owner": "Test Owner",
                    "maps": {"tokens": {"values": {"1": "0x0000000000000000000000000000000000000002"}}},
                },
                "display": {
                    "formats": {
                        "execute(address target,uint256 amount,uint256 chainId,bytes data)": {
                            "intent": "Execute",
                            "fields": fields,
                        }
                    }
                },
            }
        )
    )
    return path


@pytest.mark.parametrize(
    "field",
    [
        {
            "path": "amount",
            "label": "Amount",
            "format": "tokenAmount",
            "params": {"token": {"map": "$.metadata.maps.tokens", "keyPath": "unknown"}},
        },
        {
            "path": "data",
            "label": "Call",
            "format": "calldata",
            "params": {"calleePath": "target", "chainIdPath": "unknown"},
        },
    ],
    ids=["map key path", "calldata chainIdPath"],
)
def test_parameter_path_not_in_abi_is_an_error(field: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = lint(write_descriptor(tmp_path, [field]), monkeypatch)
    assert [output.message for output in errors(out) if "`#.unknown`" in output.message] != []
