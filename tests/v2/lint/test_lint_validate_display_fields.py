import json
from pathlib import Path
from typing import Any

import pytest

from erc7730.common import client
from erc7730.common.abi import parse_signature
from erc7730.common.output import ListOutputAdder
from erc7730.convert.resolved.v2.convert_erc7730_input_to_resolved import ERC7730InputToResolved
from erc7730.lint.v2.lint_validate_display_fields import ValidateDisplayFieldsLinter
from erc7730.model.abi import ABI, Function, InputOutput
from erc7730.model.input.v2.descriptor import InputERC7730Descriptor

TRANSFER_KEY = "transfer(address _to, uint256 _value)"
TRANSFER_FIELDS = [
    {"path": "#._to", "label": "To", "format": "addressName", "params": {"types": ["eoa"]}},
    {"path": "#._value", "label": "Amount", "format": "amount"},
]
# the reference ABI uses other names than the template, as the OpenZeppelin ERC-20 does
TRANSFER_ABI = parse_signature("transfer(address to, uint256 amount)")


def descriptor(formats: dict[str, Any], includes: str | None = None) -> dict[str, Any]:
    return {
        **({"includes": includes} if includes is not None else {}),
        "context": {
            "$id": "Test",
            "contract": {"deployments": [{"chainId": 1, "address": "0x0000000000000000000000000000000000000001"}]},
        },
        "metadata": {"owner": "Test", "contractName": "Test"},
        "display": {"formats": formats},
    }


def fmt(fields: list[dict[str, Any]]) -> dict[str, Any]:
    return {"intent": "Test", "fields": fields}


def field(path: str) -> dict[str, Any]:
    return {"path": path, "label": path, "format": "raw"}


@pytest.fixture
def lint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):  # type: ignore[no-untyped-def]
    """Write the descriptor (and its included template) and lint it against the given reference ABI."""

    def run(abis: list[ABI], content: dict[str, Any], template: dict[str, Any] | None = None) -> ListOutputAdder:
        monkeypatch.setattr(client, "get_contract_abis", lambda chain_id, contract_address: abis)
        if template is not None:
            (tmp_path / "template.json").write_text(json.dumps(template))
        path = tmp_path / "calldata-descriptor.json"
        path.write_text(json.dumps(content))
        out = ListOutputAdder()
        input_descriptor = InputERC7730Descriptor.load(path)
        resolved_descriptor = ERC7730InputToResolved().convert(input_descriptor, out)
        assert resolved_descriptor is not None, out.outputs
        ValidateDisplayFieldsLinter().lint(input_descriptor, resolved_descriptor, out)
        return out

    return run


def messages(out: ListOutputAdder, title: str) -> list[str]:
    return [output.message for output in out.outputs if output.title == title]


def test_template_paths_are_valid_against_an_abi_with_other_names(lint) -> None:  # type: ignore[no-untyped-def]
    template = {"display": {"formats": {TRANSFER_KEY: fmt(TRANSFER_FIELDS)}}}
    out = lint([TRANSFER_ABI], descriptor({}, includes="template.json"), template)
    assert messages(out, "Invalid display field") == []
    assert messages(out, "Missing display field") == []


def test_format_key_of_an_included_file_is_parsed(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(json.dumps({"display": {"formats": {TRANSFER_KEY: fmt(TRANSFER_FIELDS)}}}))
    (tmp_path / "descriptor.json").write_text(json.dumps(descriptor({}, includes="template.json")))
    input_descriptor = InputERC7730Descriptor.load(tmp_path / "descriptor.json")
    declared_abis = ValidateDisplayFieldsLinter._parse_declared_abis(input_descriptor)
    assert [p.name for p in declared_abis["0xa9059cbb"].inputs or []] == ["_to", "_value"]


def test_missing_display_field_uses_the_declared_name(lint) -> None:  # type: ignore[no-untyped-def]
    out = lint([TRANSFER_ABI], descriptor({TRANSFER_KEY: fmt([TRANSFER_FIELDS[0]])}))
    assert messages(out, "Invalid display field") == []
    assert len(missing := messages(out, "Missing display field")) == 1
    assert "`#._value`" in missing[0]


def test_path_with_the_reference_abi_name_is_valid(lint) -> None:  # type: ignore[no-untyped-def]
    out = lint([TRANSFER_ABI], descriptor({TRANSFER_KEY: fmt([field("#.to"), field("#.amount")])}))
    assert messages(out, "Invalid display field") == []
    assert messages(out, "Missing display field") == []


def test_wrong_path_is_invalid(lint) -> None:  # type: ignore[no-untyped-def]
    out = lint([TRANSFER_ABI], descriptor({TRANSFER_KEY: fmt([field("#._to"), field("#._amount")])}))
    assert len(invalid := messages(out, "Invalid display field")) == 1
    assert "`#._amount`" in invalid[0]
    assert len(missing := messages(out, "Missing display field")) == 1
    assert "`#._value`" in missing[0]


def test_tuple_components_with_other_names_are_valid(lint) -> None:  # type: ignore[no-untyped-def]
    key = "swap((address tokenIn, uint256 amountIn) order, (address token, uint256 amount)[] fees, address recipient)"
    abi = parse_signature("swap((address a, uint256 b) o, (address t, uint256 v)[] f, address r)")
    fields = ["#.order.tokenIn", "#.order.amountIn", "#.fees.[].token", "#.fees.[].amount", "#.recipient"]
    out = lint([abi], descriptor({key: fmt([field(path) for path in fields])}))
    assert messages(out, "Invalid display field") == []
    # the ABI paths also contain the array root, which no field covers
    assert [m.split("`")[1] for m in messages(out, "Missing display field")] == ["#.fees.[]"]


def test_wrong_tuple_component_is_invalid(lint) -> None:  # type: ignore[no-untyped-def]
    key = "swap((address tokenIn, uint256 amountIn) order, address recipient)"
    abi = parse_signature("swap((address a, uint256 b) o, address r)")
    fields = ["#.order.tokenIn", "#.order.amountOut", "#.recipient"]
    out = lint([abi], descriptor({key: fmt([field(path) for path in fields])}))
    assert len(invalid := messages(out, "Invalid display field")) == 1
    assert "`#.order.amountOut`" in invalid[0]


def test_name_declared_for_an_unnamed_parameter_is_valid(lint) -> None:  # type: ignore[no-untyped-def]
    key = "depositETH(address pool, address onBehalfOf, uint16 referralCode)"
    abi = Function(
        name="depositETH",
        inputs=[
            InputOutput(name="", type="address"),
            InputOutput(name="onBehalfOf", type="address"),
            InputOutput(name="referralCode", type="uint16"),
        ],
    )
    out = lint([abi], descriptor({key: fmt([field("#.pool"), field("#.onBehalfOf"), field("#.referralCode")])}))
    assert messages(out, "Invalid display field") == []
    assert messages(out, "Missing display field") == []


def test_selector_key_uses_the_reference_abi_names(lint) -> None:  # type: ignore[no-untyped-def]
    out = lint([TRANSFER_ABI], descriptor({"0xa9059cbb": fmt([field("#.to"), field("#._value")])}))
    assert len(invalid := messages(out, "Invalid display field")) == 1
    assert "`#._value`" in invalid[0]
