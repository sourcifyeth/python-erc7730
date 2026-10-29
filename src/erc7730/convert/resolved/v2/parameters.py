from typing import Any, assert_never, cast

from erc7730.common.abi import ABIDataType
from erc7730.common.output import OutputAdder
from erc7730.convert.resolved.v2.address import resolved_addresses
from erc7730.convert.resolved.v2.constants import ConstantProvider
from erc7730.convert.resolved.v2.enums import get_enum, get_enum_id
from erc7730.convert.resolved.v2.values import resolve_path_or_constant_value
from erc7730.model.input.path import DescriptorPathStr
from erc7730.model.input.v2.display import (
    InputAddressNameParameters,
    InputCallDataParameters,
    InputDateParameters,
    InputEncryptionParameters,
    InputEnumParameters,
    InputFieldParameters,
    InputInteroperableAddressNameParameters,
    InputMapReference,
    InputNftNameParameters,
    InputTokenAmountParameters,
    InputTokenTickerParameters,
    InputUnitParameters,
)
from erc7730.model.paths import ContainerPath, DataPath, DescriptorPath
from erc7730.model.paths.path_ops import data_or_container_path_concat
from erc7730.model.resolved.display import ResolvedValue
from erc7730.model.resolved.metadata import EnumDefinition
from erc7730.model.resolved.v2.display import (
    ResolvedAddressNameParameters,
    ResolvedCallDataParameters,
    ResolvedDateParameters,
    ResolvedEncryptionParameters,
    ResolvedEnumParameters,
    ResolvedFieldParameters,
    ResolvedInteroperableAddressNameParameters,
    ResolvedMapReference,
    ResolvedNftNameParameters,
    ResolvedTokenAmountParameters,
    ResolvedTokenTickerParameters,
    ResolvedUnitParameters,
)
from erc7730.model.types import Address, HexStr, Id, MixedCaseAddress, ScalarType


def resolve_field_parameters(
    prefix: DataPath,
    params: InputFieldParameters | None,
    enums: dict[Id, EnumDefinition],
    constants: ConstantProvider,
    out: OutputAdder,
) -> ResolvedFieldParameters | None:
    match params:
        case None:
            return None
        case InputAddressNameParameters():
            return resolve_address_name_parameters(prefix, params, constants, out)
        case InputInteroperableAddressNameParameters():
            return resolve_interoperable_address_name_parameters(prefix, params, constants, out)
        case InputCallDataParameters():
            return resolve_calldata_parameters(prefix, params, constants, out)
        case InputTokenAmountParameters():
            return resolve_token_amount_parameters(prefix, params, constants, out)
        case InputTokenTickerParameters():
            return resolve_token_ticker_parameters(prefix, params, constants, out)
        case InputNftNameParameters():
            return resolve_nft_parameters(prefix, params, constants, out)
        case InputDateParameters():
            return resolve_date_parameters(prefix, params, constants, out)
        case InputUnitParameters():
            return resolve_unit_parameters(prefix, params, constants, out)
        case InputEnumParameters():
            return resolve_enum_parameters(prefix, params, enums, constants, out)
        case _:
            assert_never(params)


def resolve_address_name_parameters(
    prefix: DataPath, params: InputAddressNameParameters, constants: ConstantProvider, out: OutputAdder
) -> ResolvedAddressNameParameters | None:
    sender_address: list[Address] | ResolvedMapReference | None = None
    if (sender_addr_input := params.senderAddress) is not None:
        if isinstance(sender_addr_input, InputMapReference):
            if (sender_address := constants.resolve_map_reference(prefix, sender_addr_input, out)) is None:
                return None
        else:
            resolved_sender = constants.resolve_or_none(sender_addr_input, out)
            if resolved_sender is None:
                sender_address = None
            elif isinstance(resolved_sender, str | list):
                senders = [resolved_sender] if isinstance(resolved_sender, str) else resolved_sender
                if (sender_address := resolved_addresses(senders, out)) is None:
                    return None
            else:
                raise Exception("Invalid senderAddress type")

    return ResolvedAddressNameParameters(
        types=constants.resolve_or_none(params.types, out),
        sources=constants.resolve_or_none(params.sources, out),
        senderAddress=sender_address,
    )


def resolve_interoperable_address_name_parameters(
    prefix: DataPath, params: InputInteroperableAddressNameParameters, constants: ConstantProvider, out: OutputAdder
) -> ResolvedInteroperableAddressNameParameters | None:
    sender_address: list[Address] | ResolvedMapReference | None = None
    if (sender_addr_input := params.senderAddress) is not None:
        if isinstance(sender_addr_input, InputMapReference):
            if (sender_address := constants.resolve_map_reference(prefix, sender_addr_input, out)) is None:
                return None
        else:
            resolved_sender = constants.resolve_or_none(sender_addr_input, out)
            if resolved_sender is None:
                sender_address = None
            elif isinstance(resolved_sender, str | list):
                senders = [resolved_sender] if isinstance(resolved_sender, str) else resolved_sender
                if (sender_address := resolved_addresses(senders, out)) is None:
                    return None
            else:
                raise Exception("Invalid senderAddress type")

    return ResolvedInteroperableAddressNameParameters(
        types=constants.resolve_or_none(params.types, out),
        sources=constants.resolve_or_none(params.sources, out),
        senderAddress=sender_address,
    )


def resolve_calldata_parameters(
    prefix: DataPath, params: InputCallDataParameters, constants: ConstantProvider, out: OutputAdder
) -> ResolvedCallDataParameters | None:
    if (
        callee := resolve_path_constant_or_map_reference(
            prefix, params.calleePath, params.callee, ABIDataType.ADDRESS, constants, out
        )
    ) is None:
        return None

    return ResolvedCallDataParameters(
        callee=callee,
        selector=resolve_path_constant_or_map_reference(
            prefix, params.selectorPath, params.selector, ABIDataType.STRING, constants, out
        ),
        amount=resolve_path_constant_or_map_reference(
            prefix, params.amountPath, params.amount, ABIDataType.UINT, constants, out
        ),
        spender=resolve_path_constant_or_map_reference(
            prefix, params.spenderPath, params.spender, ABIDataType.ADDRESS, constants, out
        ),
        chainId=resolve_chain_id(prefix, params.chainId, constants, out),
        chainIdPath=resolve_parameter_path(prefix, params.chainIdPath, constants, out),
    )


def resolve_token_amount_parameters(
    prefix: DataPath, params: InputTokenAmountParameters, constants: ConstantProvider, out: OutputAdder
) -> ResolvedTokenAmountParameters | None:
    token_resolved = resolve_path_constant_or_map_reference(
        prefix, params.tokenPath, params.token, ABIDataType.ADDRESS, constants, out
    )
    if token_resolved is None and (params.tokenPath is not None or params.token is not None):
        return None

    input_addresses = cast(
        list[DescriptorPathStr | MixedCaseAddress] | MixedCaseAddress | None,
        constants.resolve_or_none(params.nativeCurrencyAddress, out),
    )
    native_addresses: list[Address] | None
    if input_addresses is None:
        native_addresses = None
    elif isinstance(input_addresses, str | list):
        inputs: list[DescriptorPath | str] = [input_addresses] if isinstance(input_addresses, str) else input_addresses
        # an element of the list can be a path to a constant
        resolved_inputs = [constants.resolve(i, out) for i in inputs]
        if None in resolved_inputs or (native_addresses := resolved_addresses(resolved_inputs, out)) is None:
            return None
    else:
        raise Exception("Invalid nativeCurrencyAddress type")

    input_threshold = cast(HexStr | int | None, constants.resolve_or_none(params.threshold, out))
    resolved_threshold: HexStr | None
    if input_threshold is not None:
        if isinstance(input_threshold, int):
            resolved_threshold = "0x" + input_threshold.to_bytes(byteorder="big", signed=False).hex()
        else:
            resolved_threshold = input_threshold
    else:
        resolved_threshold = None

    return ResolvedTokenAmountParameters(
        token=token_resolved,
        nativeCurrencyAddress=native_addresses,
        threshold=resolved_threshold,
        message=constants.resolve_or_none(params.message, out),
        chainId=resolve_chain_id(prefix, params.chainId, constants, out),
        chainIdPath=resolve_parameter_path(prefix, params.chainIdPath, constants, out),
    )


def resolve_token_ticker_parameters(
    prefix: DataPath, params: InputTokenTickerParameters, constants: ConstantProvider, out: OutputAdder
) -> ResolvedTokenTickerParameters | None:
    return ResolvedTokenTickerParameters(
        chainId=resolve_chain_id(prefix, params.chainId, constants, out),
        chainIdPath=resolve_parameter_path(prefix, params.chainIdPath, constants, out),
    )


def resolve_nft_parameters(
    prefix: DataPath, params: InputNftNameParameters, constants: ConstantProvider, out: OutputAdder
) -> ResolvedNftNameParameters | None:
    if (
        collection := resolve_path_constant_or_map_reference(
            prefix, params.collectionPath, params.collection, ABIDataType.ADDRESS, constants, out
        )
    ) is None:
        return None
    return ResolvedNftNameParameters(collection=collection)


def resolve_date_parameters(
    prefix: DataPath, params: InputDateParameters, constants: ConstantProvider, out: OutputAdder
) -> ResolvedDateParameters | None:
    return ResolvedDateParameters(encoding=constants.resolve(params.encoding, out))


def resolve_unit_parameters(
    prefix: DataPath, params: InputUnitParameters, constants: ConstantProvider, out: OutputAdder
) -> ResolvedUnitParameters | None:
    return ResolvedUnitParameters(
        base=constants.resolve(params.base, out),
        decimals=constants.resolve_or_none(params.decimals, out),
        prefix=constants.resolve_or_none(params.prefix, out),
    )


def resolve_enum_parameters(
    prefix: DataPath,
    params: InputEnumParameters,
    enums: dict[Id, EnumDefinition],
    constants: ConstantProvider,
    out: OutputAdder,
) -> ResolvedEnumParameters | None:
    if get_enum_id(params.ref, out) is None:
        return None
    if get_enum(params.ref, enums, out) is None:
        return None

    return ResolvedEnumParameters.model_validate({"$ref": str(params.ref)})


def resolve_encryption_parameters(
    prefix: DataPath, params: InputEncryptionParameters, constants: ConstantProvider, out: OutputAdder
) -> ResolvedEncryptionParameters | None:
    # Encryption parameters are passed through as-is
    return ResolvedEncryptionParameters(
        scheme=params.scheme,
        plaintextType=params.plaintextType,
        fallbackLabel=params.fallbackLabel,
    )


def resolve_path_constant_or_map_reference(
    prefix: DataPath,
    input_path: DescriptorPath | DataPath | ContainerPath | None,
    input_value: DescriptorPath | ScalarType | InputMapReference | None,
    abi_type: ABIDataType,
    constants: ConstantProvider,
    out: OutputAdder,
) -> ResolvedValue | ResolvedMapReference | None:
    """
    Resolve a parameter value, as a data path, a constant value or a map reference.

    :param prefix: current path prefix
    :param input_path: input data path, if provided
    :param input_value: input constant value or map reference, if provided
    :param abi_type: expected encoded value data type
    :param constants: descriptor paths constants resolver
    :param out: error handler
    :return: resolved value, or None if error or not set
    """
    if isinstance(input_value, InputMapReference):
        return constants.resolve_map_reference(prefix, input_value, out)
    return resolve_path_or_constant_value(
        prefix=prefix,
        input_path=input_path,
        input_value=input_value,
        abi_type=abi_type,
        constants=constants,
        out=out,
    )


def resolve_chain_id(
    prefix: DataPath,
    input_chain_id: int | DescriptorPath | InputMapReference | None,
    constants: ConstantProvider,
    out: OutputAdder,
) -> int | ResolvedMapReference | None:
    """
    Resolve a chain ID parameter, as a constant value or a map reference.

    :param prefix: current path prefix
    :param input_chain_id: input chain ID, constant path or map reference, if provided
    :param constants: descriptor paths constants resolver
    :param out: error handler
    :return: resolved chain ID or map reference, or None if error or not set
    """
    if input_chain_id is None:
        return None
    if isinstance(input_chain_id, InputMapReference):
        return constants.resolve_map_reference(prefix, input_chain_id, out)
    chain_id: Any = constants.resolve(input_chain_id, out)
    if chain_id is None:
        return None
    if isinstance(chain_id, bool) or not isinstance(chain_id, int):
        return out.error(
            title="Invalid chain ID",
            message=f"Chain ID defined at {input_chain_id} must be an integer, got {type(chain_id).__name__}.",
        )
    return chain_id


def resolve_parameter_path(
    prefix: DataPath,
    input_path: DescriptorPath | DataPath | ContainerPath | None,
    constants: ConstantProvider,
    out: OutputAdder,
) -> DataPath | ContainerPath | None:
    """
    Resolve a parameter path relative to the current path prefix.

    :param prefix: current path prefix
    :param input_path: input path, or descriptor path to a constant path, if provided
    :param constants: descriptor paths constants resolver
    :param out: error handler
    :return: resolved absolute path, or None if error or not set
    """
    if (path := constants.resolve_path_or_none(input_path, out)) is None:
        return None
    return data_or_container_path_concat(prefix, path)
