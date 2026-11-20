"""
V2 linter that validates display fields against reference ABIs fetched from Sourcify.

In v2, ABI and EIP-712 schemas are NOT embedded in the descriptor. Instead:
  - For contract context: fetch ABI from Sourcify, validate display field paths match ABI params,
    and check selector exhaustiveness.
  - For EIP-712 context: no schema to validate against (no-op).
"""

import json
from collections.abc import Sequence
from typing import Any, final, override

from pydantic_string_url import HttpUrl

from erc7730.common import client
from erc7730.common.abi import Functions, compute_signature, get_functions, parse_signature, signature_to_selector
from erc7730.common.output import OutputAdder
from erc7730.lint.v2 import ERC7730Linter
from erc7730.lint.v2.path_schemas import compute_format_schema_paths
from erc7730.model.abi import Component, Function, InputOutput
from erc7730.model.input.v2.descriptor import InputERC7730Descriptor
from erc7730.model.paths import DataPath, DataPathElement, Field
from erc7730.model.paths.path_ops import data_path_starts_with
from erc7730.model.paths.path_schemas import compute_abi_schema_paths
from erc7730.model.resolved.v2.context import ResolvedContractContext, ResolvedDeployment, ResolvedEIP712Context
from erc7730.model.resolved.v2.descriptor import ResolvedERC7730Descriptor

type Parameter = InputOutput | Component


@final
class ValidateDisplayFieldsLinter(ERC7730Linter):
    """
    Validates display fields against reference ABIs fetched from Sourcify.

    For contract context:
      - Fetches ABI from Sourcify for each deployment, and reports deployments not exposing the same functions
      - Validates that display field paths exist in the ABI (once per distinct reference ABI)
      - Validates that all ABI function params have display fields
      - Checks that all selectors in the ABI have corresponding display formats

    For EIP-712 context:
      - No schema available in v2 resolved model, so no validation is performed
    """

    def __init__(self, require_verified: bool = False) -> None:
        """
        :param require_verified: report a contract that is not verified on Sourcify as an error instead of a warning
            (as well as a reference ABI that could not be fetched, for instance because of a rate limit)
        """
        self.require_verified = require_verified

    @override
    def lint(
        self, input_descriptor: InputERC7730Descriptor, descriptor: ResolvedERC7730Descriptor, out: OutputAdder
    ) -> None:
        match descriptor.context:
            case ResolvedEIP712Context():
                pass  # no schema to validate against in v2
            case ResolvedContractContext():
                self._validate_contract_display_fields(input_descriptor, descriptor, out)

    def _validate_contract_display_fields(
        self, input_descriptor: InputERC7730Descriptor, descriptor: ResolvedERC7730Descriptor, out: OutputAdder
    ) -> None:
        context = descriptor.context
        if not isinstance(context, ResolvedContractContext):
            return

        if (deployments := context.contract.deployments) is None:
            return

        # Fetch the reference ABI of every deployment, and group deployments exposing the same functions, so that
        # each distinct ABI is validated once and deployments diverging from the others are reported
        groups: dict[str, tuple[Functions, list[ResolvedDeployment]]] = {}
        for deployment in deployments:
            skipped = "display fields will not be validated against ABI"
            unverified = out.error if self.require_verified else out.warning
            unsupported = out.error if self.require_verified else out.info
            failed = out.error if self.require_verified else out.warning
            try:
                abis = client.get_contract_abis(deployment.chainId, deployment.address)
            except client.ProxyImplementationNotVerifiedError as e:
                unverified(title="Proxy implementation not verified", message=f"{e}, {skipped}")
                continue
            except client.ContractNotVerifiedError as e:
                unverified(title="Contract not verified", message=f"{e}, {skipped}")
                continue
            except client.ChainNotSupportedError as e:
                unsupported(title="Chain not supported", message=f"{e}, {skipped}")
                continue
            except Exception as e:
                failed(
                    title="Could not fetch ABI",
                    message=f"Fetching reference ABI for chain id {deployment.chainId} failed, {skipped}: {e}",
                )
                continue

            reference_abis = get_functions(abis)
            groups.setdefault(self._external_abi_key(reference_abis), (reference_abis, []))[1].append(deployment)

        if len(groups) > 1:
            out.warning(
                title="Deployment ABIs differ",
                message="The reference ABIs of the deployments do not all expose the same functions, display fields "
                "are validated against each distinct reference ABI: "
                + "; ".join(", ".join(f"{d.chainId}:{d.address}" for d in ds) for _, ds in groups.values()),
            )

        for reference_abis, group_deployments in groups.values():
            explorer_url = client.get_contract_explorer_url(group_deployments[0].chainId, group_deployments[0].address)
            self._validate_display_fields(input_descriptor, descriptor, reference_abis, explorer_url, out)

    @classmethod
    def _external_abi_key(cls, reference_abis: Functions) -> str:
        """
        Compute a key identifying the functions as seen by a caller of the contract.

        Compiler details such as internal types, or legacy fields, are left out, so that deployments compiled from
        slightly different sources but exposing the same functions are grouped together.

        :param reference_abis: functions of a reference ABI
        :return: key equal for two ABIs exposing the same functions
        """
        return json.dumps(
            {
                selector: {
                    "name": abi.name,
                    "inputs": [cls._external_parameter(param) for param in abi.inputs or []],
                    "outputs": [cls._external_parameter(param) for param in abi.outputs or []],
                    "stateMutability": abi.stateMutability,
                }
                for selector, abi in sorted(reference_abis.functions.items())
            }
        )

    @classmethod
    def _external_parameter(cls, param: InputOutput | Component) -> dict[str, Any]:
        return {
            "name": param.name,
            "type": param.type,
            "components": [cls._external_parameter(component) for component in param.components or []],
        }

    def _validate_display_fields(
        self,
        input_descriptor: InputERC7730Descriptor,
        descriptor: ResolvedERC7730Descriptor,
        reference_abis: Functions,
        explorer_url: HttpUrl,
        out: OutputAdder,
    ) -> None:
        # Parse the input format keys, which carry the parameter names resolution reduced to selectors
        declared_abis_by_selector = self._parse_declared_abis(input_descriptor)

        # Validate display field paths against ABI paths
        for selector, fmt in descriptor.display.formats.items():
            if selector not in reference_abis.functions:
                out.warning(
                    title="Unknown selector",
                    message=f"Selector {selector} in display formats not found in reference ABI (see {explorer_url}). "
                    f"This could indicate a custom function or a stale descriptor.",
                )
                continue

            # Paths refer to the parameter names of the format key, which can differ from the reference ABI names
            abi = reference_abis.functions[selector]
            declared_abi = self._declared_reference_abi(abi, declared_abis_by_selector.get(selector))
            declared_paths = compute_abi_schema_paths(declared_abi)

            # Check for display fields referencing non-existent ABI paths.
            # A format path is valid if it matches a declared path exactly OR is a prefix of one
            # (e.g. defining a field for an array root covers all nested elements).
            # A path that uses the reference ABI names is also valid.
            covering_paths: set[DataPath] = set()
            for path in compute_format_schema_paths(fmt).data_paths:
                candidates = [path]
                if (translated := self._translate_path(path, abi.inputs, declared_abi.inputs)) is not None:
                    candidates.append(translated)
                valid = next((c for c in candidates if self._path_exists(c, declared_paths)), None)
                if valid is None:
                    out.error(
                        title="Invalid display field",
                        message=f"A display field is defined for `{path}`, but it does not exist in function "
                        f"{selector} ABI (see {explorer_url}). Please check the field path is valid.",
                    )
                    continue
                covering_paths.add(valid)

            # Check for ABI paths without corresponding display fields.
            # A path is covered if it matches a format path exactly OR a format path is a prefix of it
            # (e.g. a field defined for an array root covers all descendant paths).
            for path in declared_paths - covering_paths:
                if not any(data_path_starts_with(path, fmt_path) for fmt_path in covering_paths):
                    out.warning(
                        title="Missing display field",
                        message=f"No display field is defined for path `{path}` in function {selector} "
                        f"(see {explorer_url}).",
                    )

        # Check selector exhaustiveness: all ABI functions should have display formats
        for selector, abi in reference_abis.functions.items():
            if selector not in descriptor.display.formats:
                out.warning(
                    title="Missing display format",
                    message=f"Function {compute_signature(abi)} (selector: {selector}) exists in reference ABI "
                    f"(see {explorer_url}) but has no display format defined in the descriptor.",
                )

    @classmethod
    def _parse_declared_abis(cls, input_descriptor: InputERC7730Descriptor) -> dict[str, Function]:
        """
        Parse the function signatures declared as display format keys, indexed by selector.

        Format keys that are already selectors declare no parameter name, and are skipped. The input descriptor is
        loaded with its includes merged, so the format keys of included files are parsed too.

        :param input_descriptor: input descriptor the linted descriptor was resolved from
        :return: declared ABI functions, by selector
        """
        declared_abis: dict[str, Function] = {}
        for format_id in input_descriptor.display.formats:
            if format_id.startswith("0x"):
                continue
            try:
                declared_abi = parse_signature(format_id)
            except ValueError:
                continue  # invalid signatures are reported by the resolution step
            declared_abis[signature_to_selector(compute_signature(declared_abi))] = declared_abi
        return declared_abis

    @classmethod
    def _declared_reference_abi(cls, abi: Function, declared_abi: Function | None) -> Function:
        """
        Rename the parameters of the reference ABI with the names declared in the format key.

        Parameters are matched by position, recursively for tuple components. A parameter keeps its reference ABI
        name if the format key gives it no name, or if the types differ.

        :param abi: reference ABI of the function, as fetched from the explorer
        :param declared_abi: ABI declared by the descriptor format key, if it was a signature and not a selector
        :return: the reference ABI, with the parameter names of the format key
        """
        if declared_abi is None:
            return abi
        return abi.model_copy(update={"inputs": cls._declared_parameters(abi.inputs, declared_abi.inputs)})

    @classmethod
    def _declared_parameters(
        cls, parameters: Sequence[Parameter] | None, declared_parameters: Sequence[Parameter] | None
    ) -> list[Any] | None:
        if parameters is None:
            return None
        if declared_parameters is None or len(parameters) != len(declared_parameters):
            return list(parameters)
        renamed: list[Parameter] = []
        for parameter, declared in zip(parameters, declared_parameters, strict=True):
            if parameter.type != declared.type:
                renamed.append(parameter)
                continue
            renamed.append(
                parameter.model_copy(
                    update={
                        "name": declared.name or parameter.name,
                        "components": cls._declared_parameters(parameter.components, declared.components),
                    }
                )
            )
        return renamed

    @classmethod
    def _translate_path(
        cls,
        path: DataPath,
        parameters: Sequence[Parameter] | None,
        declared_parameters: Sequence[Parameter] | None,
    ) -> DataPath | None:
        """
        Translate a data path that uses the reference ABI names into a data path that uses the declared names.

        :param path: data path, with reference ABI parameter names
        :param parameters: parameters of the reference ABI
        :param declared_parameters: the same parameters, with the declared names
        :return: the data path with the declared names, or None if a field is not in the reference ABI
        """
        if not path.absolute:
            return None
        elements: list[DataPathElement] = []
        for element in path.elements:
            if not isinstance(element, Field):
                elements.append(element)
                continue
            if parameters is None or declared_parameters is None:
                return None
            index = next((i for i, p in enumerate(parameters) if p.name and p.name == element.identifier), None)
            if index is None:
                return None
            declared = declared_parameters[index]
            elements.append(Field(identifier=declared.name))
            parameters, declared_parameters = parameters[index].components, declared.components
        return DataPath(absolute=True, elements=elements)

    @classmethod
    def _path_exists(cls, path: DataPath, paths: set[DataPath]) -> bool:
        """
        Check that a path matches one of the paths exactly, or is a prefix of one.

        :param path: data path to check
        :param paths: valid data paths
        :return: True if the path is valid
        """
        return path in paths or any(data_path_starts_with(p, path) for p in paths)
