from typing import TYPE_CHECKING, Any, Dict, Generator, List, Optional, Tuple

from astroid import InferenceError, nodes
from pylint.checkers import BaseChecker
from stix2.v21.sdo import _DomainObject
from stix2.v21.sro import Relationship

if TYPE_CHECKING:
    from pylint.lint import PyLinter

STIX2_PACKAGE_NAME = "stix2"
STIX2_OBJETS_NAMES = [_DomainObject.__name__, Relationship.__name__]


def is_constructor_call(call_node: nodes.Call) -> Tuple[bool, Optional[nodes.ClassDef]]:
    """Checks if the given call node represents a constructor call.

    Args:
        call_node (nodes.Call): The AST node representing the call.

    Returns:
        Tuple[bool, Optional[nodes.ClassDef]]: A tuple containing a boolean indicating
        whether the call is a constructor and the corresponding class definition if available.
    """
    try:
        inferred_types = call_node.func.infer()
        for inferred in inferred_types:
            if isinstance(inferred, nodes.ClassDef):
                return True, inferred
    except InferenceError:
        pass
    return False, None


def is_classdef_in_package(class_def: nodes.ClassDef, package_name: str) -> bool:
    """Checks if the given class definition is from the specified package.

    Args:
        class_def (nodes.ClassDef): The class definition node.
        package_name (str): The package name to check against.

    Returns:
        bool: True if the class definition is part of the specified package, False otherwise.
    """
    return class_def.qname().startswith(package_name)


def is_class_inheriting_from(
    class_def: nodes.ClassDef,
    class_names: List[str],
    package_name: Optional[str] = None,
) -> bool:
    """
    Recursively checks if the given class or any of its ancestor classes inherit from
    any class listed in `class_names` and, optionally, if it belongs to a specific package.

    Args:
        class_def (nodes.ClassDef): The class definition node.
        class_names (List[str]): A list of class names to check inheritance against.
        package_name (Optional[str], optional): The package name to check the inheritance from. Defaults to None.

    Returns:
        bool: True if the class or any of its ancestors inherit from a class in `class_names`, False otherwise.
    """
    if class_def.name in class_names:
        if package_name is None or is_classdef_in_package(class_def, package_name):
            return True

    for base in class_def.bases:
        try:
            inferred_bases = base.infer()
            for inferred_base in inferred_bases:
                if isinstance(inferred_base, nodes.ClassDef):
                    if is_class_inheriting_from(
                        inferred_base, class_names, package_name
                    ):
                        return True
        except InferenceError:
            continue

    return False


def extract_kwargs(call_node: nodes.Call) -> Dict[str, str]:
    """Extracts keyword arguments from the given call node.

    Args:
        call_node (nodes.Call): The AST node representing the function call.

    Returns:
        Dict[str, str]: A dictionary where keys are argument names and values are their corresponding values.
    """
    kwargs = {}
    for keyword in call_node.keywords:
        if keyword.arg is not None:  # None if it's **kwargs
            kwargs[keyword.arg] = keyword.value.as_string()
    return kwargs


def constructor_call_details(
    call_node: nodes.Call,
    class_def: nodes.ClassDef,
) -> dict[str, Any]:
    """Handles the processing of a detected constructor call.

    Args:
        call_node (nodes.Call): The AST node representing the constructor call.
        class_def (nodes.ClassDef): The class definition node of the constructor.
    """
    # Extract positional arguments
    args = [arg.as_string() for arg in call_node.args]

    # Extract keyword arguments
    kwargs = extract_kwargs(call_node)

    # Extract the package name
    in_package = class_def.qname()

    return {
        "line": call_node.lineno,
        "name": class_def.name,
        "args": args,
        "kwargs": kwargs,
        "package": in_package,
    }


def find_constructor_calls(
    node: nodes.NodeNG, class_names: List[str], package_name: Optional[str] = None
) -> Generator[dict[str, Any], None, None]:
    """Recursively traverses the AST to detect constructor calls."""

    if isinstance(node, nodes.Call):
        is_constructor, class_def = is_constructor_call(node)
        if is_constructor:
            if is_class_inheriting_from(class_def, class_names, package_name):
                yield constructor_call_details(node, class_def)

    for child in node.get_children():
        yield from find_constructor_calls(child, class_names, package_name)


class StixIdGeneratorChecker(BaseChecker):
    name = "no_generated_id_stix"
    msgs = {
        "W9101": (
            "Used STIX generator without generate_id function",
            "generated-id-stix",
            "To prevent stix duplication and explosion in OpenCTI, id should be generated via a determinist method if "
            "not known",
        )
    }

    def visit_call(self, node: nodes.Call) -> None:
        """Handle process when a Node of Call type is visited.

        Note:
            This is automatically called by pylint process.
        """
        calls = find_constructor_calls(
            node=node, class_names=STIX2_OBJETS_NAMES, package_name=STIX2_PACKAGE_NAME
        )
        for call in calls:
            if call["kwargs"].get("id") is None:
                self.add_message("generated-id-stix", node=node)


def register(linter: "PyLinter") -> None:
    """Register checker to linter."""
    linter.register_checker(StixIdGeneratorChecker(linter))
