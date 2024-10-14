from typing import TYPE_CHECKING

from astroid import BoolOp, nodes
from pylint.checkers import BaseChecker

if TYPE_CHECKING:
    from pylint.lint import PyLinter

STIX_TYPES = (
    "AttackPattern",
    "Campaign",
    "CourseOfAction",
    "Grouping",
    "Identity",
    "Incident",
    "Indicator",
    "Infrastructure",
    "IntrusionSet",
    "Location",
    "Malware",
    "MalwareAnalysis",
    "Note",
    "ObservedData",
    "Opinion",
    "Report",
    "ThreatActor",
    "Tool",
    "Vulnerability",
    "Sighting",
    "Relationship",
)


class StixIdGeneratorChecker(BaseChecker):
    name = "no_generated_id_stix"
    msgs = {
        "C9101": (
            "Used STIX generator without generate_id function",
            "generated-id-stix",
            "To prevent stix duplication and explosion in OpenCTI, id must be generated if not known",
        )
    }

    def check_arg(self, target_node) -> None:
        first_arg = next((x for x in target_node.keywords if x.arg == "id"), None)
        if first_arg is None:
            self.add_message("generated-id-stix", node=target_node)
            return

    def visit_call(self, node: nodes.Call) -> None:
        # Case where call is inside attribute (like stix2.Indicator(...))
        if isinstance(node.func, nodes.Attribute):
            if node.func.attrname in STIX_TYPES:
                # parent_node = node.func.parent
                if node.func.expr.repr_name() == "stix2" and isinstance(
                    node, nodes.Call
                ):
                    self.check_arg(node)
            return
        # Case where call is direct (like Indicator(...))
        if isinstance(node.func, nodes.Name):
            if node.func.name in STIX_TYPES:
                if len(node.keywords) == 0:
                    return
                self.check_arg(node)


def register(linter: "PyLinter") -> None:
    linter.register_checker(StixIdGeneratorChecker(linter))
