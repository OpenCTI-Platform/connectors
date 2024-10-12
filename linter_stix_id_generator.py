from typing import TYPE_CHECKING

from astroid import BoolOp, nodes
from pylint.checkers import BaseChecker

if TYPE_CHECKING:
    from pylint.lint import PyLinter

STIX_ENTITIES = (
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

    def visit_call(self, node: nodes.Call) -> None:
        if isinstance(node.func, nodes.Name):
            if node.func.name in STIX_ENTITIES:
                if len(node.keywords) == 0:
                    return
                # looking for id arg
                first_arg = next((x for x in node.keywords if x.arg == "id"), None)
                if first_arg is None:
                    self.add_message("generated-id-stix", node=node)
                    return
                if first_arg.value:
                    # if id is a function, it must be a generated_id method
                    if isinstance(first_arg.value, nodes.Call):
                        if first_arg.value.func.repr_name() != "generate_id":
                            self.add_message("generated-id-stix", node=node)
                    elif isinstance(first_arg.value, BoolOp):
                        found_generate_id = False
                        for value in first_arg.value.values:
                            if isinstance(value, nodes.Call):
                                if value.func.repr_name() == "generate_id":
                                    found_generate_id = True
                        if not found_generate_id:
                            self.add_message("generated-id-stix", node=node)
                    else:
                        self.add_message("generated-id-stix", node=node)


def register(linter: "PyLinter") -> None:
    linter.register_checker(StixIdGeneratorChecker(linter))
