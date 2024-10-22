"""Offer unit tests fo ../../ check_stix_plugin/linter_stix_id_generator checker"""

import pathlib
import sys

import pylint.testutils
import pytest
from astroid import extract_node, parse

sys.path.append(
    str(
        (
            pathlib.Path(__file__).parent.parent.parent.resolve() / "check_stix_plugin"
        ).resolve()
    )
)

from linter_stix_id_generator import StixIdGeneratorChecker, find_constructor_calls


@pytest.mark.parametrize(
    "example_code",
    [
        pytest.param(
            "from stix2 import Location; loc=Location(name='example')",
            id="class_import, assignation",
        ),
        pytest.param(
            "import stix2; loc=stix2.Location(name='example')",
            id="module_import, assignation",
        ),
        pytest.param(
            "from stix2 import Location; print(Location(name='example'))",
            id="class_import, direct_call",
        ),
        pytest.param(
            """
            import stix2  
            class MyLocation(stix2.Location):
                def __init__(self, **kwargs):
                    super().__init__(**kwargs)
            
            loc = MyLocation(name='name')
            """,
            id="simple_inheritance",
        ),
        pytest.param(
            """
            import stix2
            class MyLocation(stix2.Location):
                def __init__(self, **kwargs):
                    super().__init__(**kwargs)
            class MyLocation2(MyLocation):
                def __init__(self, **kwargs):
                    super().__init__(**kwargs)
            
            loc = MyLocation2(name="name")
            """,
            id="multiple_inheritances",
        ),
        pytest.param(
            """
            import stix2
            
            class MyLocation():
                def __init__(self, id, name):
                    self.id = id
                    self.name = name
            
                def to_stix():
                    stix2.Location(
                        name=self.name
                    )
            
            loc = MyLocation(name="name")
            res = loc.to_stix()
            """,
            id="wrapped_method",
        ),
    ],
)
def test_find_constructor_calls_should_detect_constructor_call(example_code):
    # Given a Python script with the call to a STIX2 Domain Object constructor
    module = parse(example_code)

    # When find_constructor_calls is called
    calls = list(find_constructor_calls(module, ["Location"], "stix2"))

    # Then it should detect one constructor call for 'Location' class
    assert len(calls) == 1
    assert "name" in calls[0]["kwargs"].keys()


def test_find_constructor_calls_should_detect_multiple_constructor_calls():
    # Given a Python script several calls to a STIX2 Domain Object constructors
    module = parse(
        """
        import stix2
        loc = stix2.Location(
            id=generate_id("name"),
            name="name"
        )
        author = stix2.Identity(
            name="author"
        )
        """
    )
    # When find_constructor_calls is called
    calls = list(find_constructor_calls(module, ["Location", "Identity"], "stix2"))

    # Then it should detect one constructor call for 2 classes
    assert len(calls) == 2


@pytest.mark.parametrize(
    "example_code",
    [
        pytest.param(
            """
            class Location():
                def __init__(self, **kwargs):
                    self.name = kwargs.get('name')
            
            loc = Location(name='name')
            """,
            id="similar_class_name",
        ),
    ],
)
def test_find_constructor_calls_should_detect_non_relevant_constructor_calls(
    example_code,
):
    # Given a Python script with no call to a STIX2 Domain Object constructor
    module = parse(example_code)

    # When find_constructor_calls is called
    calls = list(find_constructor_calls(module, ["Location"], "stix2"))

    # Then it should detect nothing
    assert len(calls) == 0


class TestStixIdGeneratorChecker(pylint.testutils.CheckerTestCase):
    """
    See:
        https://pylint.pycqa.org/en/latest/development_guide/how_tos/custom_checkers.html#testing-a-checker [consulted on October 22nd, 2024]
    """

    CHECKER_CLASS = StixIdGeneratorChecker

    def test_StixIdGeneratorChecker_should_raise_message_when_no_given_id_in_stix2_domain_object_constructor_call(
        self,
    ):
        # Given: A STIX2 domain object constructor call without an 'id' argument
        call_node = extract_node(
            """
            from stix2 import Location
            loc = Location(name="example") #@
        """
        )

        # When: the checker visits the constructor call node
        with self.assertAddsMessages(
            pylint.testutils.MessageTest(
                msg_id="generated-id-stix",
                line=3,
                node=call_node,
                col_offset=0,
                end_line=3,
                end_col_offset=30,
            )
        ):
            self.checker.visit_call(call_node)

    def test_StixIdGeneratorChecker_should_not_raise_message_when_no_stix2_domain_object_constructor_call(
        self,
    ):
        # Given: A Python script with no STIX2 domain object constructor call
        call_node = extract_node(
            """
            class Location:
                def __init__(self):
                    pass 
            loc = Location() #@
        """
        )

        # When: the checker visits the method without constructor calls
        with self.assertNoMessages():
            self.checker.visit_call(call_node)

    def test_StixIdGeneratorChecker_should_not_raise_message_when_given_in_stix2_domain_object_constructor_call(
        self,
    ):
        # Given: A STIX2 domain object constructor call with an 'id' argument
        call_node = extract_node(
            """
            from stix2 import Location
            loc = Location(id=generate_id("example"), name="example") #@
        """
        )

        # When: the checker visits the constructor call node with an id argument
        # Then: No message is added
        with self.assertNoMessages():
            self.checker.visit_call(call_node)
