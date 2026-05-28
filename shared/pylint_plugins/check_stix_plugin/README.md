# STIX2 ID Generation Checker

This module implements a custom `pylint` checker to ensure that objects from the STIX2 library (specifically domain objects and relationships) are not instantiated without providing a deterministic ID. This helps prevent issues such as object duplication and ID explosion in OpenCTI.

## Overview

The module defines a `StixIdGeneratorChecker` that inspects calls to constructors of specific STIX2 objects, verifying that they include an `id` keyword argument when instantiated. If no `id` is provided, it raises a warning (`W9101`) to encourage the use of deterministic ID generation.

## Features

- **Constructor Detection**: It detects calls to constructors of STIX2 objects such as `Location` and `Relationship`.
- **Inheritance Support**: The checker can identify objects that inherit from STIX2 domain objects, even if they are wrapped or subclassed.
- **Keyword Argument Extraction**: It inspects the keyword arguments passed during object instantiation, ensuring the presence of an `id` argument.
- **Custom Warning Message**: The warning (`W9101`) is issued when a STIX2 object is instantiated without an `id`.

## Key Components

### `StixIdGeneratorChecker`

This class extends `pylint`'s `BaseChecker` and is responsible for visiting AST nodes and checking for calls to STIX2 constructors.

### Helper Functions

- **`find_constructor_calls(node, class_names, package_name)`**: Recursively traverses the AST to find constructor calls of the specified classes.

## Usage

Install necessary dependencies:
```shell
cd shared/pylint_plugins/check_stix_plugin
pip install -r requirements.txt
```

To use this checker in your project, add this module to your `pylint` configuration.

You can also directly run it in CLI to lint a dedicated directory or python module : 
```shell
cd shared/pylint_plugins/check_stix_plugin
PYTHONPATH=. python -m pylint <path_to_my_code> --load-plugins linter_stix_id_generator
```
If you only want to test the custom module :
```shell
cd shared/pylint_plugins/check_stix_plugin
PYTHONPATH=. python -m pylint <path_to_my_code> --disable=all --enable=no_generated_id_stix,no-value-for-parameter,unused-import --load-plugins linter_stix_id_generator
```

To make the linter easier to read :
`--output-format=colorized`
## Examples

### Warning Example: 
The following example will trigger a warning since the `Location` object is instantiated without an `id`:
```python
from stix2 import Location
loc = Location(
    name="example"
)
```

### Resolution:
To avoid the warning, generate an ID using helper method. For instance :
```python
from stix2 import Location
from pycti.entities.opencti_location import Location as PyctiLocation
loc = Location(
    id=PyctiLocation.generate_id(name="example", x_opencti_location_type="City"),
    name="example",
)
```
