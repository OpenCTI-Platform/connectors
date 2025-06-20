# Converters

A flexible, configurable system for converting any source data format to STIX objects with consistent error handling and validation.

## Overview

The Converters module provides a standardized approach to converting various source data formats to STIX objects with:

- Configurable mappers and conversion logic
- Consistent error handling and reporting
- Validation of input and output data
- Flexible pre/post-processing capabilities
- Factory system for creating and managing multiple converters

## Architecture

The Converters module follows a clean, modular design pattern:

```mermaid
graph TD
    A[GenericConverterFactory] --> B[GenericConverter]
    B --> C[GenericConverterConfig]
    C --> D[BaseMapper]
    D --> E[to_stix()]
    C --> F[Exception Class]
    C --> G[Input Model]
    C --> H[Pre/Post Processing]
    C --> I[Validation Functions]
```

### Core Components

1. **GenericConverter**: Main class for converting source data to STIX
2. **GenericConverterConfig**: Configuration defining conversion behavior
3. **BaseMapper**: Abstract interface that mapper classes implement
4. **GenericConverterFactory**: Factory for creating and managing converters

## Pain Points Addressed

| Problem | Solution |
|---------|----------|
| Inconsistent conversion logic | Standardized mapper interface |
| Input data validation | Configurable validation rules |
| Error handling complexity | Consistent exception handling |
| Output format inconsistency | Structured output validation |
| Managing multiple converters | Factory pattern with registry |
| Code duplication | Reusable conversion patterns |
| Conversion state tracking | Built-in tracking of converted objects |

## Usage Guide

### Basic Usage

```python
from utils.converters import GenericConverter, GenericConverterConfig, BaseMapper

# Define a mapper class
class MalwareMapper(BaseMapper):
    def __init__(self, data, organization=None):
        self.data = data
        self.organization = organization
    
    def to_stix(self):
        # Convert data to STIX object
        return {
            "id": f"malware--{self.data['id']}",
            "type": "malware",
            "name": self.data['name'],
            "created_by_ref": self.organization
        }

# Create configuration
config = GenericConverterConfig(
    entity_type="malware",
    mapper_class=MalwareMapper,
    output_stix_type="malware",
    exception_class=Exception,
    display_name="malware families"
)

# Create converter
converter = GenericConverter(config=config, logger=logger)

# Convert a single item
stix_object = converter.convert_single(
    {"id": "123", "name": "Malware1"}, 
    organization="organization--uuid"
)

# Convert multiple items
source_data = [
    {"id": "123", "name": "Malware1"},
    {"id": "456", "name": "Malware2"}
]
stix_objects = converter.convert_multiple(
    source_data, 
    organization="organization--uuid"
)
```

### Using the Factory Pattern

```python
from utils.converters import GenericConverterFactory, GenericConverterConfig

# Create a factory with global dependencies
factory = GenericConverterFactory(
    global_dependencies={
        "organization": "organization--uuid",
        "tlp_marking": "marking-definition--uuid"
    },
    logger=logger
)

# Register converter configurations
factory.register_config(
    "malware", 
    GenericConverterConfig(
        entity_type="malware",
        mapper_class=MalwareMapper,
        output_stix_type="malware",
        exception_class=MalwareConversionError,
        display_name="malware families"
    )
)

factory.register_config(
    "threat_actor", 
    GenericConverterConfig(
        entity_type="threat_actors",
        mapper_class=ThreatActorMapper,
        output_stix_type="threat-actor",
        exception_class=ThreatActorConversionError,
        display_name="threat actors"
    )
)

# Create converters as needed
malware_converter = factory.create_converter_by_name("malware")
threat_actor_converter = factory.create_converter_by_name("threat_actor")

# Create a pipeline of converters
pipeline = factory.create_conversion_pipeline(
    ["malware", "threat_actor"],
    shared_dependencies={"confidence": 80}
)
```

### With Input Validation

```python
from pydantic import BaseModel

# Define input model
class MalwareInput(BaseModel):
    id: str
    name: str
    description: str = None
    malware_types: list[str] = []

# Configure with input validation
config = GenericConverterConfig(
    entity_type="malware",
    mapper_class=MalwareMapper,
    output_stix_type="malware",
    exception_class=MalwareConversionError,
    display_name="malware families",
    input_model=MalwareInput,
    required_attributes=["id", "name"]
)

converter = GenericConverter(config=config, logger=logger)

# This will validate input against MalwareInput model
result = converter.convert_single({
    "id": "123",
    "name": "Malware1",
    "malware_types": ["ransomware"]
})
```

### With Pre/Post Processing

```python
# Define preprocessing function
def preprocess_input(input_data):
    """Normalize input data before conversion."""
    input_data["name"] = input_data["name"].strip().title()
    return input_data

# Define postprocessing function
def postprocess_output(stix_object):
    """Add additional fields to STIX output."""
    if not hasattr(stix_object, "x_custom_field"):
        stix_object.x_custom_field = "default_value"
    return stix_object

config = GenericConverterConfig(
    entity_type="malware",
    mapper_class=MalwareMapper,
    output_stix_type="malware",
    exception_class=MalwareConversionError,
    display_name="malware families",
    preprocessing_function=preprocess_input,
    postprocessing_function=postprocess_output
)

converter = GenericConverter(config=config, logger=logger)
```

### Converting Batches of Different Types

```python
# Process batches of different types
input_batches = {
    "malware": [
        {"id": "123", "name": "Malware1"},
        {"id": "456", "name": "Malware2"}
    ],
    "threat_actors": [
        {"id": "789", "name": "Actor1"},
        {"id": "012", "name": "Actor2"}
    ]
}

# Create converter with batch capability
factory = GenericConverterFactory(
    global_dependencies={"organization": "organization--uuid"}
)

# Register configs for each type
factory.register_config("malware", malware_config)
factory.register_config("threat_actor", threat_actor_config)

# Create converters
malware_converter = factory.create_converter_by_name("malware")
threat_actor_converter = factory.create_converter_by_name("threat_actor")

# Convert batches
malware_stix = malware_converter.convert_multiple(input_batches["malware"])
actor_stix = threat_actor_converter.convert_multiple(input_batches["threat_actors"])
```

### Tracking Converted Objects

```python
converter = GenericConverter(config=config, logger=logger)

# Convert items
converter.convert_multiple([
    {"id": "123", "name": "Item1"},
    {"id": "456", "name": "Item2"}
])

# Get all converted objects
all_objects = converter.get_converted_objects()
print(f"Converted {len(all_objects)} objects")

# Get mapping of original IDs to STIX IDs
id_map = converter.get_object_id_map()
for original_id, stix_id in id_map.items():
    print(f"Original ID {original_id} → STIX ID {stix_id}")

# Clear cache if needed
converter.clear_converted_objects()
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `entity_type` | Type of entity being converted | Required |
| `mapper_class` | Class responsible for conversion | Required |
| `output_stix_type` | STIX type being produced | Required |
| `exception_class` | Exception class for errors | Required |
| `display_name` | Human-readable name (plural) | Required |
| `input_model` | Model for input validation | `None` |
| `display_name_singular` | Human-readable singular name | Auto-generated |
| `validate_input` | Whether to validate input data | `True` |
| `validate_output` | Whether to validate STIX output | `True` |
| `additional_dependencies` | Dependencies for mapper | `{}` |
| `id_field` | Field containing entity ID | `"id"` |
| `name_field` | Field containing entity name | `None` |
| `required_attributes` | Required input attributes | `[]` |
| `preprocessing_function` | Function to preprocess input | `None` |
| `postprocessing_function` | Function to postprocess output | `None` |
| `to_stix` | Whether to return STIX or mapper | `True` |

## Creating Custom Mapper Classes

To create a custom mapper class:

```python
from utils.converters import BaseMapper
from stix2 import Malware  # Import appropriate STIX2 models

class CustomMapper(BaseMapper):
    def __init__(self, data, organization=None, confidence=None):
        self.data = data
        self.organization = organization
        self.confidence = confidence
        
    def to_stix(self):
        """Convert data to STIX format.
        
        Returns:
            _STIXBase21 object or Pydantic model (not dict)
        """
        # Create and return a proper STIX object (not a dict)
        stix_object = Malware(
            id=f"malware--{self.data['id']}",
            name=self.data['name'],
            created_by_ref=self.organization,
            confidence=self.confidence
        )
        
        # Note: to_stix() must return a proper STIX object (_STIXBase21)
        # or a Pydantic model, not a plain dictionary
        return stix_object
```

## Best Practices

1. **Define clear mapper interfaces**: Make mappers focused on a single conversion task
2. **Use appropriate validation**: Validate both input and output for consistency
3. **Handle errors gracefully**: Use custom exception classes for better error context
4. **Use the factory pattern**: Register and manage converters through the factory
5. **Track converted objects**: Use the built-in tracking for reporting and relationship building
6. **Apply preprocessing**: Normalize input data before conversion for consistent results
7. **Document mapper requirements**: Clearly specify required fields and formats for each mapper