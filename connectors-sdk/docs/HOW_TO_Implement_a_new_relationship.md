# How To Implement a new Relationship

## Checklist

- Go to the `connectors_sdk/models/octi/relationships.py` module and create a new class that inherits from `Relationship`.
- Decorate the class with `@MODEL_REGISTRY.register` to register it as an OCTI model.
- Implement Unit Tests for your new relationship class in the `tests/test_models/test_octi/test_relationships.py` module.
- Add your new relationship to the `connectors_sdk/models/octi/__init__.py` module to ensure it is discoverable.
- Add your new relationship to `tests/test_models/test_octi/test_api.py` tested entities.
