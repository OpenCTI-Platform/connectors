# How To Implement new Observable

## Checklist

- Go to the `connectors_sdk/models/octi/activities/observations.py` module and create a new class that inherits from `Observable`.
- Decorate the class with `@MODEL_REGISTRY.register` to register it as an OCTI model.
- Implement the `to_stix2_object` method to convert your observable to a STIX2 object.
- Implement Unit Tests for your new observable class in the `tests/test_models/test_octi/test_activities/test/observations.py` module.
- Add your new observable to the `connectors_sdk/models/octi/__init__.py` module to ensure it is discoverable.
- Add your new observable to `tests/test_models/test_octi/test_api.py` tested entities.
