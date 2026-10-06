# Tests

Layout mirrors `src/` for fast navigation — find a module under `src/X/y.py`,
its tests live in `tests/X/test_y.py`.


## Running

```bash
# all tests + coverage
pytest tests/ --cov=src --cov-report=term-missing

# subset (e.g. adapters only)
pytest tests/adapters/

# single file
pytest tests/models/test_indicators.py -v
```

## Notes

- `tests/conftest.py` stubs `magic` (python-magic) before pycti imports — so
  unit tests run on hosts without system libmagic.
- Top-level `pyproject.toml` sets `pythonpath = ["src"]` so test imports
  use `from support.text_normalize import ...` rather than full
  `src.support.text_normalize` paths.
