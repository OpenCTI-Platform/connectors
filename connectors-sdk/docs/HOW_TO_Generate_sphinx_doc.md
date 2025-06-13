# How To Generate the package documentation with Sphinx

## Prerequisites

Install the package using [doc] extras:

```bash
python -m pip install .[doc]
```

## Generate the Documentation

To generate the documentation, run the following command:

```bash
cd docs/sphinx
sphinx-build -b html . _build/html
```

It will generate the HTML documentation in the `_build/html` directory.

## View the Documentation

You can view the generated documentation by opening the `_build/html/index.html` file in a web browser.

## Update the Documentation generation file

### Clean the build directory

```bash
cd docs/sphinx
sphinx-build -M clean . _build/html
```

### Update the documentation generation file

```bash
cd docs/sphinx
sphinx-apidoc -f -o . ../../connectors_sdk
```

This command will generate the `.rst` files for the package.

Then you can rebuild the documentation with the updated files.
