#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase
def retrieve_all(bundle, key, value):
    for item in bundle.get("objects"):
        if item.get(key) == value:
            yield item