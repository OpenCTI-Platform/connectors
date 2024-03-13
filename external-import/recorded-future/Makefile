# The only place to bump the version
VERSION := 1.0.2
VERSION_FILE := src/rflib/_version.py
BUILDID := $(if $(SVN_REVISION),$(SVN_REVISION),$(shell git rev-list --count HEAD))
PCK_DIR := ps_opencti_notes$(VERSION)-$(BUILDID)
PACKAGE := $(PCK_DIR).tar.gz
BUILD_DIR := pkg_build
BUILD_OUT := $(BUILD_DIR)/$(PCK_DIR)

# Commands
SED := sed
BLACK := black --line-length 100 -S
FLAKE8 := flake8
PYLINT := pylint
PEPDOCSTYLE := pydocstyle
PYTHON := python3
RUN_UNIT_TESTS := $(PYTHON) -m pytest
CWD := $(shell pwd)
VIRTUALENV := $(shell command -v virtualenv 2> /dev/null)
UNAME := $(shell uname)
RSYNC := rsync -rav
TAR := tar
MV := mv

# SED command arguments to replace 9.9.9-dev with the value of $(VERSION)
NEW_VERSION_STRING:=
ifeq ($(UNAME),Darwin)
NEW_VERSION_STRING:= -i '' 's/9.9.9-dev/$(VERSION)/g' src/rflib/_version.py
else
NEW_VERSION_STRING:= -i 's/9.9.9-dev/$(VERSION)/g' src/rflib/_version.py
endif

# UNDO SED command arguments to replace value of $(VERSION) with 9.9.9-dev
OLD_VERSION_STRING :=
ifeq ($(UNAME),Darwin)
OLD_VERSION_STRING := -i '' 's/$(VERSION)/9.9.9-dev/g' src/rflib/_version.py
else
OLD_VERSION_STRING := -i 's/$(VERSION)/9.9.9-dev/g' src/rflib/_version.py
endif

.PHONY: unittests, clear_cache, review, black, check_black, flake8, pylint, pydocstyle, test, clean, setup

help:
	@echo "Available targets:"
	@echo " setup       - Setup dev environment (install venv, dependencies)"
	@echo " test        - run review and unittests"
	@echo " unittests   - run nosetests to perform unittests"
	@echo " review      - run black_check, flake8, pylint and pydocstyle"
	@echo "   review_style  - Code style review"
	@echo "     check_black     - checks that black has been applied"
	@echo "     flake8          - python style review"
	@echo "   pydocstyle      - review inline documentation"
	@echo "   pylint          - pylint static analysis"
	@echo " build       - prepares the files for packaging"
	@echo " package     - run build & prepare the tar.gz file"
	@echo "Miscellaneous targets:"
	@echo " clean       - delete build and packaging artifacts"
	@echo " clear_cache - remove python pycache and pytest_cache"
	@echo " black       - formats things according to black standard"

##########################################
#
# Targets related to versioning (_version.py)
#
##########################################
addVersion:
	@echo "* Adding version $(VERSION) to $(VERSION_FILE)"
	$(SED) $(NEW_VERSION_STRING)

undoVersion:
	@echo "* Removing version $(VERSION) from $(VERSION_FILE)"
	$(SED) $(OLD_VERSION_STRING)


##########################################
#
# Targets related to build
#
##########################################
build: addVersion clear_cache build_dirs build_rsync undoVersion


build_dirs:
	@echo "* Creating build root directory"
	mkdir -p $(BUILD_DIR)
	@if [ -d $(BUILD_OUT) ]; then rm -rf $(BUILD_OUT); fi
	@echo "* Creating build output directory $(BUILD_OUT)"
	mkdir -p $(BUILD_OUT)
	#mkdir -p $(BUILD_OUT)/deps

build_rsync: build_dirs
	@echo "* Copying files to build output directory"
	$(RSYNC) src/ $(BUILD_OUT)/src --exclude='*.pyc' --exclude='config.yml'
	$(RSYNC) Dockerfile $(BUILD_OUT)
	$(RSYNC) docker-compose.yml $(BUILD_OUT)
	$(RSYNC) README.md $(BUILD_OUT)
	$(RSYNC) entrypoint.sh $(BUILD_OUT)

##########################################
#
# Targets related to package
#
##########################################
package: build package_gzip


package_gzip:
	@echo "* Packaging $(PACKAGE)"
	$(TAR) -zcv --exclude='.DS_Store' --exclude "__MACOSX" --exclude "__pycache__" -C $(BUILD_DIR) -f $(PACKAGE) $(PCK_DIR)
	@echo "* Removing build artifacts"
	rm -rf $(BUILD_OUT)/*
	@echo "* Moving package to build output directory"
	$(MV) $(PACKAGE) $(BUILD_OUT)
	@echo "* Packaging has compelted successfully"
	@echo "* Package is ready for client delivery: $(BUILD_OUT)/$(PACKAGE)"

##########################################
#
# Targets related to development environment setup
#
##########################################
setup:
	ifndef VIRTUALENV
		@echo "virtualenv not found, using python3 -m venv venv"
		$(PYTHON) -m venv venv
	else
		@echo "Creating virtual environment using virtualenv"
		virtualenv venv
	endif

	. $(CWD)/venv/bin/activate && pip install -r requirements-dev.txt
	@echo "Success! Development enviroment is ready"
	@echo "Please activate the virtualenv with: source venv/bin/activate"


##########################################
#
# Targets related to unittest
#
##########################################
test: review unittests

unittests:
	@echo "* Starting unit tests"
	$(RUN_UNIT_TESTS) --cov=src --cov-report html --cov-branch --cov-report term --junitxml=result.xml

##########################################
#
# Targets related to code review
#
##########################################
review: review_style pylint pydocstyle

review_style: check_black flake8

black:
	$(BLACK) src/rflib/*.py --exclude="static"
	$(BLACK) src/*.py --exclude="static"
	$(BLACK) tests/*.py --exclude="static"

check_black:
	$(BLACK) src/rflib/*.py --exclude="static" --check
	$(BLACK) src/*.py --exclude="static" --check
	$(BLACK) tests/*.py --exclude="static" --check

flake8:
	$(FLAKE8) src/rflib/*.py
	$(FLAKE8) src/*.py
	$(FLAKE8) tests/*.py

pylint:
	$(PYLINT) -E src/rflib/*.py
	$(PYLINT) -E src/*.py
	$(FLAKE8) tests/*.py

pydocstyle:
	$(PEPDOCSTYLE) src/rflib/*.py
	$(PEPDOCSTYLE) src/*.py

##########################################
#
# Misc targets
#
##########################################
clear_cache:
	@echo "* Removing __pycache__ and .pytest_cache"
	rm -rf src/rflib/__pycache__
	rm -rf tests/__pycache__
	rm -rf .pytest_cache
