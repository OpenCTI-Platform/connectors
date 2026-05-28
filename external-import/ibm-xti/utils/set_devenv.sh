#!/bin/bash

if ! (return 0 2>/dev/null); then
    echo "ERROR: Please source this script"
    exit 1
fi

#
# Usage statement
#
function usage() {
    echo "Sets up your development environment to contribute to this repo"
    echo
    echo "Usage: source utils/set_devenv.sh <ARGS>"
    echo 
    echo "      --reset"
    echo "                   (Optional) (Re)create your local Python environment"
    echo
    echo "      -h|--help    Output this usage statement."
    echo
}

#
# Parameter processing
#
reset=false

while [[ $# -gt 0 ]]
do
key="$1"
shift
case $key in
    --reset)
    reset=true
    ;;
    -h|--help)
    usage
    return
    ;;
    *)
    echo "Unrecognized parameter: $key"
    usage
    return
esac
done

if ! hash brew 2>/dev/null; then
    >&2 echo "ERROR: Homebrew is required for this script to run"
    >&2 echo $'\tInstallation resources can be found here: https://brew.sh/'
    return 1
fi

if [[ ! -d "$(brew --prefix)"/Cellar/libmagic ]]; then
    echo "Installing missing dependency 'libmagic' with Homebrew"
    brew install libmagic
fi

if [[ "$reset" == true ]]; then
    if [[ -n "$VIRTUAL_ENV" ]]; then
        deactivate
    fi

    if [[ -d venv ]]; then
        echo "Removing venv"
        rm -rf venv
    fi
fi

export VENV="$PWD"/venv

set_venv=false
if [[ ! -d venv ]]; then
    if ! python3 -m pip show -q virtualenv; then
        python3 -m pip install --user virtualenv
    fi
    
    python3 -m venv venv
    set_venv=true
fi

# shellcheck disable=SC1091
. "$VENV"/bin/activate

if [[ $set_venv == true ]]; then
    "$VENV"/bin/pip install --upgrade pip
    "$VENV"/bin/pip install -r src/requirements.txt

    echo
    echo "Created virtualenv: $VENV"
fi

unset set_venv
