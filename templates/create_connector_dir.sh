#!/bin/bash
set -e

# Script to generate a new OpenCTI connector based on a template
# Usage: ./create_connector_dir.sh -t <TYPE> -n <NAME>

display_help() {
    echo "Usage: $0 -t <TYPE> -n <NAME>" >&2
    echo
    echo "   -t, --type                Specify the connector type"
    echo "   -n, --name                Specify the connector name"
    echo "   -h, --help                Display this help message"
    echo
    echo "Example:"
    echo "   $0 -t stream -n qradar"
    echo
    exit 1
}

# Check for required options
if [ $# -eq 0 ]; then
    display_help
    exit 1
fi

# Parse options
while :
do
    case "$1" in
        -n | --name)
            if [ -n "$2" ]; then
                NAME="$2"
                shift 2
            else
                echo "Error: '--name' requires a non-empty option argument." >&2
                exit 1
            fi
            ;;
        -t | --type)
            if [ -n "$2" ]; then
                TYPE="$2"
                shift 2
            else
                echo "Error: '--type' requires a non-empty option argument." >&2
                exit 1
            fi
            ;;
        -h | --help)
            display_help
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Error: Unknown option: $1" >&2
            display_help
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

# Validate inputs
if [ -z "$TYPE" ] || [ -z "$NAME" ]; then
    echo "Error: Both --type and --name are required arguments."
    display_help
    exit 1
fi

# Define accepted types
VALID_TYPES=("external-import" "internal-enrichment" "internal-export-file" "internal-import-file" "stream")

# Validate the connector type
TYPE_IS_VALID=false
for VALID_TYPE in "${VALID_TYPES[@]}"; do
    if [ "$TYPE" == "$VALID_TYPE" ]; then
        TYPE_IS_VALID=true
        break
    fi
done

if [ "$TYPE_IS_VALID" = false ]; then
    echo "Error: Invalid connector type '$TYPE'!"
    echo "Accepted types are: ${VALID_TYPES[*]}"
    exit 1
fi

if [[ ! "$NAME" =~ ^[a-zA-Z0-9-]+$ ]]; then
    echo "Error: Connector name '$NAME' is invalid!"
    echo "The name can only contain letters, digits, and hyphens (-)."
    exit 1
fi

# Enforce full lowercase name
NAME="${NAME,,}"

NEW_CONNECTOR_DIR="../$TYPE/$NAME"
TEMPLATE_DIR="$TYPE"

# Check if the template directory exists
if [ ! -d "$TEMPLATE_DIR" ]; then
    echo "Error: Template directory '$TEMPLATE_DIR' does not exist. Execute this script in the template directory"
    exit 1
fi

if [ -d "$NEW_CONNECTOR_DIR" ]; then
    echo "Error: Connector directory '$NEW_CONNECTOR_DIR' already exists!"
    exit 1
fi

# Create the new connector directory
echo "Creating new connector directory: $NEW_CONNECTOR_DIR"
mkdir -p "$NEW_CONNECTOR_DIR"

# Copy template files to the new directory
echo "Copying template files..."
cp -r "$TEMPLATE_DIR/"* "$NEW_CONNECTOR_DIR"

# Update placeholders in the copied files
echo "Customizing connector files..."

PYTHON_NAME="$(echo "$NAME" | sed -E 's/-([a-z])/\U\1/g' | sed -E 's/^(.)/\U\1/')"
CAPITALIZED_NAME=$(echo "$NAME" |  sed 's/.*/\U&/' | sed -E 's/-/_/g')

find "$NEW_CONNECTOR_DIR" -type f -exec sed -i \
    -e "s/template/$NAME/g" \
    -e "s/ConnectorTemplate/Connector${PYTHON_NAME}/g" \
    -e "s/TEMPLATE/${CAPITALIZED_NAME}/g" {} +

sed -i -e "s/$NAME/${NAME//-/_}/g" "$NEW_CONNECTOR_DIR/src/config.yml.sample"
sed -i -e "s/$NAME/${NAME//-/_}/g" "$NEW_CONNECTOR_DIR/src/${TYPE//-/_}_connector/config_variables.py"

echo "Connector '$NAME' of type '$TYPE' created successfully!"
echo "Navigate to $NEW_CONNECTOR_DIR to start development."
echo "Add the connector build in the CI:  ../.circleci/config.yml"
