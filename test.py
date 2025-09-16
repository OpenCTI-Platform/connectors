import os

previous_version = "6.7.17"
new_version = "6.7.18"

# Update connectors-sdk git URL
os.system(
    "cd ./ && find . \\( -name 'pyproject.toml' -o -name 'requirements.txt' \\) -exec sed -i 's|connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@"
    + previous_version
    + "#subdirectory=connectors-sdk|connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@"
    + new_version
    + "#subdirectory=connectors-sdk|g' {} +"
)
