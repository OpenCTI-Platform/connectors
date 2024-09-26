#!bin/bash

TEST_REQUIREMENT_FILES=$(find . -name test-requirements.txt)

echo 'Start to install dependencies...'
echo $TEST_REQUIREMENT_FILES

for file in $TEST_REQUIREMENT_FILES
do
  echo $file
  pip install -r $file

  project=$(dirname $(dirname $file))

  pytest $project
done


