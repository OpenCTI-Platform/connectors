#!/usr/bin/env bash
set -e

connector_name="$1"

BASE=master
BRANCH="feat/4857-migrate-$connector_name"
REVIEWERS="helene-nguyen,Megafredo,Kakudou,Ninoxe,mariot,jabesq,throuxel" # GitHub usernames (comma-separated)
LABELS="do not merge,filigran team,connector: composer,connector: ${connector_name//-/ }" # Labels (comma-separated)

git checkout -b "$BRANCH"
git add -A
git commit -m "feat: automated migration"

LAST_COMMIT=$(git rev-parse HEAD)

git fetch origin "$BASE"
git reset --hard origin/$BASE
git cherry-pick "$LAST_COMMIT"

git push -u --force-with-lease origin "$BRANCH"

gh pr create \
  --base "$BASE" \
  --head "$BRANCH" \
  --reviewer "$REVIEWERS" \
  --label "$LABELS" \
  --title "[$connector_name] Update connector to be \"manager_supported\"" \
  --body "### Proposed changes

* automated code changes:
  - add \`settings.py\`
  - update \`connector.py\`
  - update \`main.py\` or \`__main__.py\`
  - add unit tests

### Related issues

* #4857 

### Checklist

- [x] I consider the submitted work as finished
- [x] I have signed my commits using GPG key.
- [ ] I tested the code for its functionality using different use cases
- [ ] I added/update the relevant documentation (either on github or on notion)
- [ ] Where necessary I refactored code to improve the overall quality

### Further comments

The code needs to be reviewed by two people: one must fix any issue, the other one review the final commits.
"
