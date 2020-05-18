# Release Checklist

- Choose the next [CalVer](https://calver.org/) version, e.g. `20.05` (`YY.MM`).
- Ensure that `CHANGELOG.md` is up-to-date including version numbers.
- Create a release branch `release/20.05` from master.
- Critical issues should have fixes delivered to both master and `release/20.05`.
- On the release branch, update the version in `VERSION`.
- Commit and push.
- Run the [release pipeline](https://dev.azure.com/sgx-lkl/sgx-lkl/_build?definitionId=5) and wait for successful completion.
- Create and push a new git tag `20.05` from the release branch.
- Switch to master and update `VERSION` to `20.06-dev` with the expected next version.

## Pre-release and patch releases  

- Any pre-release and patch releases are from commits in the release branch `release/20.05`.
- Release candidates have a version like `20.05-rc1`,`20.05-rc2`, etc.
- After a final release (`20.05`), patches have a version like `20.05.1`, `20.05.2`, etc.
- Make sure to update `VERSION` with the pre-release / patch version.
