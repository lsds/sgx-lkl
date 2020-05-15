# Release Checklist

- Decide on next version (following [CalVer](https://calver.org/)):
  - Regular release: `YY.MM`, e.g. `20.05`
  - Release candidate of regular release: `YY.MM-rcN`, e.g. `20.05-rc1`
  - Patch release: `YY.MM.P`, e.g. `20.05.1`
  - Release candidate of patch release: `YY.MM.P-rcN`, e.g. `20.05.1-rc1`
- Ensure `CHANGELOG.md` is up-to-date including version numbers
  - If not, update and submit PR
- Create release branch `releases/<VERSION>` from development branch
- Update version in `VERSION`
- Commit and push
- Trigger the release CI pipeline (**TODO**)
- Wait for successful completion of pipeline
- `git tag <VERSION>` and `git push --tags`

If the release was a regular release:
- Switch to development branch
- Update version in `VERSION` to `YY.MM-dev` with expected next version number
