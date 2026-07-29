# reference/

Place a pre-built `sbom.db` here if you want to ship a queryable KB with the skill (e.g. for a
shared engagement). The `q.sh` helper defaults to `./sbom.db` in the skill root (the build output);
override with `SBOM_DB=reference/sbom.db` to query a shipped reference KB directly.
