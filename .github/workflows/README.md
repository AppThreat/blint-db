# Blint-db Github Workflow 

## Description
Github workflows for blint-db, will build a sqlite3 database named `blint.db` which is uploaded to `AppThreat/blintdb-meson` and `AppThreat/blint-vcpkg`.

There are two build systems, `build-meson` and `build-vcpkg`.
These require an ubuntu system to run due to the use of `apt` to install some build dependencies.

## Details


### Future Improvements