# Blint-db Github Workflow

Github workflows for generating blint-db packages

## Description

These workflows will build a sqlite3 database named `blint.db`, which is then uploaded to `Appthreat/Packages` with the names `blintdb-meson` and `blintdb-vcpkg`.

Currently we build C/C++ with the goal to provide packages for more languages.

## Details

Our Workflows have the following general steps:

1. Setup blint-db repository using github action  
2. Install the latest python dependencies  
3. Clean up any files from previous runs  
4. Start `blint.db` generation using the blint-db cli
5. upload the db file to `ghcr.io` using `oras-py` package and `.oras/orasclient.py` script  

Blint-db workflows require an ubuntu system to run due to the use of `apt` to install some build dependencies.
Many of these dependencies are preinstalled on our workflow runner.

> We use `oras-py` as it is supported by both `arm64` and `x64` architectures.

### C/C++ Package Managers

We support two build systems for C/C++, `meson` and `vcpkg`.

### Future Improvements

list of possible future enhancements:

1. Support for more languages  
2. Improve build times  
