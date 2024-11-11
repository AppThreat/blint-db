# Project Compilers

This sub-module contains workflow steps to generate binaries, run blint on them and store the result in a database.

## Description

New workflows must follow these general steps given `project_name`:

1) add the project to the database and get the `pid`.
2) build the project using the package manager.
3) find all executables built (optionally strip them).
4) for all executables generated add it to the database and get `bid`.
5) run blint on the executable and retrieve the symbols and control flow data.
6) add retrieved to database using the `add_binary_export()` function