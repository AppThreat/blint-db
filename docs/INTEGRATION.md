<!--
SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>

SPDX-License-Identifier: MIT
-->

# Integrating with blint-db

This document describes the `blint-db` schema and how to query it. It is aimed at people building on top of a database rather than at people generating one; for the build pipeline see the [README](../README.md).

`blint-db` databases are **generated, not distributed as long-lived state**. You build one from the projects you care about and rebuild it when the schema or the corpus changes. There is therefore no migration path between schema versions and no backwards compatibility layer: `create_database` writes the current schema, and opening a file written by a different one fails fast rather than producing wrong answers.

- Package version: **2.1.0**
- Schema version: **3** (recorded in `SchemaMeta`)

## Design in one paragraph

The database is a corpus of binaries with known provenance. A `Project` is a piece of software, a `Build` is one way it was compiled, and a `Binary` is one artifact that build produced. Everything else hangs off `Binary` and exists to answer one question: given an unknown binary, which known one is it, and what does it need to run? Symbols and function fingerprints answer the identification half. The ABI and dependency tables answer the runtime half.

## Schema

### Identity chain

```
Projects  1---N  Builds  1---N  Binaries
```

Every table below cascades from `Binaries`, so deleting a binary removes all of its evidence.

#### `Projects`

| Column             | Notes                                           |
| ------------------ | ----------------------------------------------- |
| `project_id`       | Primary key.                                    |
| `project_key`      | Stable identity hash; unique.                   |
| `name`             | Logical project name.                           |
| `purl`             | Package URL, when the ecosystem provides one.   |
| `ecosystem`        | `conan`, `vcpkg`, `cargo`, `homebrew`, `meson`. |
| `metadata_json`    | Free-form project metadata.                     |
| `source_sbom_json` | Source SBOM captured at build time.             |

#### `Builds`

One row per compilation context. The same project built for two architectures, or once stripped and once not, produces two builds.

| Column                                       | Notes                                |
| -------------------------------------------- | ------------------------------------ |
| `build_system`                               | How it was built.                    |
| `target_os`, `target_arch`, `target_triplet` | Target platform.                     |
| `llvm_target_tuple`                          | Normalized target, useful for joins. |
| `build_mode`, `optimization`, `is_stripped`  | Build configuration.                 |

#### `Binaries`

One row per artifact. Alongside the identity and hash columns, five columns are denormalized out of `abi_analysis_json` so that a corpus can be filtered by runtime without unpacking JSON per row:

| Column                         | Notes                                                                         |
| ------------------------------ | ----------------------------------------------------------------------------- |
| `libc`                         | `glibc`, `musl`, `bionic`, or null.                                           |
| `min_glibc_version`            | Oldest glibc the binary can run on. Null when it binds no glibc version node. |
| `uses_ifunc`                   | Defines or imports an indirect function.                                      |
| `uses_private_symbol_versions` | Binds a private node such as `GLIBC_PRIVATE`, which has no stability promise. |
| `uses_runtime_loading`         | Opens libraries at runtime rather than only linking against them.             |

`metadata_json` holds the sanitized `blint` metadata with the raw `disassembled_functions` payload removed; those are normalized into `FunctionFingerprints` instead.

#### `Symbols`

Normalized symbols across the `blint` metadata buckets named in `source` (`functions`, `imports`, `exports`, `symtab_symbols`, `dynamic_symbols`, and others).

| Column                                                     | Notes                                                    |
| ---------------------------------------------------------- | -------------------------------------------------------- |
| `name`, `source`, `address`, `size`                        | Identity within a binary.                                |
| `is_imported`, `is_exported`, `is_function`, `is_variable` | Classification.                                          |
| `symbol_version`                                           | The version node the symbol binds to, e.g. `GLIBC_2.28`. |
| `raw_name`                                                 | The linkage name, when demangling changed it.            |

`symbol_version` is what makes a symbol match version aware. Without it, `memcpy@GLIBC_2.14` and `memcpy@GLIBC_2.2.5` are indistinguishable evidence, which is a large part of why symbol-only identification picks the wrong build of a library.

`raw_name` is what makes a C++ or Rust symbol matchable at all. `name` holds the demangled form, which is what a reader wants to see, but a provider's export table holds the mangled form. `_ZN3APT16PackageContainer5beginEv` and `APT::PackageContainer::begin()` are the same symbol, and only the first appears in another binary's exports. It is null for plain C symbols rather than duplicating `name`, so the index stays small.

Both `lookup_symbol_matches` and `lookup_versioned_symbol_matches` search either column, so a caller can pass whichever form it holds.

#### `AbiRequirements`

One row per version provider a binary requires. Derived from the symbols the binary **imports**, not from its version definition table — the definition table lists nodes the linker recorded whether or not anything binds to them, so a floor read from it is routinely wrong in both directions.

| Column                          | Notes                                                                                                      |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `provider`                      | Version node provider: `GLIBC`, `GLIBCXX`, `LIBPAM_EXTENSION`, `krb5`, and so on.                          |
| `min_version`                   | The **highest** node any imported symbol binds to, i.e. the minimum the runtime must supply.               |
| `symbol_count`                  | How many imported symbols bind to this provider, indicating how deeply the binary depends on it.           |
| `determining_symbols`           | Comma-separated imports that set `min_version`. Traces a surprising floor back to the one symbol at fault. |
| `package_name`, `package_group` | Package coordinates, e.g. `libc` / `gnu` for `GLIBC`.                                                      |

`min_version` is null for providers whose nodes genuinely carry no version — `GLIBC_PRIVATE`, `SASL2`, `SD_SHARED` are all real examples.

#### `Dependencies`

Dependency evidence, discriminated by `source`:

| `source`                                                      | Where it comes from                                                    |
| ------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `dynamic_entries`                                             | `DT_NEEDED` and `SONAME`.                                              |
| `libraries`                                                   | Mach-O load commands.                                                  |
| `import_dependencies`                                         | The import graph, including per-library symbol edges.                  |
| `dlopen_dependencies`                                         | Declared through the packaging note. `tag` holds the priority.         |
| `recovered_dependencies`                                      | Recovered from the image. `tag` holds the confidence grade.            |
| `link_closure`                                                | Resolved against a real filesystem. `tag` is `direct` or `transitive`. |
| `link_closure_missing`                                        | Required but not found on the search path.                             |
| `go_dependencies`, `rust_dependencies`, `dotnet_dependencies` | Language-specific build metadata.                                      |

The three runtime-loading sources matter because a library opened through `dlopen` never appears in `dynamic_entries`, and those are frequently the components that determine what a binary can do: drivers, codecs, authentication modules and cryptographic providers are almost always loaded on demand.

#### `FunctionFingerprints`

Disassembly-derived per-function hashes (`assembly_hash`, `instruction_hash`) and behavioural flags. Present only when the ingest ran with disassembly enabled; check `Binaries.disassembly_enabled`.

#### `SourceGraphs`, `CallGraphNodes`, `CallGraphEdges`

Callgraph storage shared between binary-derived and source-derived graphs, discriminated by `graph_kind` (`binary` or `source`) and `owner_id`.

### Indexes

Queries are expected to filter on these. Anything outside them will table-scan.

| Index                          | Supports                                      |
| ------------------------------ | --------------------------------------------- |
| `idx_symbols_lookup`           | `(name, source, binary_id)` symbol matching.  |
| `idx_symbols_version`          | Version-aware symbol matching.                |
| `idx_binaries_libc`            | `(libc, min_glibc_version)` corpus filtering. |
| `idx_abi_provider`             | `(provider, min_version)` ABI queries.        |
| `idx_dependencies_source_name` | Dependency lookups by kind.                   |
| `idx_functions_*_hash`         | Function hash matching.                       |
| `idx_binaries_type_target`     | Filtering by binary type and target tuple.    |

## Python API

The helpers in `blint_db.handlers.sqlite_handler` cover the common queries and handle the details that are easy to get wrong in raw SQL.

```python
from blint_db.handlers.sqlite_handler import (
    lookup_binaries_by_abi_requirement,
    lookup_function_hash_matches,
    lookup_symbol_matches,
    lookup_versioned_symbol_matches,
)
```

### Identify a binary by its symbols

```python
lookup_symbol_matches(["curl_easy_init", "curl_easy_setopt"], limit=5)

# Mangled names work equally well, and are the only form that matches C++.
lookup_symbol_matches(["_ZN3APT16PackageContainer5beginEv"])
```

Returns candidate binaries ranked by how many distinct symbol names matched. Each value is matched against both `name` and `raw_name`.

### Identify it more precisely using version nodes

```python
lookup_versioned_symbol_matches([
    ("statx", "GLIBC_2.28"),
    ("memcpy", "GLIBC_2.14"),
])
```

Each pair must match both the name and the node, which separates builds of a library that export the same names against different runtime versions. Prefer this over `lookup_symbol_matches` whenever the unknown binary has versioned imports.

### Find everything that will not run on a target

```python
# Cannot start on a host with glibc older than 2.34.
lookup_binaries_by_abi_requirement("GLIBC", min_version="2.34")

# Every binary with a libstdc++ requirement, regardless of version.
lookup_binaries_by_abi_requirement("GLIBCXX")
```

Version comparison happens in Python, not SQL. **Do not filter versions with SQL comparison operators** — SQLite orders these strings lexically and will place `2.9` above `2.34`, silently omitting most of the corpus. If you write your own query, pull the rows and sort them with `blint.lib.elf_abi.version_sort_key`.

### Match by function hash

```python
lookup_function_hash_matches(instruction_hashes=[...], assembly_hashes=[...])
```

`instruction_hash` covers mnemonics only and survives relocation differences; `assembly_hash` includes operands and is stricter. Try the instruction hash first.

## SQL recipes

For anything the helpers do not cover, `execute_statement(statement, arguments=None, *, db_file=None)` runs raw SQL and returns dict rows.

```python
from blint_db.handlers.sqlite_handler import execute_statement

execute_statement(
    "SELECT name, min_glibc_version FROM Binaries WHERE libc = ?",
    ("glibc",),
)
```

**Corpus composition by C library and architecture**

```sql
SELECT libc, machine_type, COUNT(*) AS binaries
FROM Binaries
GROUP BY libc, machine_type
ORDER BY binaries DESC;
```

**Which imports are raising the runtime floor across the corpus**

Useful for finding the one or two symbols that cost portability most often.

```sql
SELECT determining_symbols, min_version, COUNT(*) AS binaries
FROM AbiRequirements
WHERE provider = 'GLIBC' AND determining_symbols IS NOT NULL
GROUP BY determining_symbols, min_version
ORDER BY binaries DESC
LIMIT 20;
```

**Dependencies that exist only at runtime**

These are invisible to any tool reading the dynamic table, which is what makes them worth querying for directly.

```sql
SELECT Dependencies.name, Dependencies.tag AS confidence, COUNT(*) AS binaries
FROM Dependencies
WHERE Dependencies.source IN ('recovered_dependencies', 'dlopen_dependencies')
GROUP BY Dependencies.name, Dependencies.tag
ORDER BY binaries DESC;
```

Treat `tag` as the confidence grade for `recovered_dependencies`: `high` means the soname is a literal in a read-only data section of a binary that imports a loading entry point, `medium` and `low` are weaker placements.

**Binaries with a packaging gap**

A library that nothing on the search path supplies is a load-time failure and usually an undeclared runtime dependency.

```sql
SELECT Binaries.name AS binary_name, Dependencies.name AS missing_library
FROM Dependencies
JOIN Binaries ON Dependencies.binary_id = Binaries.binary_id
WHERE Dependencies.source = 'link_closure_missing';
```

**Binaries bound to C library internals**

```sql
SELECT Binaries.name, Binaries.libc, Binaries.min_glibc_version
FROM Binaries
WHERE Binaries.uses_private_symbol_versions = 1
ORDER BY Binaries.name;
```

**Compare the same project across builds**

```sql
SELECT Builds.target_arch, Binaries.name, Binaries.min_glibc_version
FROM Binaries
JOIN Builds ON Binaries.build_id = Builds.build_id
JOIN Projects ON Builds.project_id = Projects.project_id
WHERE Projects.name = ?
ORDER BY Builds.target_arch;
```

The floor commonly differs between architectures for the same source, because different targets bind different version nodes for the same call.

## Pitfalls

**Version strings do not sort lexically.** Covered above, and it is the single most likely thing to go wrong. `2.34` must sort above `2.9`.

**A version in `AbiRequirements` is a floor, not an installed version.** `min_version = '2.28'` means "2.28 or newer is required". Matching it against a vulnerability database as an exact version will produce wrong results.

**A null `min_version` is not a parse failure.** Several real providers carry no version at all.

**`link_closure` rows describe one filesystem.** They are only produced when closure resolution was enabled during the `blint` run, and they describe the root it resolved against. A closure resolved on a build host says nothing about the deployment image.

**Absence of function fingerprints is not absence of functions.** Check `Binaries.disassembly_enabled` before concluding a binary has none.

**Symbol counts are not comparable across stripped and unstripped builds.** Filter on `Builds.is_stripped` when ranking matches, or a stripped binary will always look like a poor match.
