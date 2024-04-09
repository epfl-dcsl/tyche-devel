# Microbenchmarks

# Overview

There are mainly three distinct microbenchmarks:

`create/delete`:

This benchmarks the creation/deletion time for domains of various size.
It provides measurements for (1) enclave (carve/hash/cleanup), (2) carves (carve/no hash/no cleanup)
and (3) sandboxes (no carve/ no hash/ no cleanup).
The available domain sizes are: `[8k, 12k, 256k, 512k, 1M, 10M]`

`transitions`:

This benchmark measures the time needed to transition and come back from a domain.
It outputs an estimated cost per-call (1 direction).

`attestation`:

This benchmarks measures
(1) the time to create an attestation when domains are loaded.
(2) the number of bytes in the attestation.

# Environment variables

The benchmark binary uses environment variables for configuration.

### Boolean

Boolean values accept `true`, `True`, `TRUE`, and `1`
and `false`, `False`, `FALSE`, and `0`.

We use booleans to select benchmarks to run and workloads.
Multiple benchmarks and multiple workloads can be selected at once.

The benchmarks are:

`RUN_CREATE_DELETE`: the create/delete benchmark.

`RUN_TRANSITION`: the transition benchmark.

`RUN_ATTESTATION`: the attestation benchmark.

The workloads are:

`RUN_ENCLAVES`: run selected benchs with enclaves (carve/hash/cleanup).

`RUN_SANDBOXES`: run selected benchs with sandboxes (no carve/no hash/no cleanup)

`RUN_CARVES`: run selected benchs with carves (carve/no hash/no cleanup)


### Domain size argument.

Used for create/delete and attestation benchmarks.
A name that solely identifies the size of the dom.
The valid names are defined in src/main.c:

```
const char* domain_size_names[7] = {
	"8k",
	"12k",
	"128k",
	"256k",
	"512k",
	"1M",
	"10M",
};

```
`RUN_MIN`: size to start from (inclusive).
`RUN_MAX`: size to finish at (incusive).

We check the invariant `RUN_MIN` <= `RUN_MAX`


### Number of iterations

`RUN_NB_ITER`: 

Change the default number of iterations.
Must be a valid number parsed with `strtoul`

### Repetition per iterations

`RUN_REP_PER_ITER`:

In case we want to run the same benchmark many times.

### Defaults 

We have default values defined in `src/main.c` for all environment variables.

# Benchmarks algorithms 

## Create/ Delete

The main logic loop is as follows:

```
// For all the selected sizes such that:
// RUN_MIN and RUN_MAX in [8k, 12k, 128k, 256k, 512k, 1M, 10M]
// with RUN_MIN <= RUN_MAX

// Creation
for s <- [RUN_MIN, RUN_MAX]:
	create_res[s] = measure {
		for i <- [0, RUN_NB_ITER[:
			create(s)
		}

//Deletion
for s <- [RUN_MIN, RUN_MAX]:
	delete_res[s] = measure {
		for i <- [0, RUN_NB_ITER[:
			delete(s)
		}

// source code in src/internal.c
```

It can run for `enclaves`, `carves`, and `sandboxes`.

## Transitions

The main logic loop is as follows:

```
/// For PATH in [bin/enclaves, bin/sandboxes, bin/carves]

for s <- [0, RUN_REP_ITER[:
	res[s] = measure {
		for i <- [0, RUN_NB_ITER[:
			call(PATH/transition)
	}
	
// source code in src/internal.c
```
It can run for `enclaves`, `carves`, and `sandboxes`.

## Attestation

The main logic loop is as follows

```
for d <- [RUN_MIN, RUN_MAX]:
	create(d)

for i <- [0, RUN_REP_ITER[:
	results[i] = measure {
		for j <- [0, RUN_NB_ITER[:
			sizes[i] = attest(all)
	}

// Reports (results[i], results[i]/RUN_NB_ITER, sizes[i])
// source code in src/internal.c
```

It can run for `enclaves`, `carves`, and `sandboxes`.

# Compilation

## Create/Delete

The `Makefile` creates a `mock_dom` to be used as the domain.
It contains two regions (TEXT and RO) by default, so 2 pages.
We generate a `mock_app` and use tychools to generate all the binaries to be loaded by the benchmark.
Note that when we add segments, we take care of computing real byte size, e.g., 1K = 1024 bytes and to remove the two pages that we have already.

:warning: We still need to configure some extra attributes in json to hash/cleanup regions.

Enclaves have their manifests in `manifests/enclaves/` and generate their binaries in `bin/enclaves/`.
Sandboxes have their manifests in `manifests/sandboxes` and generate their binaries in `bin/sandboxes`.
Carves have their manifests in `manifests/carve` and generate their binaries in `bin/carve`.

## Transitions

The transition domain source code is in `transition/`.
It contains a loop that keeps switching back to the parent.
The `Makefile` generates a binary called `trans_dom`.
It packages it with `mock_app` using tychools and manifests in `manifests/{enclaves,carve,sandboxes}/transition,json` and puts the binary in the correspond `bin` sub folder.

## Attestation

This benchmark reuses the same domains as the create/delete one.
We load the selected domains and take our measurements.
