# Create Delete Benchmark

The binary `create_delete_bench` measures the creation and deletion of domains.

## Overview

The main logic loop is as follows:

```
// For all the selected sizes such that:
// RUN_MIN and RUN_MAX in [8k, 12k, 128k, 256k, 512k, 1M, 10M]
// with RUN_MIN <= RUN_MAX

// Creation
for s <- [run_min, run_max]:
	create_res[s] = measure {
		for i <- [0, run_nb_iter[:
			create(s)
		}

//Deletion
for s <- [run_min, run_max]:
	delete_res[s] = measure {
		for i <- [0, run_nb_iter[:
			delete(s)
		}

// source code in src/internal.c
```

It will run for `enclaves` and `sandboxes` separately.

## Parameters

The following parameters are supported as environment variables, but all have default values defined in `src/main.c`

### Boolean
Boolean values accept `true`, `True`, `TRUE`, and `1`
and `false`, `False`, `FALSE`, and `0`.

`RUN_ENCLAVES`: run the enclaves.

`RUN_SANDBOXES`: run the sandboxes.

### Domain size argument.

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

`RUN_NB_ITER`: change the default number of iterations
Must be a valid number parsed with `strtoul`

## Compilation

The `Makefile` creates a `mock_dom` to be used as the domain.
It contains two regions (TEXT and RO) by default, so 2 pages.
We generate a `mock_app` and use tychools to generate all the binaries to be loaded by the benchmark.
Note that when we add segments, we take care of computing real byte size, e.g., 1K = 1024 bytes and to remove the two pages that we have already.

:warning: We still need to configure some extra attributes in json to hash/cleanup regions.

Enclaves have their manifests in `manifests/enclaves/` and generate their binaries in `bin/enclaves/`.
Sandboxes have their manifests in `manifests/sandboxes` and generate their binaries in `bin/sandboxes`.

