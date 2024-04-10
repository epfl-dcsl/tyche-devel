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

`Boolean` accept `true`, `True`, `TRUE`, and `1` to enable them.
To disable them `false`, `False`, `FALSE`, and `0`

`Loop Bounds` arguments must be valid non-zero positive numbers.
They are parsed with `strtoul`.

`Domain Sizes` arguments must be in `[8k, 12k, 128k, 256k, 512k, 1M, 10M]`.


## Workloads

The available `Boolean` environment parameters are:

```
CREATION
TRANSITION
ATTESTATION
```

## Benchmarks

The available `Boolean` environment parameters are:

```
ENCLAVES
SANDBOXES
CARVES
```

## Configuration parameters

The algorithm ran by the selected benchmarks is influenced by parameters (see algorithms below).

The `Domain Sizes` parameters are:

```
MIN_SIZE
MAX_SIZE
```
`MIN_SIZE` must be smaller or equal to `MAX_SIZE`.
These two parameters select the range of domain sizes used by the relevant benchmark (creation and attestation).
The `Loop Bounds` parameters are:

```
INNER
OUTER
```

# Algorithms

All benchmarks run on all workloads selected:

```
/// Workloads are [ENCLAVES, SANDBOXES, CARVES]
/// Benchmarks are [CREATE, TRANSITION, ATTESTATION]
  for Bench <- Selected Benchmarks
    for Workload <- Selected Workloads
      Bench(Workload)
```

## Create/Delete

The main logic loop is as follows:

```
// For all the selected sizes such that:
// MIN_SIZE and MAX_SIZE in [8k, 12k, 128k, 256k, 512k, 1M, 10M]
// with MIN_SIZE <= MAX_SIZE

// Creation
for s <- [MIN_SIZE, MAX_SIZE]:
  for i <- [0, OUTER[:
    measure = {
      for j <- [0, INNER[:
        Create(S)
    };
    display(measure/INNER);

```


## Transitions

This benchmark reports transition numbers with the selected sdk and with raw vmcalls.
:warning: Raw vmcalls seem to pose a problem to KVM and got disabled.

```
/// 
for s <- [0, OUTER[:
  sdk_measure = {
    for i <- [0, INNER[:
      sdk_call(WORKLOAD/transition)
  };
  raw_measure = {
    for i <- [0, INNER[:
      raw_call(WORKLOAD/transition)
  };
  display(sdk_measure/INNER, raw_measure/INNER)
  
```

## Attestation


```
for d <- [MIN_SIZE, MAX_SIZE]:
  create(d)

for i <- [0, OUTER[:
  measure = {
    for j <- [0, INNER[:
      sizes[i] = attest()
  };
  display(measure.time/INNER, measure.size of attestation)
```

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
