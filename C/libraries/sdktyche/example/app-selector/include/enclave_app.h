#ifndef __INCLUDE_ENCLAVE_APP_H__
#define __INCLUDE_ENCLAVE_APP_H__

/// Environment variable to select the application.
#define ENV_APP ("APP")

/// Transition benchmark loop bounds.
#define OUTER_LOOP_NB (10)
#define INNER_LOOP_NB (1000)

/// The different applications provided by this setup.
typedef enum {
  /// Estimate the transition cost.
  TRANSITION_BENCHMARK = 0,
  /// Print hello world and goodbye from the enclave.
  HELLO_WORLD = 1,
  /// Untrusted code attempts to access enclave memory.
  MALICIOUS = 2,
  /// Enclave triggers a breakpoint interrupt that should be handled by the untrusted code.
  BREAKPOINT = 3,
} application_e;

/// Names for the applications.
char* APP_NAMES[] = {
  "TRANSITION_BENCHMARK",
  "HELLO_WORLD",
  "MALICIOUS",
  "BREAKPOINT",
};

/// Configuration for the enclave.
/// This allows to select which example to run via shared memory.
typedef struct {
  /// The application to run.
  application_e app;
  /// arguments for this application.
  void* args;
} config_t;

/// Transition benchmark argument.
typedef struct {
  usize counter;
} transition_benchmark_t;

/// Hello world argument.
typedef struct {
  char reply[30];
} hello_world_t;

/// Malicious argument.
typedef hello_world_t malicious_t;

/// Breakpoint argument.
typedef hello_world_t breakpoint_t;

#endif
