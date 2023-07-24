#ifndef __INCLUDE_SANDBOX_APP_H__
#define __INCLUDE_SANDBOX_APP_H__

/// Environment variable to select the application.
#define ENV_APP ("APP")

#define SHARED_BUFFER (0x300000)

/// The different applications provided by this setup.
typedef enum {
  /// Sandbox attempts to write to a readonly region.
  WRITE_RO = 0,
} application_e;

/// Names for the applications.
char* APP_NAMES[] = {
  "WRITE_RO",
};

/// Configuration for the enclave.
/// This allows to select which example to run via shared memory.
typedef struct {
  /// The application to run.
  application_e app;
  /// arguments for this application.
  void* args;
} config_t;

/// WRITE_RO argument.
typedef struct {
  char buffer[30];
} write_ro_t;

#endif
