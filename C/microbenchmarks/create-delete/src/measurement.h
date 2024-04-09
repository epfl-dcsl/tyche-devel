#pragma once

#include <sys/time.h>

// ———————————————————————————————— Defines ————————————————————————————————— //
#define TIME_MEASUREMENT_UNIT ("us")

// ————————————————————————————————— Types —————————————————————————————————— //
/// Alias the name of a time measurement so we can easily change it.
typedef struct timeval time_measurement_t;

/// The difference between two time measurements
typedef double time_diff_t;

// —————————————————————————————————— API ——————————————————————————————————— //

/// Take a timestamp. Returns true on success, false on failure.
bool take_time(time_measurement_t* measure);
/// Compute the difference between two time measurements.
time_diff_t compute_elapsed(time_measurement_t* start, time_measurement_t* end);
