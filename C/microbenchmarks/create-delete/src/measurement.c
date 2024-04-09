#include <assert.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdbool.h>

#include "measurement.h"

inline bool take_time(time_measurement_t * measure) {
	if (gettimeofday(measure, NULL) < 0) {
		return false;
	}
	return true;
}

inline time_diff_t compute_elapsed(time_measurement_t* start, time_measurement_t* end) {
	assert(start != NULL && end != NULL);
	return ((end->tv_sec - start->tv_sec) * 1000000L) +
		(end->tv_usec - start->tv_usec);
} 
