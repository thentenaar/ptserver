/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef LOGGING_H
#define LOGGING_H

#include <time.h>

#ifndef NDEBUG
#define DEBUG(args) do {\
	error("%ld %s:%d [DEBUG] # ", time(NULL), __FILE__, __LINE__); \
	error args; \
	error("\n"); \
} while (0);
#else
#define DEBUG(args) do { ; } while(0);
#endif

#define INFO(args) do {\
	error("%ld %s:%d [\x1b[1;36mINFO\x1b[0m] # ", time(NULL), __FILE__, __LINE__); \
	error args; \
	error("\n"); \
} while (0);

#define WARN(args) do {\
	error("%ld %s:%d [\x1b[1;33mWARN\x1b[0m] # ", time(NULL), __FILE__, __LINE__); \
	error args; \
	error("\n"); \
} while (0);

#define ERROR(args) do {\
	error("%ld %s:%d [\x1b[1;31mERROR\x1b[0m] # ", time(NULL), __FILE__, __LINE__); \
	error args; \
	error("\n"); \
} while (0);

/**
 * Log a message to stderr
 */
void error(const char *fmt, ...);

#endif /* LOGGING_H */
