/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RANDOM_H
#define _RANDOM_H

#include <stdlib.h>
#include <sys/random.h>

static inline void get_random_bytes(void *buf, int nbytes)
{
	getrandom(buf, nbytes, 0);
}

static inline u32 prandom_u32(void)
{
	return rand();
}

static inline int wait_for_random_bytes(void)
{
	return 0;
}

#endif
