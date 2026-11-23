/* Shared setup for OVN lflow-language harnesses, modelled on tests/test-ovn.c. */
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H 1
#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "openvswitch/vlog.h"

/* Returns a NUL-terminated copy of the input (the parsers take C strings). */
static inline char *
fuzz_cstr(const uint8_t *data, size_t size)
{
    char *s = malloc(size + 1);
    memcpy(s, data, size);
    s[size] = '\0';
    return s;
}

static inline void
fuzz_quiet_logs(void)
{
    vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_OFF);
}
#endif
