/* Fuzz the OVN logical-flow lexer (lib/lex.c): tokenize, format, re-lex, and
 * expand templates, as tests/test-ovn.c test_lex does. */
#include <config.h>
#include "fuzz_common.h"
#include "openvswitch/dynamic-string.h"
#include "ovn/lex.h"
#include "smap.h"
#include "sset.h"

static struct smap template_vars;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    fuzz_quiet_logs();
    smap_init(&template_vars);
    smap_add(&template_vars, "vip", "10.0.0.1");
    smap_add(&template_vars, "port", "80");
    smap_add(&template_vars, "mac", "00:00:00:00:00:01");
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = fuzz_cstr(data, size);
    struct ds out = DS_EMPTY_INITIALIZER;
    struct lexer lexer;

    lexer_init(&lexer, s);
    while (lexer_get(&lexer) != LEX_T_END) {
        size_t len = out.length;
        lex_token_format(&lexer.token, &out);
        if (lexer.token.type != LEX_T_ERROR) {
            struct lexer l2;
            lexer_init(&l2, ds_cstr(&out) + len);
            lexer_get(&l2);
            lexer_destroy(&l2);
        }
        ds_put_char(&out, ' ');
    }
    lexer_destroy(&lexer);

    struct lex_str ls;
    struct sset refs = SSET_INITIALIZER(&refs);
    if (lexer_parse_template_string(&ls, s, &template_vars, &refs)) {
        lex_str_free(&ls);
    }
    sset_destroy(&refs);

    ds_destroy(&out);
    free(s);
    return 0;
}
