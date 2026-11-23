/* Fuzz OVN match expressions (lib/expr.c): parse, annotate, simplify,
 * evaluate, normalize and convert to OpenFlow matches, the full pipeline of
 * tests/test-ovn.c "expr-to-flows" (test_parse_expr__(4)). */
#include <config.h>
#include "fuzz_ovn_setup.h"

static struct shash symtab, addr_sets, port_groups;
static struct simap ports;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    fuzz_quiet_logs();
    create_symtab(&symtab);
    create_addr_sets(&addr_sets);
    create_port_groups(&port_groups);
    simap_init(&ports);
    simap_put(&ports, "eth0", 5);
    simap_put(&ports, "eth1", 6);
    simap_put(&ports, "LOCAL", ofp_to_u16(OFPP_LOCAL));
    simap_put(&ports, "lsp1", 0x11);
    simap_put(&ports, "lsp2", 0x12);
    simap_put(&ports, "lsp3", 0x13);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = fuzz_cstr(data, size);
    char *error = NULL;
    struct expr *expr = expr_parse_string(s, &symtab, &addr_sets,
                                          &port_groups, NULL, NULL, 0,
                                          &error);
    if (!error) {
        struct ds out = DS_EMPTY_INITIALIZER;
        expr_format(expr, &out);
        ds_destroy(&out);
        expr = expr_annotate(expr, &symtab, &error);
    }
    if (!error) {
        expr = expr_simplify(expr);
        expr = expr_evaluate_condition(expr, is_chassis_resident_cb, &ports);
        expr = expr_normalize(expr);
        ovs_assert(expr_is_normalized(expr));

        struct hmap matches;
        expr_to_matches(expr, lookup_port_cb, &ports, &matches);
        expr_matches_destroy(&matches);
    }
    free(error);
    expr_destroy(expr);
    free(s);
    return 0;
}
