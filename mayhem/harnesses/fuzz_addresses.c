/* Fuzz the NB/SB column-value parsers in lib/ovn-util.c and lib/lb.c:
 * logical switch port addresses, IP address lists, load-balancer keys and
 * load-balancer VIP/backend pairs (explicit and template forms).
 * Input: "<key>\0<value>" — the first NUL splits the LB key from its
 * backends; the key alone also feeds the address parsers. */
#include <config.h>
#include "fuzz_common.h"
#include "openvswitch/dynamic-string.h"
#include "lib/ovn-util.h"
#include "lib/lb.h"
#include <sys/socket.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    fuzz_quiet_logs();
    return 0;
}

static void
fuzz_vip(const char *key, const char *value, bool template, int af)
{
    struct ovn_lb_vip vip;
    memset(&vip, 0, sizeof vip);
    char *err = ovn_lb_vip_init(&vip, key, value, template, af);
    if (!err) {
        struct ds s = DS_EMPTY_INITIALIZER;
        ovn_lb_vip_format(&vip, &s, template);
        ovn_lb_vip_backends_format(&vip, &s);
        ds_destroy(&s);
    }
    free(err);
    ovn_lb_vip_destroy(&vip);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = fuzz_cstr(data, size);
    size_t klen = strlen(s);
    const char *key = s;
    const char *value = klen < size ? s + klen + 1 : "";

    struct lport_addresses la;
    if (extract_lsp_addresses(key, &la)) {
        destroy_lport_addresses(&la);
    }
    if (extract_ip_addresses(key, &la)) {
        destroy_lport_addresses(&la);
    }
    if (extract_ip_address(key, &la)) {
        destroy_lport_addresses(&la);
    }
    int ofs;
    if (extract_addresses(key, &la, &ofs)) {
        destroy_lport_addresses(&la);
    }

    char *ip = NULL;
    struct in6_addr ip6;
    uint16_t port;
    int af;
    if (ip_address_and_port_from_lb_key(key, &ip, &ip6, &port, &af)) {
        free(ip);
    }

    fuzz_vip(key, value, false, AF_INET);
    fuzz_vip(key, value, true, AF_INET);
    fuzz_vip(key, value, true, AF_INET6);
    free(s);
    return 0;
}
