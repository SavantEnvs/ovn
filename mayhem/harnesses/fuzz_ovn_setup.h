/* Symbol table, DHCP/ND option tables, address sets, port groups and port
 * lookup callbacks for the OVN lflow harnesses: copied verbatim from
 * tests/test-ovn.c (create_symtab .. is_chassis_resident_cb) so the harnesses
 * parse with the same environment as upstream's own tests. */
#ifndef FUZZ_OVN_SETUP_H
#define FUZZ_OVN_SETUP_H 1
#include "fuzz_common.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/shash.h"
#include "ovn/actions.h"
#include "ovn/expr.h"
#include "ovn/lex.h"
#include "ovn/logical-fields.h"
#include "lib/ovn-l7.h"
#include "lib/extend-table.h"
#include "lib/ovn-util.h"
#include "controller/lflow.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "util.h"

static void
create_symtab(struct shash *symtab)
{
    ovn_init_symtab(symtab);

    /* For negative testing. */
    expr_symtab_add_field(symtab, "bad_prereq", MFF_XREG0, "xyzzy", false);
    expr_symtab_add_field(symtab, "self_recurse", MFF_XREG0,
                          "self_recurse != 0", false);
    expr_symtab_add_field(symtab, "mutual_recurse_1", MFF_XREG0,
                          "mutual_recurse_2 != 0", false);
    expr_symtab_add_field(symtab, "mutual_recurse_2", MFF_XREG0,
                          "mutual_recurse_1 != 0", false);
    expr_symtab_add_string(symtab, "big_string", MFF_XREG0, NULL);
}

static void
create_gen_opts(struct hmap *dhcp_opts, struct hmap *dhcpv6_opts,
                struct hmap *nd_ra_opts,
                struct controller_event_options *event_opts)
{
    hmap_init(dhcp_opts);
    dhcp_opt_add(dhcp_opts, "offerip", 0, "ipv4");
    dhcp_opt_add(dhcp_opts, "netmask", 1, "ipv4");
    dhcp_opt_add(dhcp_opts, "router",  3, "ipv4");
    dhcp_opt_add(dhcp_opts, "dns_server", 6, "ipv4");
    dhcp_opt_add(dhcp_opts, "log_server", 7, "ipv4");
    dhcp_opt_add(dhcp_opts, "lpr_server",  9, "ipv4");
    dhcp_opt_add(dhcp_opts, "hostname", 12, "str");
    dhcp_opt_add(dhcp_opts, "domain_name", 15, "str");
    dhcp_opt_add(dhcp_opts, "swap_server", 16, "ipv4");
    dhcp_opt_add(dhcp_opts, "policy_filter", 21, "ipv4");
    dhcp_opt_add(dhcp_opts, "router_solicitation",  32, "ipv4");
    dhcp_opt_add(dhcp_opts, "nis_server", 41, "ipv4");
    dhcp_opt_add(dhcp_opts, "ntp_server", 42, "ipv4");
    dhcp_opt_add(dhcp_opts, "server_id",  54, "ipv4");
    dhcp_opt_add(dhcp_opts, "tftp_server", 66, "host_id");
    dhcp_opt_add(dhcp_opts, "classless_static_route", 121, "static_routes");
    dhcp_opt_add(dhcp_opts, "ip_forward_enable",  19, "bool");
    dhcp_opt_add(dhcp_opts, "router_discovery", 31, "bool");
    dhcp_opt_add(dhcp_opts, "ethernet_encap", 36, "bool");
    dhcp_opt_add(dhcp_opts, "default_ttl",  23, "uint8");
    dhcp_opt_add(dhcp_opts, "tcp_ttl", 37, "uint8");
    dhcp_opt_add(dhcp_opts, "mtu", 26, "uint16");
    dhcp_opt_add(dhcp_opts, "lease_time",  51, "uint32");
    dhcp_opt_add(dhcp_opts, "wpad", 252, "str");
    dhcp_opt_add(dhcp_opts, "bootfile_name", 67, "str");
    dhcp_opt_add(dhcp_opts, "path_prefix", 210, "str");
    dhcp_opt_add(dhcp_opts, "tftp_server_address", 150, "ipv4");
    dhcp_opt_add(dhcp_opts, "arp_cache_timeout", 35, "uint32");
    dhcp_opt_add(dhcp_opts, "tcp_keepalive_interval", 38, "uint32");
    dhcp_opt_add(dhcp_opts, "domain_search_list", 119, "domains");
    dhcp_opt_add(dhcp_opts, "bootfile_name_alt", 254, "str");
    dhcp_opt_add(dhcp_opts, "broadcast_address", 28, "ipv4");
    dhcp_opt_add(dhcp_opts, "netbios_name_server", 44, "ipv4");
    dhcp_opt_add(dhcp_opts, "netbios_node_type", 46, "uint8");
    dhcp_opt_add(dhcp_opts, "next_server", 253, "ipv4");

    /* DHCPv6 options. */
    hmap_init(dhcpv6_opts);
    dhcp_opt_add(dhcpv6_opts, "server_id",  2, "mac");
    dhcp_opt_add(dhcpv6_opts, "ia_addr",  5, "ipv6");
    dhcp_opt_add(dhcpv6_opts, "dns_server",  23, "ipv6");
    dhcp_opt_add(dhcpv6_opts, "domain_search",  24, "str");
    dhcp_opt_add(dhcpv6_opts, "bootfile_name", 59, "str");
    dhcp_opt_add(dhcpv6_opts, "bootfile_name_alt", 254, "str");
    dhcp_opt_add(dhcpv6_opts, "fqdn", 39, "domain");

    /* IPv6 ND RA options. */
    hmap_init(nd_ra_opts);
    nd_ra_opts_init(nd_ra_opts);

    /* OVN controller events options. */
    controller_event_opts_init(event_opts);
}

static void
create_addr_sets(struct shash *addr_sets)
{
    shash_init(addr_sets);

    static const char *const addrs1[] = {
        "10.0.0.1", "10.0.0.2", "10.0.0.3",
    };
    static const char *const addrs2[] = {
        "::1", "::2", "::3",
    };
    static const char *const addrs3[] = {
        "00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:03",
    };
    static const char *const addrs4[] = { NULL };

    expr_const_sets_add_integers(addr_sets, "set1", addrs1, 3);
    expr_const_sets_add_integers(addr_sets, "set2", addrs2, 3);
    expr_const_sets_add_integers(addr_sets, "set3", addrs3, 3);
    expr_const_sets_add_integers(addr_sets, "set4", addrs4, 0);
}

static void
create_port_groups(struct shash *port_groups)
{
    shash_init(port_groups);

    static const char *const pg1[] = {
        "lsp1", "lsp2", "lsp3",
    };
    static const char *const pg2[] = { NULL };

    expr_const_sets_add_strings(port_groups, "0_pg1", pg1, 3, NULL);
    expr_const_sets_add_strings(port_groups, "0_pg_empty", pg2, 0, NULL);
}

static bool
lookup_port_cb(const void *ports_, const char *port_name, unsigned int *portp)
{
    const struct simap *ports = ports_;
    const struct simap_node *node = simap_find(ports, port_name);
    if (!node) {
        return false;
    }
    *portp = node->data;
    return true;
}

static bool
lookup_local_port_cb(const void *ports_, const char *port_name)
{
    const struct simap *ports = ports_;
    return !!simap_find(ports, port_name);
}

static bool
lookup_tunnel_ofport(const void *ports_, const char *port_name,
                     ofp_port_t *ofport)
{
    const struct simap *ports = ports_;
    const struct simap_node *node = simap_find(ports, port_name);
    if (!node) {
        return false;
    }
    *ofport = (OVS_FORCE ofp_port_t ) node->data;
    return true;
}

static bool
is_chassis_resident_cb(const void *ports_, const char *port_name)
{
    const struct simap *ports = ports_;
    const struct simap_node *node = simap_find(ports, port_name);
    if (node) {
        return true;
    }
    return false;
}

#endif
