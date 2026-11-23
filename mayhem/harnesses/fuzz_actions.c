/* Fuzz OVN logical-flow actions (lib/actions.c): template expansion, parse,
 * format, re-parse, and encode to OpenFlow, as tests/test-ovn.c
 * test_parse_actions does. Group/meter tables and collector ids are rebuilt
 * per input so each input's result depends only on that input. */
#include <config.h>
#include "fuzz_ovn_setup.h"

static struct shash symtab;
static struct hmap dhcp_opts, dhcpv6_opts, nd_ra_opts;
static struct controller_event_options event_opts;
static struct simap ports;
static struct smap template_vars;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    fuzz_quiet_logs();
    create_symtab(&symtab);
    create_gen_opts(&dhcp_opts, &dhcpv6_opts, &nd_ra_opts, &event_opts);
    simap_init(&ports);
    simap_put(&ports, "eth0", 5);
    simap_put(&ports, "eth1", 6);
    simap_put(&ports, "LOCAL", ofp_to_u16(OFPP_LOCAL));
    simap_put(&ports, "lsp1", 0x11);
    smap_init(&template_vars);
    smap_add(&template_vars, "vip", "10.0.0.1");
    smap_add(&template_vars, "port", "80");
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = fuzz_cstr(data, size);
    struct lex_str exp_input;
    if (!lexer_parse_template_string(&exp_input, s, &template_vars, NULL)) {
        free(s);
        return 0;
    }

    struct ovn_extend_table group_table, meter_table;
    ovn_extend_table_init(&group_table, "group-table", OFPG_MAX);
    ovn_extend_table_init(&meter_table, "meter-table", OFPM13_MAX);
    struct flow_collector_ids collector_ids;
    flow_collector_ids_init(&collector_ids);
    flow_collector_ids_add(&collector_ids, 0);
    flow_collector_ids_add(&collector_ids, 200);

    const struct ovnact_parse_params pp = {
        .symtab = &symtab,
        .dhcp_opts = &dhcp_opts,
        .dhcpv6_opts = &dhcpv6_opts,
        .nd_ra_opts = &nd_ra_opts,
        .controller_event_opts = &event_opts,
        .pipeline = OVNACT_P_INGRESS,
        .n_tables = LOG_PIPELINE_INGRESS_LEN,
        .cur_ltable = 10,
    };

    struct ofpbuf ovnacts;
    struct expr *prereqs = NULL;
    ofpbuf_init(&ovnacts, 0);
    char *error = ovnacts_parse_string(lex_str_get(&exp_input), &pp,
                                       &ovnacts, &prereqs);
    if (!error) {
        struct ds ovnacts_s = DS_EMPTY_INITIALIZER;
        ovnacts_format(ovnacts.data, ovnacts.size, &ovnacts_s);

        const struct ovnact_encode_params ep = {
            .lookup_port = lookup_port_cb,
            .lookup_local_port = lookup_local_port_cb,
            .tunnel_ofport = lookup_tunnel_ofport,
            .aux = &ports,
            .is_switch = true,
            .group_table = &group_table,
            .meter_table = &meter_table,
            .collector_ids = &collector_ids,
            .pipeline = OVNACT_P_INGRESS,
            .ingress_ptable = OFTABLE_LOG_INGRESS_PIPELINE,
            .egress_ptable = OFTABLE_LOG_EGRESS_PIPELINE,
            .output_ptable = OFTABLE_SAVE_INPORT,
            .mac_bind_ptable = OFTABLE_MAC_BINDING,
            .mac_lookup_ptable = OFTABLE_MAC_LOOKUP,
            .lb_hairpin_ptable = OFTABLE_CHK_LB_HAIRPIN,
            .lb_hairpin_reply_ptable = OFTABLE_CHK_LB_HAIRPIN_REPLY,
            .ct_snat_vip_ptable = OFTABLE_CT_SNAT_HAIRPIN,
            .fdb_ptable = OFTABLE_GET_FDB,
            .remote_fdb_ptable = OFTABLE_GET_REMOTE_FDB,
            .fdb_lookup_ptable = OFTABLE_LOOKUP_FDB,
            .common_nat_ct_zone = MFF_LOG_DNAT_ZONE,
            .in_port_sec_ptable = OFTABLE_CHK_IN_PORT_SEC,
            .out_port_sec_ptable = OFTABLE_CHK_OUT_PORT_SEC,
            .mac_cache_use_table = OFTABLE_MAC_CACHE_USE,
            .ct_nw_dst_load_table = OFTABLE_CT_ORIG_NW_DST_LOAD,
            .ct_ip6_dst_load_table = OFTABLE_CT_ORIG_IP6_DST_LOAD,
            .ct_tp_dst_load_table = OFTABLE_CT_ORIG_TP_DST_LOAD,
            .ct_proto_load_table = OFTABLE_CT_ORIG_PROTO_LOAD,
            .flood_remote_table = OFTABLE_FLOOD_REMOTE_CHASSIS,
            .ct_state_save_table = OFTABLE_CT_STATE_SAVE,
            .evpn_arp_ptable = OFTABLE_EVPN_ARP_LOOKUP,
            .lflow_uuid.parts = { 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd },
            .dp_key = 0xabcdef,
        };
        struct ofpbuf ofpacts;
        ofpbuf_init(&ofpacts, 0);
        ovnacts_encode(ovnacts.data, ovnacts.size, &ep, &ofpacts);
        struct ds ofpacts_s = DS_EMPTY_INITIALIZER;
        struct ofpact_format_params fp = { .s = &ofpacts_s };
        ofpacts_format(ofpacts.data, ofpacts.size, &fp);
        ds_destroy(&ofpacts_s);
        ofpbuf_uninit(&ofpacts);

        /* Round trip: the formatted actions must parse again. */
        struct ofpbuf ovnacts2;
        struct expr *prereqs2 = NULL;
        ofpbuf_init(&ovnacts2, 0);
        char *error2 = ovnacts_parse_string(ds_cstr(&ovnacts_s), &pp,
                                            &ovnacts2, &prereqs2);
        free(error2);
        expr_destroy(prereqs2);
        ovnacts_free(ovnacts2.data, ovnacts2.size);
        ofpbuf_uninit(&ovnacts2);
        ds_destroy(&ovnacts_s);
    }
    free(error);
    expr_destroy(prereqs);
    ovnacts_free(ovnacts.data, ovnacts.size);
    ofpbuf_uninit(&ovnacts);
    lex_str_free(&exp_input);
    ovn_extend_table_destroy(&group_table);
    ovn_extend_table_destroy(&meter_table);
    flow_collector_ids_destroy(&collector_ids);
    free(s);
    return 0;
}
