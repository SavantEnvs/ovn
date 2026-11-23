/* Fuzz ovn-controller's pinctrl packet-in handling (controller/pinctrl.c).
 *
 * In production a tenant VM's packet hits a logical flow whose action punts
 * it to ovn-controller (put_dhcpv6_opts, put_dhcp_opts, dns_lookup, arp,
 * nd_na, icmp, put_nd_ra_opts, ...). ovs-vswitchd sends it as an
 * NXT_PACKET_IN2 whose userdata is the controller action's encoding, and
 * the pinctrl thread hands it to pinctrl_recv() -> process_packet_in().
 *
 * This harness builds that exact message: the userdata is produced by OVN's
 * own action encoder (ovnacts_parse_string + ovnacts_encode of the logical
 * action), the packet is the fuzz input, and the message goes to
 * pinctrl_recv() over a connected OpenFlow 1.5 rconn (a unix-socket pair, the
 * peer end drained after every input so replies do not accumulate).
 *
 * Covered packet-in opcodes: PUT_DHCPV6_OPTS, PUT_DHCP_OPTS, DNS_LOOKUP,
 * DHCP_RELAY_REQ/RESP_CHK, PUT_ND_RA_OPTS, ARP, ND_NA, ND_NA_ROUTER, ND_NS,
 * ICMP, ICMP4/6_ERROR, TCP_RESET, SCTP_ABORT, REJECT, LOG, IGMP (IGMP/MLD
 * snooping), PUT_ARP, PUT_ND, PUT_FDB, HANDLE_SVC_CHECK, DHCP6_SERVER, BFD_MSG
 * and PUT_ICMP4_INNER_IP4_SRC. The SB-derived state the IGMP, service-monitor
 * and BFD handlers look packets up in is seeded (seed_sb_state) and rebuilt
 * after every input.
 *
 * FUZZ_PINCTRL_DHCPV6: every input is a frame for put_dhcpv6_opts.
 * Otherwise: the first input byte selects the logical action, the rest is
 * the frame.
 *
 * pinctrl.c is included so its static entry point and state are reachable;
 * pinctrl_init() is not called because it starts the pinctrl thread — the
 * same init_*() calls are made here instead. */
#include <config.h>
#include "../../controller/pinctrl.c"

#include "fuzz_ovn_setup.h"
#include "openvswitch/vconn.h"
#include "stream.h"
#include "dirs.h"
#include <unistd.h>

static const char *const actions[] = {
    "reg1[0] = put_dhcpv6_opts(ia_addr = ae70::4, server_id = 00:00:00:00:10:02, "
    "dns_server = {ae70::1,ae89::2}, domain_search = \"ovn.org\", fqdn = \"ovn.org\", "
    "bootfile_name = \"https://127.0.0.1/boot.ipxe\");",
    "reg0[15] = put_dhcp_opts(offerip=10.0.0.4,router=10.0.0.1,netmask=255.255.255.0,"
    "mtu=1400,ip_forward_enable=1,default_ttl=121,dns_server={8.8.8.8,7.7.7.7},"
    "classless_static_route={30.0.0.0/24,10.0.0.4,40.0.0.0/16,10.0.0.6,0.0.0.0/0,10.0.0.1},"
    "domain_name=\"ovn.org\",domain_search_list=\"ovn.org,abc.ovn.org\",lease_time=3600,"
    "server_id=10.0.0.1,hostname=\"ip-10-0-0-4\");",
    "reg1[0] = dns_lookup();",
    "reg9[7] = dhcp_relay_req_chk(192.168.1.1, 172.16.1.1);",
    "reg9[8] = dhcp_relay_resp_chk(192.168.1.1, 172.16.1.1);",
    "reg1[0] = put_nd_ra_opts(addr_mode = \"slaac\", mtu = 1500, "
    "router_preference = \"HIGH\", prefix = aef0::/64, slla = ae:01:02:03:04:05);",
    "arp { eth.dst = ff:ff:ff:ff:ff:ff; output; };",
    "nd_na { eth.src = 12:34:56:78:9a:bc; nd.tll = 12:34:56:78:9a:bc; output; };",
    "nd_ns { nd.target = xxreg0; output; };",
    "icmp4 { eth.dst = ff:ff:ff:ff:ff:ff; output; };",
    "icmp6 { eth.dst = ff:ff:ff:ff:ff:ff; output; };",
    "tcp_reset { eth.dst = ff:ff:ff:ff:ff:ff; output; };",
    "sctp_abort { eth.dst = ff:ff:ff:ff:ff:ff; output; };",
    "log(name=\"test1\", verdict=drop, severity=info);",
    /* 14.. : appended so the selector byte of the existing seeds keeps
     * its meaning. */
    "igmp;",
    "put_arp(inport, arp.spa, arp.sha);",
    "put_nd(inport, nd.target, nd.tll);",
    "put_fdb(inport, eth.src);",
    "handle_svc_check(inport);",
    "reject { eth.dst = ff:ff:ff:ff:ff:ff; output; };",
    "icmp4_error { eth.dst = ff:ff:ff:ff:ff:ff; ip.ttl = 255; "
    "icmp4.type = 3; icmp4.code = 4; icmp4.frag_mtu = 1400; output; };",
    "icmp6_error { eth.dst = ff:ff:ff:ff:ff:ff; ip.ttl = 255; "
    "icmp6.type = 2; icmp6.code = 0; icmp6.frag_mtu = 1400; output; };",
    "reg0 = 0; handle_dhcpv6_reply;",
    "handle_bfd_msg();",
    "ip4.dst = 10.0.0.4; icmp4.inner_ip4.src = 10.0.0.4;",
    "nd_na_router { eth.src = 12:34:56:78:9a:bc; nd.tll = 12:34:56:78:9a:bc; output; };",
};
#define N_ACTIONS ARRAY_SIZE(actions)

/* ovn-northd only punts a packet with one of these actions from a logical
 * flow whose match restricts the packet (e.g. northd.c builds
 * put_dhcpv6_opts under "ip6.dst == ff02::1:2 && udp.src == 546 &&
 * udp.dst == 547", put_dhcp_opts under "ip4 && udp.src == 68 &&
 * udp.dst == 67", dns_lookup under "udp.dst == 53", put_nd_ra_opts under
 * "nd_rs", nd_na under "nd_ns"). The handlers rely on that match (e.g. they
 * dereference the L4 header), so a frame the flow could never match is
 * rejected (-1) rather than handed to them. */
static bool
frame_matches(size_t sel, const struct flow *f)
{
    bool ip4 = f->dl_type == htons(ETH_TYPE_IP);
    bool ip6 = f->dl_type == htons(ETH_TYPE_IPV6);
    bool udp = (ip4 || ip6) && f->nw_proto == IPPROTO_UDP;
    bool icmp6 = ip6 && f->nw_proto == IPPROTO_ICMPV6;
    switch (sel) {
    case 0: return ip6 && udp && f->tp_src == htons(546) && f->tp_dst == htons(547);
    case 1: return ip4 && udp && f->tp_src == htons(68) && f->tp_dst == htons(67);
    case 2: return udp && f->tp_dst == htons(53);
    case 3: return ip4 && udp && f->tp_dst == htons(67);
    case 4: return ip4 && udp && f->tp_src == htons(67) && f->tp_dst == htons(67);
    case 5: return icmp6 && f->tp_src == htons(ND_ROUTER_SOLICIT) && !f->tp_dst;
    case 6: return ip4;
    case 7: return icmp6 && f->tp_src == htons(ND_NEIGHBOR_SOLICIT) && !f->tp_dst;
    case 8: return ip6;
    case 9: return ip4;
    case 10: return ip6;
    case 11: return (ip4 || ip6) && f->nw_proto == IPPROTO_TCP;
    case 12: return (ip4 || ip6) && f->nw_proto == IPPROTO_SCTP;
    /* igmp: northd punts "igmp" (ip4 proto 2) and MLD ("mldv1 || mldv2",
     * ICMPv6 130-132/143). */
    case 14: return (ip4 && f->nw_proto == IPPROTO_IGMP)
                    || (icmp6 && (f->tp_src == htons(MLD_QUERY)
                                  || f->tp_src == htons(MLD_REPORT)
                                  || f->tp_src == htons(MLD_DONE)
                                  || f->tp_src == htons(MLD2_REPORT)));
    /* put_arp under "arp", put_nd under "nd_na" (northd.c
     * build_neigh_learning_flows_for_lrouter). */
    case 15: return f->dl_type == htons(ETH_TYPE_ARP);
    case 16: return icmp6 && f->tp_src == htons(ND_NEIGHBOR_ADVERT) && !f->tp_dst;
    case 17: return true;
    /* handle_svc_check under "eth.dst == $svc_monitor_mac &&
     * (tcp || icmp || icmp6)". */
    case 18: return (ip4 || ip6) && (f->nw_proto == IPPROTO_TCP
                                     || f->nw_proto == IPPROTO_ICMP
                                     || f->nw_proto == IPPROTO_ICMPV6);
    case 19: return ip4 || ip6;
    case 20: return ip4;
    case 21: return ip6;
    /* "ip6.dst == <lrp> && udp.src == 547 && udp.dst == 546". */
    case 22: return ip6 && udp && f->tp_src == htons(547) && f->tp_dst == htons(546);
    /* "ip4.dst == <ip> && udp.dst == 3784" (and ip6). */
    case 23: return udp && f->tp_dst == htons(3784);
    /* "... && icmp4 && icmp4.type == {3, 11, 12}" (northd.c, stateless
     * NAT ICMP helper). */
    case 24: return ip4 && f->nw_proto == IPPROTO_ICMP
                    && (f->tp_src == htons(3) || f->tp_src == htons(11)
                        || f->tp_src == htons(12));
    case 25: return icmp6 && f->tp_src == htons(ND_NEIGHBOR_SOLICIT) && !f->tp_dst;
    default: return true;
    }
}

static struct ofpbuf userdata[N_ACTIONS];
static struct rconn *swconn;
static struct vconn *peer;

/* State the main ovn-controller thread would load from the SB DB before any
 * of these packets could arrive: IGMP snooping enabled on datapath 1, a few
 * service monitors (LB TCP/UDP backends, ICMP probes) and BFD sessions on
 * logical port 1. The handlers mutate it (learned groups, monitor and BFD
 * state), so it is rebuilt after every input. Keys (shown in the seeds):
 *   svc: 10.0.0.10 tcp/80, 10.0.0.10 udp/53, 10.0.0.11 icmp,
 *        fd00::10 tcp/80, fd00::11 icmp; health-check tcp src port 40000,
 *        seq 1000.
 *   bfd: remote 10.0.0.20 / fd00::20, local discriminator 0x11223344. */
#define FUZZ_DP_KEY 1
#define FUZZ_PORT_KEY 1

static void
seed_svc_monitor(const char *ip_s, enum svc_monitor_protocol proto,
                 uint32_t port)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct in6_addr ip;
    ovs_be32 ip4;
    bool is_ip4 = ip_parse(ip_s, &ip4);
    if (is_ip4) {
        ip = in6_addr_mapped_ipv4(ip4);
    } else {
        ovs_assert(ipv6_parse(ip_s, &ip));
    }
    struct svc_monitor *svc_mon = xzalloc(sizeof *svc_mon);
    svc_mon->dp_key = FUZZ_DP_KEY;
    svc_mon->port_key = FUZZ_PORT_KEY;
    svc_mon->input_port_key = FUZZ_PORT_KEY;
    svc_mon->proto_port = port;
    svc_mon->ip = ip;
    svc_mon->is_ip6 = !is_ip4;
    svc_mon->state = SVC_MON_S_WAITING;
    svc_mon->status = SVC_MON_ST_UNKNOWN;
    svc_mon->protocol = proto;
    svc_mon->type = proto == SVC_MON_PROTO_ICMP ? SVC_MON_TYPE_LSP
                                                : SVC_MON_TYPE_LB;
    smap_init(&svc_mon->options);
    svc_mon->interval = 5000;
    svc_mon->svc_timeout = 3000;
    svc_mon->success_count = 1;
    svc_mon->failure_count = 1;
    svc_mon->seq_no = 1000;
    svc_mon->tp_src = htons(40000);
    svc_mon->icmp_id = htons(0x1234);
    svc_mon->icmp_seq_no = htons(1);
    svc_mon->ea = (struct eth_addr) ETH_ADDR_C(00,00,00,00,00,10);
    svc_mon->src_mac = (struct eth_addr) ETH_ADDR_C(00,00,00,00,00,01);
    svc_mon->src_ip = is_ip4 ? in6_addr_mapped_ipv4(htonl(0x0a000001))
                             : ip;
    uint32_t hash = hash_bytes(&ip, sizeof ip,
                               hash_3words(FUZZ_DP_KEY, FUZZ_PORT_KEY, port));
    hmap_insert(&svc_monitors_map, &svc_mon->hmap_node, hash);
    ovs_list_push_back(&svc_monitors, &svc_mon->list_node);
}

static void
seed_bfd_entry(const char *remote_ip)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct bfd_entry *entry = xzalloc(sizeof *entry);
    struct in6_addr ip;
    ovs_be32 ip4;
    if (ip_parse(remote_ip, &ip4)) {
        entry->ip_dst = in6_addr_mapped_ipv4(ip4);
        entry->ip_src = in6_addr_mapped_ipv4(htonl(0x0a000001));
    } else {
        ovs_assert(ipv6_parse(remote_ip, &ip));
        entry->ip_dst = ip;
        ovs_assert(ipv6_parse("fd00::1", &entry->ip_src));
    }
    entry->src_mac = (struct eth_addr) ETH_ADDR_C(00,00,00,00,00,01);
    entry->udp_src = 49152;
    entry->local_disc = htonl(0x11223344);
    long long int now = time_msec();
    entry->next_tx = now;
    entry->last_rx = now;
    entry->detection_timeout = 30000;
    entry->metadata = FUZZ_DP_KEY;
    entry->port_key = FUZZ_PORT_KEY;
    entry->state = BFD_STATE_DOWN;
    entry->local_min_tx = 1000;
    entry->local_min_rx = 1000;
    entry->remote_min_rx = 1;
    entry->local_mult = 3;
    hmap_insert(&bfd_monitor_map, &entry->node, hash_string(remote_ip, 0));
}

static void
seed_sb_state(void)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct ip_mcast_snoop_cfg cfg = {
        .enabled = true,
        .table_size = OVN_MCAST_DEFAULT_MAX_ENTRIES,
        .idle_time_s = OVN_MCAST_DEFAULT_IDLE_TIMEOUT_S,
        .query_interval_s = OVN_MCAST_DEFAULT_IDLE_TIMEOUT_S / 2,
        .query_max_resp_s = OVN_MCAST_DEFAULT_QUERY_MAX_RESPONSE_S,
    };
    ovs_assert(ip_mcast_snoop_add(FUZZ_DP_KEY, &cfg));

    seed_svc_monitor("10.0.0.10", SVC_MON_PROTO_TCP, 80);
    seed_svc_monitor("10.0.0.10", SVC_MON_PROTO_UDP, 53);
    seed_svc_monitor("10.0.0.11", SVC_MON_PROTO_ICMP, 0);
    seed_svc_monitor("fd00::10", SVC_MON_PROTO_TCP, 80);
    seed_svc_monitor("fd00::11", SVC_MON_PROTO_ICMP, 0);

    seed_bfd_entry("10.0.0.20");
    seed_bfd_entry("fd00::20");
}

static void
clear_sb_state(void)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct ip_mcast_snoop *ip_ms;
    HMAP_FOR_EACH_SAFE (ip_ms, hmap_node, &mcast_snoop_map) {
        ip_mcast_snoop_remove(ip_ms);
    }

    struct svc_monitor *svc;
    HMAP_FOR_EACH_POP (svc, hmap_node, &svc_monitors_map) {
    }
    LIST_FOR_EACH_POP (svc, list_node, &svc_monitors) {
        smap_destroy(&svc->options);
        free(svc);
    }

    struct bfd_entry *entry;
    HMAP_FOR_EACH_POP (entry, node, &bfd_monitor_map) {
        free(entry);
    }
    bfd_pending_update = 0;
}

static void
encode_userdata(const char *action, struct ofpbuf *out)
{
    struct shash symtab;
    struct hmap dhcp_opts, dhcpv6_opts, nd_ra_opts;
    struct controller_event_options event_opts;
    struct simap ports;

    create_symtab(&symtab);
    create_gen_opts(&dhcp_opts, &dhcpv6_opts, &nd_ra_opts, &event_opts);
    simap_init(&ports);
    simap_put(&ports, "eth0", 5);

    struct ovn_extend_table group_table, meter_table;
    ovn_extend_table_init(&group_table, "group-table", OFPG_MAX);
    ovn_extend_table_init(&meter_table, "meter-table", OFPM13_MAX);
    struct flow_collector_ids collector_ids;
    flow_collector_ids_init(&collector_ids);

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
    char *error = ovnacts_parse_string(action, &pp, &ovnacts, &prereqs);
    if (error) {
        fprintf(stderr, "fuzz_pinctrl: cannot parse \"%s\": %s\n", action, error);
        abort();
    }

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
        .dp_key = 1,
    };
    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);
    ovnacts_encode(ovnacts.data, ovnacts.size, &ep, &ofpacts);

    /* The packet-in userdata is the userdata of the (first) controller
     * action the logical action encodes to. */
    const struct ofpact *a;
    bool found = false;
    OFPACT_FOR_EACH (a, ofpacts.data, ofpacts.size) {
        if (a->type == OFPACT_CONTROLLER) {
            const struct ofpact_controller *oc = ofpact_get_CONTROLLER(a);
            ofpbuf_init(out, oc->userdata_len);
            ofpbuf_put(out, oc->userdata, oc->userdata_len);
            found = true;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "fuzz_pinctrl: \"%s\" has no controller action\n", action);
        abort();
    }
    ofpbuf_uninit(&ofpacts);
    expr_destroy(prereqs);
    ovnacts_free(ovnacts.data, ovnacts.size);
    ofpbuf_uninit(&ovnacts);
    ovn_extend_table_destroy(&group_table);
    ovn_extend_table_destroy(&meter_table);
    flow_collector_ids_destroy(&collector_ids);
    simap_destroy(&ports);
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
    dhcp_opts_destroy(&dhcp_opts);
    dhcp_opts_destroy(&dhcpv6_opts);
    nd_ra_opts_destroy(&nd_ra_opts);
    controller_event_opts_destroy(&event_opts);
}

/* Connects 'swconn' to a local peer over a unix socket so the rconn
 * negotiates OpenFlow 1.5, as it does with br-int. */
static void
connect_swconn(void)
{
    const char *tmp = getenv("TMPDIR");
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s/fuzz_pinctrl.XXXXXX", tmp && *tmp ? tmp : "/tmp");
    ovs_assert(mkdtemp(dir));
    char *punix = xasprintf("punix:%s/br-int.mgmt", dir);
    char *unix_ = xasprintf("unix:%s/br-int.mgmt", dir);
    uint32_t versions = 1u << OFP15_VERSION;

    struct pvconn *pvconn;
    ovs_assert(!pvconn_open(punix, versions, DSCP_DEFAULT, &pvconn));
    struct vconn *client;
    ovs_assert(!vconn_open(unix_, versions, DSCP_DEFAULT, &client));
    int error;
    do {
        error = pvconn_accept(pvconn, &peer);
    } while (error == EAGAIN);
    ovs_assert(!error);
    int e1, e2;
    do {
        e1 = vconn_connect(client);
        e2 = vconn_connect(peer);
    } while (e1 == EAGAIN || e2 == EAGAIN);
    ovs_assert(!e1 && !e2);
    pvconn_close(pvconn);

    swconn = rconn_create(0, 0, DSCP_DEFAULT, versions);
    rconn_connect_unreliably(swconn, client, NULL);
    rconn_run(swconn);
    ovs_assert(rconn_get_version(swconn) == OFP15_VERSION);
    /* The connected sockets no longer need the listening path: remove it
     * and its directory so nothing is left behind in $TMPDIR. */
    unlink(punix + strlen("punix:"));
    ovs_assert(!rmdir(dir));
    free(punix);
    free(unix_);
}

static void
drain_peer(void)
{
    rconn_run(swconn);
    struct ofpbuf *msg;
    while (!vconn_recv(peer, &msg)) {
        ofpbuf_delete(msg);
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    fuzz_quiet_logs();

    init_mac_bindings();
    init_send_arps_nds();
    init_ipv6_ras();
    init_ipv6_prefixd();
    init_buffered_packets_map();
    init_activated_ports();
    init_event_table();
    ip_mcast_snoop_init();
    init_put_vport_bindings();
    init_svc_monitors();
    bfd_monitor_init();
    init_fdb_entries();
    ovn_dns_cache_init();
    ovs_mutex_lock(&pinctrl_mutex);
    seed_sb_state();
    ovs_mutex_unlock(&pinctrl_mutex);
    pinctrl_handler_seq = seq_create();
    pinctrl_main_seq = seq_create();

    for (size_t i = 0; i < N_ACTIONS; i++) {
        encode_userdata(actions[i], &userdata[i]);
    }
    connect_swconn();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef FUZZ_PINCTRL_DHCPV6
    size_t sel = 0;
#else
    if (size < 1) {
        return -1;
    }
    size_t sel = data[0] % N_ACTIONS;
    data++;
    size--;
#endif
    /* Like the packet inside a decoded packet-in, the frame starts on an
     * aligned boundary (data + 1 above would not be). */
    uint8_t *frame = xmemdup(data, size);
    data = frame;

    struct dp_packet pkt;
    struct flow flow;
    dp_packet_use_const(&pkt, data, size);
    flow_extract(&pkt, &flow);
    if (!frame_matches(sel, &flow)) {
        free(frame);
        return -1;
    }

    struct ofputil_packet_in_private pin;
    memset(&pin, 0, sizeof pin);
    pin.base.packet = CONST_CAST(uint8_t *, data);
    pin.base.packet_len = size;
    pin.base.reason = OFPR_ACTION;
    pin.base.table_id = OFTABLE_LOG_INGRESS_PIPELINE + 10;
    pin.base.cookie = htonll(0x12345678);
    pin.base.userdata = userdata[sel].data;
    pin.base.userdata_len = userdata[sel].size;
    match_init_catchall(&pin.base.flow_metadata);
    match_set_in_port(&pin.base.flow_metadata, u16_to_ofp(5));
    match_set_metadata(&pin.base.flow_metadata, htonll(1));
    match_set_reg(&pin.base.flow_metadata, MFF_LOG_INPORT - MFF_REG0, 1);
    match_set_reg(&pin.base.flow_metadata, MFF_LOG_OUTPORT - MFF_REG0, 2);

    struct ofpbuf *msg = ofputil_encode_packet_in_private(
        &pin, OFPUTIL_P_OF15_OXM, OFPUTIL_PACKET_IN_NXT2);
    const struct ofp_header *oh = msg->data;
    enum ofptype type;
    if (!ofptype_decode(&type, oh)) {
        pinctrl_recv(swconn, oh, type);
    }
    ofpbuf_delete(msg);

    /* Per-input state: drop buffered packets, learned MAC/FDB bindings,
     * learned multicast groups and the service-monitor/BFD state the input
     * may have advanced, so the next input starts from the same state. */
    ovs_mutex_lock(&pinctrl_mutex);
    clear_sb_state();
    seed_sb_state();
    destroy_buffered_packets_map();
    init_buffered_packets_map();
    destroy_mac_bindings();
    init_mac_bindings();
    destroy_fdb_entries();
    init_fdb_entries();
    ovs_mutex_unlock(&pinctrl_mutex);
    drain_peer();
    free(frame);
    return 0;
}
