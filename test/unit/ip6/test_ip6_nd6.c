#include "test_ip6_nd6.h"

#include "lwip/ethip6.h"
#include "lwip/icmp6.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/prot/ip6.h"
#include "lwip/prot/nd6.h"
#include "lwip/tcpip.h"
#include "lwip/udp.h"
#include "netif/ethernet.h"

#if LWIP_IPV6 && LWIP_ND6

static struct netif host_netif;
static struct netif first_router_netif;
static struct netif second_router_netif;
static u8_t first_router_mac[6] = {1, 2, 3, 4, 5, 6};
static u8_t second_router_mac[6] = {1, 2, 3, 4, 5, 7};
static u8_t host_mac[6] = {1, 2, 3, 4, 5, 8};

/* Setups/teardown functions */
static void ip6nd6_setup(void) {
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static void ip6nd6_teardown(void) {
  if (netif_list->loop_first != NULL) {
    pbuf_free(netif_list->loop_first);
    netif_list->loop_first = NULL;
  }
  netif_list->loop_last = NULL;
  tcpip_thread_poll_one();
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static void nd6_handle_timer(u32_t count) {
  u32_t i;
  for (i = 0; i < count; i++) {
    nd6_tmr();
  }
}

static err_t host_tx_func(struct netif *netif, struct pbuf *p) {
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(p);
  return ERR_OK;
}

static err_t router_tx_func(struct netif *netif, struct pbuf *p) {
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(p);
  return ERR_OK;
}

static void send_to_netif(struct netif *input_netif, struct pbuf *p) {
  err_t err;

  if (p != NULL) {
    err = ip6_input(p, input_netif);
    fail_unless(err == ERR_OK);
  }
}

static struct pbuf *create_nd6_rio_test_packet(ip6_addr_t *dst_addr,
                                               ip6_addr_t *src_addr,
                                               ip6_addr_t *rio_prefix,
                                               u8_t rio_prefix_len,
                                               u32_t rio_lifetime,
                                               u8_t *mac_addr) {
  struct pbuf *p;
  struct ip6_hdr *ip6hdr;
  struct ra_header *ra_hdr;
  u8_t *ra_payload;
  u32_t route_lifetime;
  struct pbuf *icmp6_clone_pbuf = NULL;
  struct pbuf *icmp6_clone_pbuf_ori = NULL;

  p = pbuf_alloc(PBUF_IP,
                 sizeof(struct ip6_hdr) + sizeof(struct ra_header) + 32,
                 PBUF_RAM);
  fail_unless(p != NULL);
  if (p == NULL) {
    return NULL;
  }

  ip6hdr = (struct ip6_hdr *)p->payload;
  ip6hdr->_v_tc_fl = lwip_htonl((6 << 28) | (0));
  ip6hdr->_plen = lwip_htons(sizeof(struct ra_header) + 32);
  ip6hdr->_nexth = IP6_NEXTH_ICMP6;
  ip6hdr->_hoplim = 255;
  ip6_addr_copy_to_packed(ip6hdr->src, *src_addr);
  ip6_addr_copy_to_packed(ip6hdr->dest, *dst_addr);

  ra_hdr = (struct ra_header *)((u8_t *)ip6hdr + sizeof(struct ip6_hdr));
  ra_hdr->type = ICMP6_TYPE_RA;
  ra_hdr->code = 0;
  ra_hdr->chksum = 0;
  ra_hdr->current_hop_limit = 64;
  ra_hdr->flags = 0;
  ra_hdr->router_lifetime = 0;
  ra_hdr->reachable_time = 100;
  ra_hdr->retrans_timer = 0;

  ra_payload = (u8_t *)(ra_hdr + 1);

  /* Route information option */
  ra_payload[0] = ND6_OPTION_TYPE_ROUTE_INFO;
  ra_payload[1] = 3;
  ra_payload[2] = rio_prefix_len;
  ra_payload[3] = 0;

  route_lifetime = lwip_htonl(rio_lifetime);
  memcpy(&ra_payload[4], &route_lifetime, sizeof(route_lifetime));
  memcpy(&ra_payload[8], &rio_prefix->addr[0], 16);

  /* Add source link-layer address option to make neighbor reachable */
  ra_payload[24] = ND6_OPTION_TYPE_SOURCE_LLADDR;
  ra_payload[25] = 1;
  memcpy(&ra_payload[26], mac_addr, 6);

  icmp6_clone_pbuf = pbuf_clone(PBUF_IP, PBUF_RAM, p);
  fail_unless(icmp6_clone_pbuf != NULL);
  icmp6_clone_pbuf_ori = icmp6_clone_pbuf;
  pbuf_remove_header(icmp6_clone_pbuf, sizeof(struct ip6_hdr));
  ra_hdr->chksum =
      ip6_chksum_pseudo(icmp6_clone_pbuf, IP6_NEXTH_ICMP6,
                        icmp6_clone_pbuf->tot_len, src_addr, dst_addr);

  pbuf_free(icmp6_clone_pbuf_ori);
  return p;
}

static err_t testif_init_host(struct netif *netif) {
  netif->name[0] = 'h';
  netif->name[1] = 's';
  netif->output_ip6 = ethip6_output;
  netif->linkoutput = host_tx_func;
  netif->mtu = 1500;
  netif->hwaddr_len = ETH_HWADDR_LEN;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHERNET | NETIF_FLAG_MLD6;

  memcpy(netif->hwaddr, host_mac, 6);
  return ERR_OK;
}

static err_t testif_init_first_router(struct netif *netif) {
  netif->name[0] = 'f';
  netif->name[1] = 'r';
  netif->output_ip6 = ethip6_output;
  netif->linkoutput = router_tx_func;
  netif->mtu = 1500;
  netif->hwaddr_len = ETH_HWADDR_LEN;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHERNET | NETIF_FLAG_MLD6;

  memcpy(netif->hwaddr, first_router_mac, 6);
  return ERR_OK;
}

static err_t testif_init_second_router(struct netif *netif) {
  netif->name[0] = 's';
  netif->name[1] = 'r';
  netif->output_ip6 = ethip6_output;
  netif->linkoutput = router_tx_func;
  netif->mtu = 1500;
  netif->hwaddr_len = ETH_HWADDR_LEN;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHERNET | NETIF_FLAG_MLD6;

  memcpy(netif->hwaddr, second_router_mac, 6);
  return ERR_OK;
}

/* Test functions */
START_TEST(test_ip6_nd6_ra_rio) {
  struct pbuf *ra_rio_pbuf = NULL;
  err_t err = ERR_OK;
  const u8_t *hwaddr = NULL;
  struct netif *found_route = NULL;
  ip6_addr_t first_router_addr, second_router_addr, host_addr, dst_addr, rio_prefix, multicast_addr;
  s8_t chosen_idx = -1;

  netif_add(&first_router_netif, NULL, NULL, NULL, NULL, testif_init_first_router,
            ethernet_input);
  ip6addr_aton("fe80::ab00:beef:cafe:1", &first_router_addr);
  netif_add_ip6_address(&first_router_netif, &first_router_addr, &chosen_idx);
  fail_unless(chosen_idx != -1);
  first_router_netif.ip6_addr_state[chosen_idx] = IP6_ADDR_VALID;

  netif_add(&second_router_netif, NULL, NULL, NULL, NULL, testif_init_second_router,
            ethernet_input);
  ip6addr_aton("fe80::ab00:beef:cafe:2", &second_router_addr);
  chosen_idx = -1;
  netif_add_ip6_address(&second_router_netif, &second_router_addr, &chosen_idx);
  fail_unless(chosen_idx != -1);
  second_router_netif.ip6_addr_state[chosen_idx] = IP6_ADDR_VALID;

  netif_add(&host_netif, NULL, NULL, NULL, NULL, testif_init_host,
            ethernet_input);
  ip6addr_aton("fe80::ab00:beef:cafe:3", &host_addr);
  chosen_idx = -1;
  netif_add_ip6_address(&host_netif, &host_addr, &chosen_idx);
  fail_unless(chosen_idx != -1);
  host_netif.ip6_addr_state[chosen_idx] = IP6_ADDR_VALID;

  netif_set_up(&first_router_netif);
  netif_set_up(&second_router_netif);
  netif_set_up(&host_netif);

  ip6addr_aton("ff02::1", &multicast_addr);
  ip6addr_aton("fdde:ad00:abcd:beef:cafe::", &rio_prefix);
  ip6addr_aton("fdde:ad00:abcd:beef:cafe::1", &dst_addr);

  /* Check the route before receiving the ra_rio packet */
  found_route = nd6_find_route(&dst_addr);
  fail_unless(found_route == NULL);

  /* Send ra_rio packet */
  ra_rio_pbuf = create_nd6_rio_test_packet(&multicast_addr, &first_router_addr,
                                           &rio_prefix, 64, 3600, &first_router_mac[0]);
  fail_unless(ra_rio_pbuf != NULL);
  send_to_netif(&host_netif, ra_rio_pbuf);

  ra_rio_pbuf = create_nd6_rio_test_packet(&multicast_addr, &second_router_addr,
                                           &rio_prefix, 72, 1800, &second_router_mac[0]);
  fail_unless(ra_rio_pbuf != NULL);
  send_to_netif(&host_netif, ra_rio_pbuf);

  /* Check the route after receiving the ra_rio packets */
  found_route = nd6_find_route(&dst_addr);
  fail_unless(found_route == &host_netif);

  /* Check whether next hop is second router */
  err = nd6_get_next_hop_addr_or_queue(found_route, NULL, &dst_addr, &hwaddr);
  fail_unless(err == ERR_OK);
  fail_unless(hwaddr != NULL);
  fail_unless(memcmp(second_router_mac, hwaddr, 6) == 0);

  /* Make the second router invalid */
  nd6_handle_timer(1800);

  /* Check the route */
  found_route = nd6_find_route(&dst_addr);
  fail_unless(found_route == &host_netif);

  /* Check whether next hop is first router */
  err = nd6_get_next_hop_addr_or_queue(found_route, NULL, &dst_addr, &hwaddr);
  fail_unless(err == ERR_OK);
  fail_unless(hwaddr != NULL);
  fail_unless(memcmp(first_router_mac, hwaddr, 6) == 0);

  /* Make the first router invalid */
  nd6_handle_timer(1800);

  /* Check the route */
  found_route = nd6_find_route(&dst_addr);
  fail_unless(found_route == NULL);

  /* cleanup */
  netif_set_down(&first_router_netif);
  netif_remove(&first_router_netif);
  netif_set_down(&second_router_netif);
  netif_remove(&second_router_netif);
  netif_set_down(&host_netif);
  netif_remove(&host_netif);
  ra_rio_pbuf = NULL;
}
END_TEST

/** Create the suite including all tests for this module */
Suite *ip6_nd6_suite(void) {
  testfunc tests[] = {
      TESTFUNC(test_ip6_nd6_ra_rio),
  };
  return create_suite("IP6_ND6", tests, sizeof(tests) / sizeof(testfunc),
                      ip6nd6_setup, ip6nd6_teardown);
}
#endif /* LWIP_IPV6 && LWIP_ND6 */
