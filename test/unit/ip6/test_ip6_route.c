#include "test_ip6_route.h"

#include "lwip/ethip6.h"
#include "lwip/ip6.h"
#include "lwip/icmp6.h"
#include "lwip/inet_chksum.h"
#include "lwip/stats.h"
#include "lwip/prot/ethernet.h"
#include "lwip/prot/ip.h"
#include "lwip/prot/ip6.h"
#include "netif/ethernet.h"

#if LWIP_IPV6 /* allow to build the unit tests without IPv6 support */

#define IP6_PAYLOAD_LEN 0

static struct netif ap;
static struct netif sta;
static int ap_cnt = 0;
static int sta_cnt = 0;
static u8_t ap_output_p_type_internal = (PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS | PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP);
static u8_t sta_output_p_type_internal = (PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS | PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP);
unsigned char packet_buffer[sizeof(struct ip6_hdr) + IP6_PAYLOAD_LEN];

/* Setups/teardown functions */
static void
ip6route_setup(void)
{
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

static void
ip6route_teardown(void)
{
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

/* test helper functions */
static void debug_print_packet(struct pbuf *p)
{
    LWIP_UNUSED_ARG(p);
    ip6_debug_print(p);
}

static void
send_to_netif(struct netif *input_netif, struct pbuf *p)
{
  err_t err;

  if (p != NULL) {
    err = ip6_input(p, input_netif);
    EXPECT(err == ERR_OK);
  }
}

static err_t
ap_output(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr)
{
    fail_unless(p->type_internal == ap_output_p_type_internal);
    ap_cnt++;
    debug_print_packet(p);
    LWIP_UNUSED_ARG(netif);
    LWIP_UNUSED_ARG(p);
    LWIP_UNUSED_ARG(ipaddr);

    return ERR_OK;
}

static err_t
sta_output(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr)
{
    fail_unless(p->type_internal == sta_output_p_type_internal);
    sta_cnt++;
    debug_print_packet(p);
    LWIP_UNUSED_ARG(netif);
    LWIP_UNUSED_ARG(p);
    LWIP_UNUSED_ARG(ipaddr);

    return ERR_OK;
}

static err_t
sta_tx_func(struct netif *netif, struct pbuf *p)
{
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(p);
  return ERR_OK;
}

static err_t
ap_tx_func(struct netif *netif, struct pbuf *p)
{
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(p);
  return ERR_OK;
}

static err_t
testif_init_sta(struct netif *netif)
{
    netif->name[0] = 's';
    netif->name[1] = 't';
    netif->output_ip6 = sta_output;
    netif->linkoutput = sta_tx_func;
    netif->mtu = 1500;
    netif->hwaddr_len = 6;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_IGMP | NETIF_FLAG_MLD6 | NETIF_FLAG_LINK_UP;

    netif->hwaddr[0] = 0x02;
    netif->hwaddr[1] = 0x03;
    netif->hwaddr[2] = 0x04;
    netif->hwaddr[3] = 0x05;
    netif->hwaddr[4] = 0x06;
    netif->hwaddr[5] = 0x08;

    return ERR_OK;
}

static err_t
testif_init_ap(struct netif *netif)
{
  netif->name[0] = 'a';
  netif->name[1] = 'p';
  netif->output_ip6 = ap_output;
  netif->linkoutput = ap_tx_func;
  netif->mtu = 1500;
  netif->hwaddr_len = 6;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_IGMP | NETIF_FLAG_MLD6 | NETIF_FLAG_LINK_UP;

  netif->hwaddr[0] = 0x02;
  netif->hwaddr[1] = 0x03;
  netif->hwaddr[2] = 0x04;
  netif->hwaddr[3] = 0x05;
  netif->hwaddr[4] = 0x06;
  netif->hwaddr[5] = 0x07;

  return ERR_OK;
}

static struct pbuf *
test_ip6_create_test_packet(const ip6_addr_t *src_ip6, const ip6_addr_t *dst_ip6, pbuf_layer layer, pbuf_type type)
{
    struct pbuf *p = NULL;
    u16_t pbuf_len = (u16_t)(sizeof(struct ip6_hdr) + IP6_PAYLOAD_LEN);
    struct ip6_hdr *ip6hdr = NULL;

    if (type == PBUF_RAM) {
      p = pbuf_alloc(layer, pbuf_len, PBUF_RAM);
    } else if (type == PBUF_REF) {
        p = pbuf_alloc(layer, pbuf_len, PBUF_REF);
        p->payload = packet_buffer;
    }
    EXPECT_RETNULL(p != NULL);

    ip6hdr = (struct ip6_hdr *)p->payload;
    IP6H_VTCFL_SET(ip6hdr, 6, 0, 0);
    IP6H_PLEN_SET(ip6hdr, 0);
    IP6H_NEXTH_SET(ip6hdr, IP6_NEXTH_NONE);
    IP6H_HOPLIM_SET(ip6hdr, 64);
    ip6_addr_copy_to_packed(ip6hdr->src, *src_ip6);
    ip6_addr_copy_to_packed(ip6hdr->dest, *dst_ip6);

    return p;
}

/* Test functions */
static void test_ip6_route_netif_with_params(pbuf_layer layer, pbuf_type type)
{
    ip6_addr_t addr_link_sta, addr_link_ap, sta_addr, ap_addr;
    struct pbuf *p = NULL;
    s8_t chosen_idx = -1;

    /* setup station */
    netif_add(&sta, NULL, NULL, NULL, NULL, testif_init_sta, ethernet_input);
    ip6addr_aton("fdde:ad00:beef:cafe::1", &sta_addr);
    netif_add_ip6_address(&sta, &sta_addr, &chosen_idx);
    fail_unless(chosen_idx != -1);
    sta.ip6_addr_state[chosen_idx] = IP6_ADDR_VALID;
    netif_set_up(&sta);

    /* setup access point */
    netif_add(&ap, NULL, NULL, NULL, NULL, testif_init_ap, ethernet_input);
    ip6addr_aton("fdde:ad00:beef:abcd::1", &ap_addr);
    chosen_idx = -1;
    netif_add_ip6_address(&ap, &ap_addr, &chosen_idx);
    fail_unless(chosen_idx != -1);
    ap.ip6_addr_state[chosen_idx] = IP6_ADDR_VALID;
    netif_set_up(&ap);

    /* add addr */
    ip6addr_aton("fdde:ad00:beef:cafe::2", &addr_link_sta);
    ip6addr_aton("fdde:ad00:beef:abcd::2", &addr_link_ap);

    /* create packet and send it to the STA */
    p = test_ip6_create_test_packet(&addr_link_sta, &addr_link_ap, layer, type);
    send_to_netif(&sta, p);
    fail_unless(ap_cnt == 1);
    fail_unless(sta_cnt == 0);

    /* create packet and send it to the AP */
    p = test_ip6_create_test_packet(&addr_link_ap, &addr_link_sta, layer, type);
    send_to_netif(&ap, p);
    fail_unless(ap_cnt == 1);
    fail_unless(sta_cnt == 1);

    /* cleanup */
    ap_cnt = 0;
    sta_cnt = 0;
    netif_set_down(&ap);
    netif_remove(&ap);
    netif_set_down(&sta);
    netif_remove(&sta);
}

START_TEST(test_ip6_route_netif_forward_PBUF_RAM)
{
    test_ip6_route_netif_with_params(PBUF_RAW, PBUF_RAM);
}
END_TEST

START_TEST(test_ip6_route_netif_forward_PBUF_REF)
{
    test_ip6_route_netif_with_params(PBUF_RAW, PBUF_REF);
}
END_TEST

/** Create the suite including all tests for this module */
Suite *
ip6route_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_ip6_route_netif_forward_PBUF_RAM),
    TESTFUNC(test_ip6_route_netif_forward_PBUF_REF),
  };
  return create_suite("IP6_ROUTE", tests, sizeof(tests)/sizeof(testfunc), ip6route_setup, ip6route_teardown);
}
#endif /* LWIP_IPV6 */
