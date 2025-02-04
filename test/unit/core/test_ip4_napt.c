#include "test_ip4_napt.h"

#include "lwip/netif.h"
#include "netif/ethernet.h"
#include "lwip/lwip_napt.h"


#if IP_NAPT

/* Initialize a test network interface with standard ethernet settings */
static err_t
testif_init_netif(struct netif *netif)
{
  netif->name[0] = 's';
  netif->name[1] = 't';
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

/* Helper function to setup test network interfaces with given IP configuration */
static struct netif *setup_test_netifs(struct netif *netif_o, const char *addr_str, const char *netmask_str, const char *gw_str)
{
  ip4_addr_t addr, netmask, gw;
  struct netif *netif_p;

  memset(netif_o, 0, sizeof(struct netif));

  /* Setup network interface with given parameters */
  ip4addr_aton(addr_str, &addr);
  ip4addr_aton(netmask_str, &netmask);
  ip4addr_aton(gw_str, &gw);
  netif_p = netif_add(netif_o, &addr, &netmask, &gw, netif_o, testif_init_netif, ethernet_input);
  if (netif_p != NULL) {
    netif_set_up(netif_o);
  }

  return netif_p;
}

/* Test enabling NAPT on a valid IP address */
START_TEST(test_ip_napt_enable_enable_napt)
{
  struct netif netif1, netif2, *ret_netif;
  ip4_addr_t addr;

  /* Setup interfaces with proper gateway format */
  ret_netif = setup_test_netifs(&netif1, "192.168.1.1", "255.255.255.0", "192.168.1.1");
  fail_unless(ret_netif != NULL, "Failed to setup netif1");

  ret_netif = setup_test_netifs(&netif2, "1.2.4.4", "255.255.255.0", "1.2.4.10");  /* Fixed gateway IP format */
  fail_unless(ret_netif != NULL, "Failed to setup netif2");

  /* Test enabling NAPT for netif1's IP address */
  ip4addr_aton("192.168.1.1", &addr);
  ip_napt_enable(addr.addr, 1);

  fail_unless(netif1.napt == 1, "NAPT should be enabled for netif1");
  fail_unless(netif2.napt == 0, "NAPT should remain disabled for netif2");

  /* Cleanup in reverse order of creation */
  netif_remove(&netif2);
  netif_remove(&netif1);
}
END_TEST

/* Test that NAPT cannot be enabled on an invalid IP address (0.0.0.0) */
START_TEST(test_ip_napt_enable_enable_invalid_addr)
{
  struct netif netif1, *ret_netif;
  ip4_addr_t addr;

  ret_netif = setup_test_netifs(&netif1, "192.168.1.1", "255.255.255.0", "192.168.1.1");
  fail_unless(ret_netif != NULL, "Failed to setup netif1");

  /* Test valid enable then disable */
  ip4addr_aton("192.168.1.1", &addr);
  ip_napt_enable(addr.addr, 1);
  fail_unless(netif1.napt == 1, "Initial enable failed");

  /* Disable napt */
  ip_napt_enable(addr.addr, 0);
  fail_unless(netif1.napt == 0, "Disable failed");

  /* Test invalid enable attempt */
  ip4addr_aton("0.0.0.0", &addr);
  ip_napt_enable(addr.addr, 1);
  fail_unless(netif1.napt == 0, "NAPT enabled with invalid address");

  netif_remove(&netif1);
}
END_TEST

/* Test disabling NAPT on a specific IP address */
START_TEST(test_ip_napt_enable_disable_napt)
{
  struct netif netif1, netif2, *ret_netif;
  ip4_addr_t addr1, addr2;

  ret_netif = setup_test_netifs(&netif1, "192.168.1.1", "255.255.255.0", "192.168.1.1");
  fail_unless(ret_netif != NULL, "Failed to setup netif1");
  ret_netif = setup_test_netifs(&netif2, "1.2.4.4", "255.255.255.0", "1.2.4.10");  /* Fixed gateway IP format */
  fail_unless(ret_netif != NULL, "Failed to setup netif2");

  /* Initialize both to enabled state */
  ip4addr_aton("192.168.1.1", &addr1);
  ip4addr_aton("1.2.4.4", &addr2);
  ip_napt_enable(addr1.addr, 1);
  ip_napt_enable(addr2.addr, 1);

  /* Disable first interface */
  ip_napt_enable(addr1.addr, 0);
  fail_unless(netif1.napt == 0, "NAPT disable failed for netif1");
  fail_unless(netif2.napt == 1, "netif2 napt state changed unexpectedly");

  netif_remove(&netif2);
  netif_remove(&netif1);
}
END_TEST

/* Test enabling and disabling NAPT using interface number */
START_TEST(test_ip_napt_enable_no_enable_disable_napt)
{
  struct netif netif1, netif2, *ret_netif;

  ret_netif = setup_test_netifs(&netif1, "192.168.1.1", "255.255.255.0", "192.168.1.1");
  fail_unless(ret_netif != NULL, "Failed to setup netif1");
  ret_netif = setup_test_netifs(&netif2, "1.2.4.4", "255.255.255.0", "1.2.4.10");
  fail_unless(ret_netif != NULL, "Failed to setup netif2");

  /* Assign unique numbers */
  netif1.num = 1;
  netif2.num = 2;

  /* Test enable/disable by interface number */
  ip_napt_enable_no(1, 1);
  ip_napt_enable_no(2, 1);
  fail_unless(netif1.napt == 1 && netif2.napt == 1, "Enable by number failed");

  ip_napt_enable_no(1, 0);

  /* Verify the state changes */
  fail_unless(netif1.napt == 0, "Disable by number failed");
  fail_unless(netif2.napt == 1, "netif2 NAPT state changed unexpectedly");

  /* Clean up */
  netif_remove(&netif2);
  netif_remove(&netif1);
}
END_TEST

/* Test netif pointer based NAPT control */
START_TEST(test_ip_napt_enable_netif_enable_disable_napt)
{
  struct netif netif1, *ret_netif;
  int ret=0;

  ret_netif = setup_test_netifs(&netif1, "192.168.1.1", "255.255.255.0", "192.168.1.1");
  fail_unless(ret_netif != NULL, "Failed to setup netif1");

  fail_unless(netif1.napt == 0, "Default state should be disabled");

  ret = ip_napt_enable_netif(&netif1, 1);
  fail_unless(ret == 1, "NAPT enable returned error");
  fail_unless(netif1.napt == 1, "NAPT enable failed");

  ret = ip_napt_enable_netif(&netif1, 0);
  fail_unless(ret == 1, "NAPT disable returned error");
  fail_unless(netif1.napt == 0, "NAPT disable failed");

  netif_remove(&netif1);
}
END_TEST

/* Test independent interface NAPT control */
START_TEST(test_ip_napt_enable_netif_disable_napt_with_other_enabled)
{
  struct netif netif1, netif2, *ret_netif;
  int ret=0;

  ret_netif = setup_test_netifs(&netif1, "192.168.1.1", "255.255.255.0", "192.168.1.1");
  fail_unless(ret_netif != NULL, "Failed to setup netif1");
  ret_netif = setup_test_netifs(&netif2, "1.2.4.4", "255.255.255.0", "1.2.4.10");
  fail_unless(ret_netif != NULL, "Failed to setup netif2");

  ret = ip_napt_enable_netif(&netif1, 1);
  fail_unless(ret == 1, "NAPT enable returned error");
  ret = ip_napt_enable_netif(&netif2, 1);
  fail_unless(ret == 1, "NAPT enable returned error");

  /* Verify the napt is enabled */
  fail_unless(netif1.napt == 1, "NAPT disabled for netif1");
  fail_unless(netif2.napt == 1, "NAPT disabled for netif2");

  /* Disable NAPT for netif1 */
  ret = ip_napt_enable_netif(&netif1, 0);
  fail_unless(ret == 1, "NAPT disable returned error");

  /* Verify the state change */
  fail_unless(netif1.napt == 0, "NAPT not disabled for netif1");
  fail_unless(netif2.napt == 1, "NAPT state of netif2 changed unexpectedly");

  netif_remove(&netif2);
  netif_remove(&netif1);
}
END_TEST
#endif /* IP_NAPT */

/* Create test suite containing all NAPT enable/disable tests */
Suite *
ip4napt_suite(void)
{
  testfunc tests[] = {
#if IP_NAPT
    TESTFUNC(test_ip_napt_enable_enable_napt),
    TESTFUNC(test_ip_napt_enable_enable_invalid_addr),
    TESTFUNC(test_ip_napt_enable_disable_napt),
    TESTFUNC(test_ip_napt_enable_no_enable_disable_napt),
    TESTFUNC(test_ip_napt_enable_netif_enable_disable_napt),
    TESTFUNC(test_ip_napt_enable_netif_disable_napt_with_other_enabled),
#else
    TESTFUNC(NULL),
#endif
  };

  return create_suite("IP4_NAPT", tests, sizeof(tests)/sizeof(testfunc), NULL, NULL);
}
