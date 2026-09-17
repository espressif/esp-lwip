#include <pthread.h>

#include "lwip_check.h"

#include "lwip/mem.h"
#include "lwip/opt.h"
#include "lwip/sockets.h"
#include "lwip/priv/sockets_priv.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/api.h"
#include "lwip/priv/tcpip_priv.h"

Suite *sockets_suite(void);

static int
test_sockets_get_used_count(void)
{
  int used = 0;
  int i;

  for (i = 0; i < NUM_SOCKETS; i++) {
    struct lwip_sock* s = lwip_socket_dbg_get_socket(i);
    if (s != NULL) {
      if (s->fd_used) {
        used++;
      }
    }
  }
  return used;
}

/* Must run on tcpip thread: abort leftover PCBs so the next test can bind :1234.
 * Use tcpip_api_call (available on 2.1.x); tcpip_callback_wait is newer only. */
static err_t
tcp_cleanup_pcbs(struct tcpip_api_call_data *call)
{
  LWIP_UNUSED_ARG(call);
  while (tcp_tw_pcbs != NULL) {
    tcp_abort(tcp_tw_pcbs);
  }
  while (tcp_active_pcbs != NULL) {
    tcp_abort(tcp_active_pcbs);
  }
  return ERR_OK;
}

/* Setups/teardown functions */
static void
sockets_setup(void)
{
  fail_unless(test_sockets_get_used_count() == 0);
}

static void
sockets_teardown(void)
{
  struct tcpip_api_call_data call;
  fail_unless(test_sockets_get_used_count() == 0);
  /* Previous closes can still be in FIN_WAIT/TIME_WAIT after sockets are gone.
   * Aborting from the app thread races the tcpip thread and misses PCBs that
   * enter TIME_WAIT after a non-blocking walk of tcp_tw_pcbs — bind(port) then flakes. */
  fail_unless(tcpip_api_call(tcp_cleanup_pcbs, &call) == ERR_OK);
}


struct test_params {
    int listener;
    size_t tx_buffer_size;
    struct linger so_linger;
};

static void *
server_thread(void *arg)
{
  struct test_params *params = (struct test_params *)arg;
  int srv;
  int err;
  int ret;
  struct sockaddr_storage source_addr;
  socklen_t addr_len = sizeof(source_addr);
  char rxbuf[16];

    /* accept the connection */
    srv = lwip_accept(params->listener, (struct sockaddr *)&source_addr, &addr_len);
    /* accepted, so won't need the listener socket anymore, close it */
    ret = lwip_close(params->listener);
    fail_unless(ret == 0);

#if LWIP_SO_LINGER
    /* if we linger with timeout=0, we might not be able to even accept */
    if (params->so_linger.l_onoff == 1 && params->so_linger.l_linger == 0 && srv < 0) {
        return NULL;
    }
    fail_unless(srv >= 0);
#endif


#if !LWIP_SO_LINGER
    /* check that we received exactly the amount of bytes that we sent */
    ret = lwip_recv(srv, rxbuf, params->tx_buffer_size, 0);
    err = errno;
    fail_unless(ret == (int)params->tx_buffer_size);
    /* check that we received exactly 0, i.e. EOF, connection closed cleanly */
    ret = lwip_recv(srv, rxbuf, sizeof(rxbuf), 0);
    err = errno;
    fail_unless(ret == 0);
    /* check that we could receive no longer */
    ret = lwip_recv(srv, rxbuf, sizeof(rxbuf), 0);
    err = errno;
    fail_unless(ret == -1);
    fail_unless(err == ENOTCONN || err == ECONNRESET);
#else
    /* try to receive (could be data or EOF if the client lingers on closing) */
    ret = lwip_recv(srv, rxbuf, sizeof(rxbuf), 0);
    err = errno;
    if (params->so_linger.l_onoff == 1 && params->so_linger.l_linger == 0 && ret < 0) {
        /* RST may arrive before any payload is readable */
        fail_unless(err == ENOTCONN || err == ECONNRESET);
        ret = lwip_close(srv);
        fail_unless(ret == 0);
        return NULL;
    }
    fail_unless(ret >= 0);

    if (params->so_linger.l_onoff == 1 && params->so_linger.l_linger > 0) {
        /* if lingering enabled with a non-zero timeout, let's just close
         * (connection could be closed both cleanly and abruptly) */
        ret = lwip_close(srv);
        fail_unless(ret == 0);
        return NULL;
    }
    /* otherwise, check that we could receive no longer */
    ret = lwip_recv(srv, rxbuf, sizeof(rxbuf), 0);
    err = errno;
    if (params->so_linger.l_onoff == 0) {
        /* lingering disabled: expect a clean FIN/EOF */
        fail_unless(ret == 0);
    } else {
        /* linger timeout=0: RST if unacked data remained at close(), else clean FIN
         * if the payload was already ACKed (timing-dependent on loopback). */
        fail_unless(ret == -1 || ret == 0);
        if (ret == -1) {
            fail_unless(err == ENOTCONN || err == ECONNRESET);
        }
    }
#endif
    /* close server socket */
    ret = lwip_close(srv);
    fail_unless(ret == 0);

    return NULL;
}

static void
test_socket_close_linger(int l_onoff, int l_linger)
{
    int client;
    int ret;
    struct sockaddr_in sa_listen;
    const u16_t port = 1234;
    static const char txbuf[] = "something";
    struct test_params params;
    int err;
    pthread_t srv_thread;

    /* set test parameters */
    params.so_linger.l_onoff = l_onoff;
    params.so_linger.l_linger = l_linger;
    params.tx_buffer_size = sizeof(txbuf);

    fail_unless(test_sockets_get_used_count() == 0);
    /* set up the listener */
    memset(&sa_listen, 0, sizeof(sa_listen));
    sa_listen.sin_family = AF_INET;
    sa_listen.sin_port = PP_HTONS(port);
    sa_listen.sin_addr.s_addr = PP_HTONL(INADDR_LOOPBACK);
    params.listener = lwip_socket(AF_INET, SOCK_STREAM, 0);
    fail_unless(params.listener >= 0);
#if SO_REUSE
    ret = 1;
    fail_unless(setsockopt(params.listener, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret)) == 0);
#endif
    ret = lwip_bind(params.listener, (struct sockaddr *)&sa_listen, sizeof(sa_listen));
    fail_unless(ret == 0);
    ret = lwip_listen(params.listener, 1);
    fail_unless(ret == 0);

    /* continue to serve connections in a separate thread*/
    err = pthread_create(&srv_thread, NULL, server_thread, &params);
    fail_unless(err == 0);

    /* set up the client */
    client = lwip_socket(AF_INET, SOCK_STREAM, 0);

    /* connect */
    ret = lwip_connect(client, (struct sockaddr *) &sa_listen, sizeof(sa_listen));
    fail_unless(ret == 0);

    /* set socket to enable SO_LINGER option */
    ret = lwip_setsockopt(client, SOL_SOCKET, SO_LINGER, &params.so_linger, sizeof(params.so_linger));
#if LWIP_SO_LINGER
    fail_unless(ret == 0);
#else
    /* If not enabled, just expect No Such Option error */
    err = errno;
    fail_unless(ret == -1);
    fail_unless(err == ENOPROTOOPT);
#endif /* LWIP_SO_LINGER */

    ret = lwip_send(client, txbuf, sizeof(txbuf), 0);
    fail_unless(ret == sizeof(txbuf));

    /* close from client's side */
    ret = lwip_close(client);
#if !LWIP_SO_LINGER
    err = errno;
    fail_unless(ret == 0);
#endif

    pthread_join(srv_thread, NULL);
}

START_TEST(test_sockets_close_state_machine_linger_off)
{
    LWIP_UNUSED_ARG(_i);
    test_socket_close_linger(0, 0);
}
END_TEST

START_TEST(test_sockets_close_state_machine_linger_on)
    {
        LWIP_UNUSED_ARG(_i);
        test_socket_close_linger(1, 1);
    }
END_TEST

START_TEST(test_sockets_close_state_machine_linger_on_timeout_0)
{
    LWIP_UNUSED_ARG(_i);
    test_socket_close_linger(1, 0);
}
END_TEST

/** Create the suite including all tests for this module */
Suite *
sockets_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_sockets_close_state_machine_linger_off),
    TESTFUNC(test_sockets_close_state_machine_linger_on),
    TESTFUNC(test_sockets_close_state_machine_linger_on_timeout_0),
  };
  return create_suite("SOCKETS", tests, sizeof(tests)/sizeof(testfunc), sockets_setup, sockets_teardown);
}
