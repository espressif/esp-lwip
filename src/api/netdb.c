/**
 * @file
 * API functions for name resolving
 *
 * @defgroup netdbapi NETDB API
 * @ingroup socket
 */

/*
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Simon Goldschmidt
 *
 */

#include "lwip/netdb.h"

#if LWIP_DNS && LWIP_SOCKET

#include "lwip/err.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/ip6_addr.h"
#include "lwip/api.h"
#include "lwip/dns.h"

#include <string.h> /* memset */
#include <stdlib.h> /* atoi */

/** helper struct for gethostbyname_r to access the char* buffer */
struct gethostbyname_r_helper {
  ip_addr_t *addr_list[2];
  ip_addr_t addr;
  char *aliases;
};

/** h_errno is exported in netdb.h for access by applications. */
#if LWIP_DNS_API_DECLARE_H_ERRNO
int h_errno;
#endif /* LWIP_DNS_API_DECLARE_H_ERRNO */

/** define "hostent" variables storage: 0 if we use a static (but unprotected)
 * set of variables for lwip_gethostbyname, 1 if we use a local storage */
#ifndef LWIP_DNS_API_HOSTENT_STORAGE
#define LWIP_DNS_API_HOSTENT_STORAGE 0
#endif

/** define "hostent" variables storage */
#if LWIP_DNS_API_HOSTENT_STORAGE
#define HOSTENT_STORAGE
#else
#define HOSTENT_STORAGE static
#endif /* LWIP_DNS_API_STATIC_HOSTENT */

#if LWIP_IPV4 && LWIP_IPV6 && LWIP_DNS_DYNAMIC_SORT
ip6_addr_t * dns_select_destination_address(ip6_addr_t *cand_list[], const int cand_list_length);
u8_t dns_addr_get_scope(const ip6_addr_t *addr);
u8_t dns_precedence_for_label(u8_t label);
u8_t dns_get_precedence_label(const ip6_addr_t *addr);
#endif

/**
 * Returns an entry containing addresses of address family AF_INET
 * for the host with name name.
 * Due to dns_gethostbyname limitations, only one address is returned.
 *
 * @param name the hostname to resolve
 * @return an entry containing addresses of address family AF_INET
 *         for the host with name name
 */
struct hostent *
lwip_gethostbyname(const char *name)
{
  err_t err;
  ip_addr_t addr;

  /* buffer variables for lwip_gethostbyname() */
  HOSTENT_STORAGE struct hostent s_hostent;
  HOSTENT_STORAGE char *s_aliases;
  HOSTENT_STORAGE ip_addr_t s_hostent_addr;
  HOSTENT_STORAGE ip_addr_t *s_phostent_addr[2];
  HOSTENT_STORAGE char s_hostname[DNS_MAX_NAME_LENGTH + 1];

  /* query host IP address */
  err = netconn_gethostbyname(name, &addr);
  if (err != ERR_OK) {
    LWIP_DEBUGF(DNS_DEBUG, ("lwip_gethostbyname(%s) failed, err=%d\n", name, err));
    h_errno = HOST_NOT_FOUND;
    return NULL;
  }

  /* fill hostent */
  s_hostent_addr = addr;
  s_phostent_addr[0] = &s_hostent_addr;
  s_phostent_addr[1] = NULL;
  strncpy(s_hostname, name, DNS_MAX_NAME_LENGTH);
  s_hostname[DNS_MAX_NAME_LENGTH] = 0;
  s_hostent.h_name = s_hostname;
  s_aliases = NULL;
  s_hostent.h_aliases = &s_aliases;
  s_hostent.h_addrtype = (IPADDR_TYPE_V4 == IP_GET_TYPE(&addr)? AF_INET : AF_INET6);
  s_hostent.h_length = IP_ADDR_RAW_SIZE(addr);
  s_hostent.h_addr_list = (char **)&s_phostent_addr;

#if DNS_DEBUG
  /* dump hostent */
  LWIP_DEBUGF(DNS_DEBUG, ("hostent.h_name           == %s\n", s_hostent.h_name));
  LWIP_DEBUGF(DNS_DEBUG, ("hostent.h_aliases        == %p\n", (void *)s_hostent.h_aliases));
  /* h_aliases are always empty */
  LWIP_DEBUGF(DNS_DEBUG, ("hostent.h_addrtype       == %d\n", s_hostent.h_addrtype));
  LWIP_DEBUGF(DNS_DEBUG, ("hostent.h_length         == %d\n", s_hostent.h_length));
  LWIP_DEBUGF(DNS_DEBUG, ("hostent.h_addr_list      == %p\n", (void *)s_hostent.h_addr_list));
  if (s_hostent.h_addr_list != NULL) {
    u8_t idx;
    for (idx = 0; s_hostent.h_addr_list[idx]; idx++) {
      LWIP_DEBUGF(DNS_DEBUG, ("hostent.h_addr_list[%i]-> == %s\n", idx, ipaddr_ntoa(s_phostent_addr[idx])));
    }
  }
#endif /* DNS_DEBUG */

#if LWIP_DNS_API_HOSTENT_STORAGE
  /* this function should return the "per-thread" hostent after copy from s_hostent */
  return sys_thread_hostent(&s_hostent);
#else
  return &s_hostent;
#endif /* LWIP_DNS_API_HOSTENT_STORAGE */
}

/**
 * Thread-safe variant of lwip_gethostbyname: instead of using a static
 * buffer, this function takes buffer and errno pointers as arguments
 * and uses these for the result.
 *
 * @param name the hostname to resolve
 * @param ret pre-allocated struct where to store the result
 * @param buf pre-allocated buffer where to store additional data
 * @param buflen the size of buf
 * @param result pointer to a hostent pointer that is set to ret on success
 *               and set to zero on error
 * @param h_errnop pointer to an int where to store errors (instead of modifying
 *                 the global h_errno)
 * @return 0 on success, non-zero on error, additional error information
 *         is stored in *h_errnop instead of h_errno to be thread-safe
 */
int
lwip_gethostbyname_r(const char *name, struct hostent *ret, char *buf,
                     size_t buflen, struct hostent **result, int *h_errnop)
{
  err_t err;
  struct gethostbyname_r_helper *h;
  char *hostname;
  size_t namelen;
  int lh_errno;

  if (h_errnop == NULL) {
    /* ensure h_errnop is never NULL */
    h_errnop = &lh_errno;
  }

  if (result == NULL) {
    /* not all arguments given */
    *h_errnop = EINVAL;
    return -1;
  }
  /* first thing to do: set *result to nothing */
  *result = NULL;
  if ((name == NULL) || (ret == NULL) || (buf == NULL)) {
    /* not all arguments given */
    *h_errnop = EINVAL;
    return -1;
  }

  namelen = strlen(name);
  if (buflen < (sizeof(struct gethostbyname_r_helper) + LWIP_MEM_ALIGN_BUFFER(namelen + 1))) {
    /* buf can't hold the data needed + a copy of name */
    *h_errnop = ERANGE;
    return -1;
  }

  h = (struct gethostbyname_r_helper *)LWIP_MEM_ALIGN(buf);
  hostname = ((char *)h) + sizeof(struct gethostbyname_r_helper);

  /* query host IP address */
  err = netconn_gethostbyname(name, &h->addr);
  if (err != ERR_OK) {
    LWIP_DEBUGF(DNS_DEBUG, ("lwip_gethostbyname(%s) failed, err=%d\n", name, err));
    *h_errnop = HOST_NOT_FOUND;
    return -1;
  }

  /* copy the hostname into buf */
  MEMCPY(hostname, name, namelen);
  hostname[namelen] = 0;

  /* fill hostent */
  h->addr_list[0] = &h->addr;
  h->addr_list[1] = NULL;
  h->aliases = NULL;
  ret->h_name = hostname;
  ret->h_aliases = &h->aliases;
  ret->h_addrtype = (IPADDR_TYPE_V4 == IP_GET_TYPE(&h->addr)? AF_INET : AF_INET6);
  ret->h_length = IP_ADDR_RAW_SIZE(h->addr);
  ret->h_addr_list = (char **)&h->addr_list;

  /* set result != NULL */
  *result = ret;

  /* return success */
  return 0;
}

/**
 * Frees one or more addrinfo structures returned by getaddrinfo(), along with
 * any additional storage associated with those structures. If the ai_next field
 * of the structure is not null, the entire list of structures is freed.
 *
 * @param ai struct addrinfo to free
 */
void
lwip_freeaddrinfo(struct addrinfo *ai)
{
  struct addrinfo *next;

  while (ai != NULL) {
    next = ai->ai_next;
    memp_free(MEMP_NETDB, ai);
    ai = next;
  }
}

/**
 * Translates the name of a service location (for example, a host name) and/or
 * a service name and returns a set of socket addresses and associated
 * information to be used in creating a socket with which to address the
 * specified service.
 * Memory for the result is allocated internally and must be freed by calling
 * lwip_freeaddrinfo()!
 *
 * Due to a limitation in dns_gethostbyname, only the first address of a
 * host is returned.
 * Also, service names are not supported (only port numbers)!
 *
 * @param nodename descriptive name or address string of the host
 *                 (may be NULL -> local address)
 * @param servname port number as string of NULL
 * @param hints structure containing input values that set socktype and protocol
 * @param res pointer to a pointer where to store the result (set to NULL on failure)
 * @return 0 on success, non-zero on failure
 *
 * @todo: implement AI_V4MAPPED, AI_ADDRCONFIG
 */
int
lwip_getaddrinfo(const char *nodename, const char *servname,
                 const struct addrinfo *hints, struct addrinfo **res)
{
  err_t err;
  ip_addr_t addr;
  struct addrinfo *ai;
  struct sockaddr_storage *sa = NULL;
  int port_nr = 0;
  size_t total_size;
  size_t namelen = 0;
  int ai_family;

  if (res == NULL) {
    return EAI_FAIL;
  }
  *res = NULL;
  if ((nodename == NULL) && (servname == NULL)) {
    return EAI_NONAME;
  }

  if (hints != NULL) {
    ai_family = hints->ai_family;
    if ((ai_family != AF_UNSPEC)
#if LWIP_IPV4
        && (ai_family != AF_INET)
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
        && (ai_family != AF_INET6)
#endif /* LWIP_IPV6 */
       ) {
      return EAI_FAMILY;
    }
  } else {
    ai_family = AF_UNSPEC;
  }

  if (servname != NULL) {
    /* service name specified: convert to port number
     * @todo?: currently, only ASCII integers (port numbers) are supported (AI_NUMERICSERV)! */
    port_nr = atoi(servname);
    if (port_nr == 0 && (servname[0] != '0')) {
      /* atoi failed - service was not numeric */
      return EAI_SERVICE;
    }
    if ((port_nr < 0) || (port_nr > 0xffff)) {
      return EAI_SERVICE;
    }
  }

  if (nodename != NULL) {
    /* service location specified, try to resolve */
    if ((hints != NULL) && (hints->ai_flags & AI_NUMERICHOST)) {
      /* no DNS lookup, just parse for an address string */
      if (!ipaddr_aton(nodename, &addr)) {
        return EAI_NONAME;
      }
#if LWIP_IPV4 && LWIP_IPV6
      if ((IP_IS_V6_VAL(addr) && ai_family == AF_INET) ||
          (IP_IS_V4_VAL(addr) && ai_family == AF_INET6)) {
        return EAI_NONAME;
      }
#endif /* LWIP_IPV4 && LWIP_IPV6 */
    } else {
#if LWIP_IPV4 && LWIP_IPV6
      if (ai_family == AF_UNSPEC) {
#if LWIP_DNS_DYNAMIC_SORT
        ip_addr_t addr4;
        ip_addr_t addr6;
        ip6_addr_t *addr_list[2];
        int index = 0;
        err_t err6 = netconn_gethostbyname_addrtype(nodename, &addr6, NETCONN_DNS_IPV6);
        if (err6 == ERR_OK) {
          addr_list[index] = ip_2_ip6(&addr6);
          index++;
        }
        err_t err4 = netconn_gethostbyname_addrtype(nodename, &addr4, NETCONN_DNS_IPV4);
        if (err4 == ERR_OK) {
          /* Convert native V4 address to a V4-mapped IPV6 address */
          ip4_2_ipv4_mapped_ipv6(ip_2_ip6(&addr4), ip_2_ip4(&addr4));
          IP_SET_TYPE_VAL(addr4, IPADDR_TYPE_V6);
          addr_list[index] = ip_2_ip6(&addr4);
          index++;
        }
        err = err6 == ERR_OK || err4 == ERR_OK ? ERR_OK : EAI_FAIL;
        if (err != ERR_OK) {
          return EAI_FAIL;
        }
        ip6_addr_t *best_addr = dns_select_destination_address(addr_list, index);
        if (ip6_addr_isipv4mappedipv6(best_addr)) {
          unmap_ipv4_mapped_ipv6(ip_2_ip4(&addr), best_addr);
        } else {
          ip_addr_copy_from_ip6(addr, *best_addr);
        }
#else /* LWIP_DNS_DYNAMIC_SORT */
        err = netconn_gethostbyname_addrtype(nodename, &addr, NETCONN_DNS_IPV4_IPV6);
#endif /* LWIP_DNS_DYNAMIC_SORT */
      } else {
        u8_t type = NETCONN_DNS_IPV4_IPV6;
        if (ai_family == AF_INET) {
          type = NETCONN_DNS_IPV4;
        } else if (ai_family == AF_INET6) {
          type = NETCONN_DNS_IPV6;
#if ESP_LWIP
          if (hints->ai_flags & AI_V4MAPPED) {
            type = NETCONN_DNS_IPV6_IPV4;
          }
#endif /* ESP_LWIP */
        }
        err = netconn_gethostbyname_addrtype(nodename, &addr, type);
      }
#else /* LWIP_IPV4 && LWIP_IPV6 */
      err = netconn_gethostbyname(nodename, &addr);
#endif /* LWIP_IPV4 && LWIP_IPV6 */
      if (err != ERR_OK) {
        return EAI_FAIL;
      }
    }
  } else {
    /* service location specified, use loopback address */
    if ((hints != NULL) && (hints->ai_flags & AI_PASSIVE)) {
      ip_addr_set_any_val(ai_family == AF_INET6, addr);
    } else {
      ip_addr_set_loopback_val(ai_family == AF_INET6, addr);
    }
  }

#if ESP_LWIP && LWIP_IPV4 && LWIP_IPV6
  if (ai_family == AF_INET6 && (hints->ai_flags & AI_V4MAPPED)
      && IP_GET_TYPE(&addr) == IPADDR_TYPE_V4) {
    /* Convert native V4 address to a V4-mapped IPV6 address */
    ip4_2_ipv4_mapped_ipv6(ip_2_ip6(&addr), ip_2_ip4(&addr));
    IP_SET_TYPE_VAL(addr, IPADDR_TYPE_V6);
  }
#endif /* ESP_LWIP && LWIP_IPV4 && LWIP_IPV6 */

  total_size = sizeof(struct addrinfo) + sizeof(struct sockaddr_storage);
  if (nodename != NULL) {
    namelen = strlen(nodename);
    if (namelen > DNS_MAX_NAME_LENGTH) {
      /* invalid name length */
      return EAI_FAIL;
    }
    LWIP_ASSERT("namelen is too long", total_size + namelen + 1 > total_size);
    total_size += namelen + 1;
  }
  /* If this fails, please report to lwip-devel! :-) */
  LWIP_ASSERT("total_size <= NETDB_ELEM_SIZE: please report this!",
              total_size <= NETDB_ELEM_SIZE);
  ai = (struct addrinfo *)memp_malloc(MEMP_NETDB);
  if (ai == NULL) {
    return EAI_MEMORY;
  }
  memset(ai, 0, total_size);
  /* cast through void* to get rid of alignment warnings */
  sa = (struct sockaddr_storage *)(void *)((u8_t *)ai + sizeof(struct addrinfo));
  if (IP_IS_V6_VAL(addr)) {
#if LWIP_IPV6
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
    /* set up sockaddr */
    inet6_addr_from_ip6addr(&sa6->sin6_addr, ip_2_ip6(&addr));
    sa6->sin6_family = AF_INET6;
    sa6->sin6_len = sizeof(struct sockaddr_in6);
    sa6->sin6_port = lwip_htons((u16_t)port_nr);
    sa6->sin6_scope_id = ip6_addr_zone(ip_2_ip6(&addr));
    ai->ai_family = AF_INET6;
#endif /* LWIP_IPV6 */
  } else {
#if LWIP_IPV4
    struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
    /* set up sockaddr */
    inet_addr_from_ip4addr(&sa4->sin_addr, ip_2_ip4(&addr));
    sa4->sin_family = AF_INET;
    sa4->sin_len = sizeof(struct sockaddr_in);
    sa4->sin_port = lwip_htons((u16_t)port_nr);
    ai->ai_family = AF_INET;
#endif /* LWIP_IPV4 */
  }

  /* set up addrinfo */
  if (hints != NULL) {
    /* copy socktype & protocol from hints if specified */
    ai->ai_socktype = hints->ai_socktype;
    ai->ai_protocol = hints->ai_protocol;
  }
  if (nodename != NULL) {
    /* copy nodename to canonname if specified */
    ai->ai_canonname = ((char *)ai + sizeof(struct addrinfo) + sizeof(struct sockaddr_storage));
    MEMCPY(ai->ai_canonname, nodename, namelen);
    ai->ai_canonname[namelen] = 0;
  }
  ai->ai_addrlen = sizeof(struct sockaddr_storage);
  ai->ai_addr = (struct sockaddr *)sa;

  *res = ai;

  return 0;
}

#if LWIP_IPV4 && LWIP_IPV6 && LWIP_DNS_DYNAMIC_SORT

/* Labels 1-13 for the default precedence table from RFC 6724 */
#define IP6_PRECEDENCE_LABEL_LOCALHOST             0x0
#define IP6_PRECEDENCE_LABEL_GENERAL               0x1
#define IP6_PRECEDENCE_LABEL_IPV4_COMPATIBLE_IPV6  0x3
#define IP6_PRECEDENCE_LABEL_6TO4                  0x2
#define IP6_PRECEDENCE_LABEL_IPV4_MAPPED_IPV6      0x4
#define IP6_PRECEDENCE_LABEL_TOREDO                0x5
#define IP6_PRECEDENCE_LABEL_SITE_LOCAL            0xb
#define IP6_PRECEDENCE_LABEL_6BONE                 0xc
#define IP6_PRECEDENCE_LABEL_ULA                   0xd

/* Prefix match functions for the ranges from the default precedence table */
#define ip6_addr_isipv4compatibleipv6(ip6addr) (((ip6addr)->addr[0] == 0) && ((ip6addr)->addr[1] == 0) && (((ip6addr)->addr[2]) == PP_HTONL(0x00000000UL)))
#define ip6_addr_is6to4(ip6addr) (((ip6addr)->addr[0] & PP_HTONL(0xffff0000UL)) == PP_HTONL(0x20020000UL))
#define ip6_addr_isteredo(ip6addr) (((ip6addr)->addr[0] & PP_HTONL(0xffffffffUL)) == PP_HTONL(0x20010000UL))
#define ip6_addr_is6bone(ip6addr) (((ip6addr)->addr[0] & PP_HTONL(0xffff0000UL)) == PP_HTONL(0x3ffe0000UL))
#define ip6_addr_isip4vmappedlinklocal(ip6addr) (((ip6addr)->addr[0] == 0) && ((ip6addr)->addr[1] == 0) && (((ip6addr)->addr[2]) == PP_HTONL(0x0000ffffUL)) && (((ip6addr)->addr[3] & PP_HTONL(0xffff0000UL)) == PP_HTONL(0xa9fe0000UL)))
#define ip6_addr_isip4vmappedloopback(ip6addr) (((ip6addr)->addr[0] == 0) && ((ip6addr)->addr[1] == 0) && (((ip6addr)->addr[2]) == PP_HTONL(0x0000ffffUL)) && (((ip6addr)->addr[3] & PP_HTONL(0xff000000UL)) == PP_HTONL(0x7f000000UL)))

/**
 * @brief Determines scope of IPv6 address (including IPv4 mapped addresses)
 *
 * This function follows the RFC 6724 definition of scopes, matching
 * unicast addresses to the appropriate multicast scope.
 *
 * Link-local and the loopback are considered link-local, as are the
 * corresponding ranges in IPv4-mapped addresses. Everything else
 * (including ULA addresses, DNS64 address, etc) are global scope.
 *
 * NOTE: Existing functions ip6_addr_isglobal is not suitable because it
 * only checks for 2000:x and 3000:x addresses, and so misses things like
 * DNS64/NAT64 ranges.
 *
 * @param addr address to check
 * @return u8_t scope of address [0x0 - 0xf]
 */
u8_t
dns_addr_get_scope(const ip6_addr_t *addr) {
  u8_t scope = IP6_MULTICAST_SCOPE_RESERVED;
  if (ip6_addr_ismulticast(addr)) {
    scope = ip6_addr_multicast_scope(addr);
  } else if (ip6_addr_islinklocal(addr) || ip6_addr_isloopback(addr)
        || ip6_addr_isip4vmappedlinklocal(addr) || ip6_addr_isip4vmappedloopback(addr)) {
    scope = IP6_MULTICAST_SCOPE_LINK_LOCAL;
  } else if (ip6_addr_issitelocal(addr)) {
    scope = IP6_MULTICAST_SCOPE_SITE_LOCAL;
  } else {
    /* everything else, consider scope global */
    scope = IP6_MULTICAST_SCOPE_GLOBAL;
  }
  return scope;
}

/**
 * @brief Get the precedence label based on longest prefix match.
 *
 * This implements the default precedence table from RFC 6724.
 *
 * Labels are matched from longest prefix to shortest, with the
 * first match returned. The last label (most IPv6 addresses)
 * is the everything range (::/0), which has a high precendence.
 *
 * The presence of labels is stored as bit flags in an unsigned
 * int, so any custom values are limited to [0x00-0x1f].
 *
 * @param addr address to check
 * @return u8_t precedence label [0x0-0xd]
 */
u8_t
dns_get_precedence_label(const ip6_addr_t *addr) {
  /* IDEA: Allow this function to be overriden by a customisation hook */

  /* length 128 */
  if (ip6_addr_isloopback(addr)) {
    return IP6_PRECEDENCE_LABEL_LOCALHOST;
  }
  /* length 96 */
  if (ip6_addr_isipv4mappedipv6(addr)) {
    return IP6_PRECEDENCE_LABEL_IPV4_MAPPED_IPV6;
  }
  if (ip6_addr_isipv4compatibleipv6(addr)) {
    return IP6_PRECEDENCE_LABEL_IPV4_COMPATIBLE_IPV6;
  }
  /* length 32 */
  if (ip6_addr_isteredo(addr)) {
    return IP6_PRECEDENCE_LABEL_TOREDO;

  }
  /* length 16 */
  if (ip6_addr_is6to4(addr)) {
    return IP6_PRECEDENCE_LABEL_6TO4;
  }
  if (ip6_addr_is6bone(addr)) {
    return IP6_PRECEDENCE_LABEL_6BONE;
  }
  /* length 10 */
  if (ip6_addr_issitelocal(addr)) {
    return IP6_PRECEDENCE_LABEL_SITE_LOCAL;
  }
  /* length 7 */
  if (ip6_addr_isuniquelocal(addr)) {
    return IP6_PRECEDENCE_LABEL_ULA;
  }
  return IP6_PRECEDENCE_LABEL_GENERAL;
}

/**
 * @brief Gets the precedence ranking (higher has priority) for a given label
 *
 * Precedence ratings are based on RFC 6724 default values.
 *
 * @param label label to get precedence for
 * @return u8_t precendence [0-50]
 */
u8_t
dns_precedence_for_label(u8_t label) {
  /* IDEA: Allow this function to be overriden by a customisation hook */

  /*
    Default table from RFC 6724:

    Prefix        Precedence Label
    ::1/128               50     0 (loopback)
    ::/0                  40     1 (general IPv6)
    ::ffff:0:0/96         35     4 (IPv4-mapped IPv6)
    2002::/16             30     2 (6to4)
    2001::/32              5     5 (Teredo)
    fc00::/7               3    13 (ULA)
    ::/96                  1     3 (IPv4-compatible IPv6 - deprecated
    fec0::/10              1    11 (site-local - deprecated)
    3ffe::/16              1    12 (6bone - deprecated)
  */
  switch (label) {
    case IP6_PRECEDENCE_LABEL_LOCALHOST:
        return 50;
    case IP6_PRECEDENCE_LABEL_GENERAL:
        return 40;
    case IP6_PRECEDENCE_LABEL_IPV4_MAPPED_IPV6:
        return 35;
    case IP6_PRECEDENCE_LABEL_6TO4:
        return 30;
    case IP6_PRECEDENCE_LABEL_TOREDO:
        return 5;
    case IP6_PRECEDENCE_LABEL_ULA:
        return 3;
    case IP6_PRECEDENCE_LABEL_IPV4_COMPATIBLE_IPV6:
    case IP6_PRECEDENCE_LABEL_SITE_LOCAL:
    case IP6_PRECEDENCE_LABEL_6BONE:
        return 1;
    default:
        return 0;
  }
}

/**
 * Select the best destination address based on available source addresses.
 *
 * IPv4 addresses are represented as IPv4-mapped IPv6 addresses for this algorithm.
 *
 * DNS only returns a maximum of 2 addresses, one IPv6 and one IPv4, so the
 * current algorithm is simplified and only supports this case, although the
 * signature is generic and the logic could be extended to support multiple
 * addresses and pick the best (or even to sort them).
 *
 * This implementation follows RFC 6724 Sec. 6 to the following extent:
 *   Rule 1: not implemented
 * - Rule 2: implemented
 *   Rules 3, 4: not applicable
 * - Rule 5, 6: implemented - as we only have one of each address we will have a result
 * - Rules 7, 8, 9: not applicable
 * - Rule 10: implemented - but not applicable as we only have one of each address
 *
 * @param cand_list list of candidate destination addresses (IPv4 in IPv4-mapped IPv6 format)
 * @param cand_list_length length of the candidate list (maximum 2 addresses, one IPv6 and one IPv4)
 * @return the most suitable destination address to use, or NULL if no addresses were provided
 */
ip6_addr_t *
dns_select_destination_address(ip6_addr_t *cand_list[], const int cand_list_length)
{
  LWIP_DEBUGF(DNS_DEBUG, ("dns_select: selecting from %d candidates\n", cand_list_length));

  /* Short circuit - no addresses */
  if (cand_list_length == 0) {
    return NULL;
  }
  /* Short circuit - Only one address, so by definition it is the most suitable */
  if (cand_list_length == 1) {
    return cand_list[0];
  }

  /*
  If we get past this point, then we have exactly 2 addresses:
  cand_list[0] is IPv6 and cand_list[1] is IPv4.

  Determine types of available source address types
  Note: We don't actually determine preferred source address,
  but use a heuristic that if the type exists, then one of them
  will be preferred (and match), and if it the type doesn't exist,
  then the preferred can't match.
  */
  u32_t has_ipv6_source_scope_flags = 0x0;
  u32_t has_ipv4_source_scope_flags = 0x0;
  u32_t has_source_precedence_label_flags = 0x0;
  struct netif *netif;
  for(netif = netif_list; netif != NULL; netif = netif->next) {
    const ip4_addr_t *ip4_addr = netif_ip4_addr(netif);
    if (!ip4_addr_cmp(ip4_addr, IP4_ADDR_ANY4)) {
      /* Convert native V4 address to a V4-mapped IPV6 address */
      ip6_addr_t mapped_addr;
      ip4_2_ipv4_mapped_ipv6(&mapped_addr, ip4_addr);
      has_ipv4_source_scope_flags |= 0x1 << dns_addr_get_scope(&mapped_addr);
      has_source_precedence_label_flags |= 0x1 << dns_get_precedence_label(&mapped_addr);
    }

    for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
      const ip6_addr_t *ip6_addr = netif_ip6_addr(netif, i);
      if (!ip6_addr_isany_val(*ip6_addr)) {
        has_ipv6_source_scope_flags |= 0x1 << dns_addr_get_scope(ip6_addr);
        has_source_precedence_label_flags |= 0x1 << dns_get_precedence_label(ip6_addr);
      }
    }
  }

  LWIP_DEBUGF(DNS_DEBUG, ("dns_select: precedence labels flags 0x%04x, ipv6 scopes flags 0x%04x, ipv4 scopes flags 0x%04x\n",
    (unsigned int)has_source_precedence_label_flags, (unsigned int)has_ipv6_source_scope_flags,
    (unsigned int)has_ipv4_source_scope_flags));

  /* Rule 1: Avoid unusable destinations - not implemented */

  /* Rule 2: Prefer matching scope */
  /*
  DNS is unlikely to return anything but global scope addresses, but we check anyway

  Note: We don't actually calculate the source address, just check if at least one
  of the source address (of the right type IPv6/IPv4) has a matching scope;
  The source address selection prioritises appropriate scope, so if we have some
  then one of them would be preferred and so the scope would match.
  (If we don't have any matching, then the preferred can't be matching)
  */
  u8_t cand_0_scope = dns_addr_get_scope(cand_list[0]);
  bool cand_0_matching_scope = (0x1 << cand_0_scope & has_ipv6_source_scope_flags) != 0;

  u8_t cand_1_scope = dns_addr_get_scope(cand_list[0]);
  bool cand_1_matching_scope = (0x1 << cand_1_scope & has_ipv4_source_scope_flags) != 0;

  LWIP_DEBUGF(DNS_DEBUG, ("dns_select: rule 2, cand_0 scope (%d) match %d, cand_1 scope (%d) match %d\n",
    cand_0_scope, cand_0_matching_scope, cand_1_scope, cand_1_matching_scope));

  /* this is where it will return if there is no public IPv4 address */
  if (cand_0_matching_scope && !cand_1_matching_scope) {
    return cand_list[0];
  }
  /* this is where it will return if there is no global IPv6 address (only link-local) */
  if (cand_1_matching_scope && !cand_0_matching_scope) {
    return cand_list[1];
  }

  /* Rule 3: Avoid deprecated addresses - not applicable */
  /* Rule 4: Prefer home addresses - not applicable */

  /* Rule 5: Prefer matching label */

  /*
  Note: Similar to Rule 2, we don't actually calculate the source address,
  just check if we have at least one with a matching label. If we do, one of
  them would be preferred and matching; and if we don't there are not matching.
  IPv4 mapped is already it's own label, so not checked separately.
  */

  u8_t cand_0_label = dns_get_precedence_label(cand_list[0]);
  bool cand_0_matching_label = (0x1 << cand_0_label & has_source_precedence_label_flags) != 0;

  u8_t cand_1_label = dns_get_precedence_label(cand_list[1]);
  bool cand_1_matching_label = (0x1 << cand_1_label & has_source_precedence_label_flags) != 0;

  LWIP_DEBUGF(DNS_DEBUG, ("dns_select: rule 5, cand_0 label (%d) match %d, cand_1 label (%d) match %d\n",
    cand_0_label, cand_0_matching_label, cand_1_label, cand_1_matching_label));

  if (cand_0_matching_label && !cand_1_matching_label) {
    return cand_list[0];
  }
  if (cand_1_matching_label && !cand_0_matching_label) {
    return cand_list[1];
  }

  /* Rule 6: Prefer higher precedence */

  /*
  If we have IPv6 general (source) & general (destination),
  then we use that, otherwise we use IPv4.
  Even though ULA & ULA passes rule 5, it is lower precedence
  so that won't matter.
  */
  u8_t cand_0_precedence = dns_precedence_for_label(cand_0_label);
  u8_t cand_1_precedence = dns_precedence_for_label(cand_1_label);

  LWIP_DEBUGF(DNS_DEBUG, ("dns_select: rule 6, cand_0 precedence %d, cand_1 precedence %d\n",
    cand_0_precedence, cand_1_precedence));

  /* We will always return from one of these as cand 0 is IPv6 and cand 0 is IPv4,
     so won't ever have the same precedence */
  if (cand_0_precedence > cand_1_precedence) {
    return cand_list[0];
  }
  if (cand_1_precedence > cand_0_precedence) {
    return cand_list[1];
  }

  /* Rule 7: Prefer native transport - not applicable */
  /* Rule 8: Prefer smaller scope - not applicable */
  /* Rule 9: Use longest matching prefix - not applicable */

  /* Rule 10: Otherwise, leave the order unchanged */
  return cand_list[0];
}
#endif

#endif /* LWIP_DNS && LWIP_SOCKET */
