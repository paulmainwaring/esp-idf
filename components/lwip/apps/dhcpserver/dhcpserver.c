/*
 * SPDX-FileCopyrightText: 2015-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "lwip/dhcp.h"
#include "lwip/err.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"
#include "lwip/mem.h"
#include "lwip/ip_addr.h"
#include "lwip/timeouts.h"
#include "lwip/etharp.h"
#include "lwip/prot/ethernet.h"

#include "dhcpserver/dhcpserver.h"
#include "dhcpserver/dhcpserver_options.h"
#include "esp_log.h"

#if ESP_DHCPS

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

#ifndef LWIP_HOOK_DHCPS_POST_APPEND_OPTS
#define LWIP_HOOK_DHCPS_POST_APPEND_OPTS(netif, dhcps, state, pp_opts)
#endif

#define BOOTP_BROADCAST 0x8000
#define BROADCAST_BIT_IS_SET(flag) (flag & BOOTP_BROADCAST)

#define DHCP_REQUEST        1
#define DHCP_REPLY          2
#define DHCP_HTYPE_ETHERNET 1
#define DHCP_HLEN_ETHERNET  6
#define DHCP_MSG_LEN      236

#define DHCPS_SERVER_PORT  67
#define DHCPS_CLIENT_PORT  68

#define DHCPDISCOVER  1
#define DHCPOFFER     2
#define DHCPREQUEST   3
#define DHCPDECLINE   4
#define DHCPACK       5
#define DHCPNAK       6
#define DHCPRELEASE   7

#define DHCP_OPTION_PAD           0
#define DHCP_OPTION_SUBNET_MASK   1
#define DHCP_OPTION_ROUTER        3
#define DHCP_OPTION_DNS_SERVER    6
#define DHCP_OPTION_REQ_IPADDR   50
#define DHCP_OPTION_LEASE_TIME   51
#define DHCP_OPTION_MSG_TYPE     53
#define DHCP_OPTION_SERVER_ID    54
#define DHCP_OPTION_INTERFACE_MTU 26
#define DHCP_OPTION_PERFORM_ROUTER_DISCOVERY 31
#define DHCP_OPTION_BROADCAST_ADDRESS 28
#define DHCP_OPTION_REQ_LIST     55
#define DHCP_OPTION_END         255

//#define USE_CLASS_B_NET 1
#ifndef DHCPS_DEBUG
#define DHCPS_DEBUG          0
#endif
#define DHCPS_LOG printf

#define IS_INVALID_SUBNET_MASK(x)  (((x-1) | x) != 0xFFFFFFFF)
/* Notes:
*  CIDR eliminates the traditional Class A, Class B and Class C addresses.
 */
#define IP_CLASS_HOST_NUM(mask)            (0xffffffff & ~mask)
#define DHCP_CHECK_SUBNET_MASK_IP(mask)                                                               \
    do {                                                                                                  \
        if (IS_INVALID_SUBNET_MASK(mask)) {                                                               \
            DHCPS_LOG("dhcps: Illegal subnet mask.\n");                                                   \
            return ERR_ARG;                                                                               \
        }                                                                                                 \
    } while (0)

#define DHCP_CHECK_IP_MATCH_SUBNET_MASK(mask, ip)                           \
    u32_t start_ip = 0;                                                     \
    u32_t end_ip = 0;                                                       \
    do {                                                                    \
        start_ip = ip & mask;                                               \
        end_ip = start_ip | ~mask;                                          \
        if (ip == end_ip || ip == start_ip) {                               \
            DHCPS_LOG("dhcps: ip address and subnet mask do not match.\n"); \
            return ERR_ARG;                                                 \
        }                                                                   \
    } while (0)

#define MAX_STATION_NUM CONFIG_LWIP_DHCPS_MAX_STATION_NUM

/* hold-down period of a withheld address, in dhcps_tmr ticks */
#define DHCPS_HOLD_TICKS (CONFIG_LWIP_DHCPS_DECLINE_HOLD_SECS / DHCPS_COARSE_TIMER_SECS)

#if CONFIG_LWIP_DHCPS_OFFER_ARP_PROBE
/* pre-offer ARP conflict probe: two requests, decision after the full window */
#define DHCPS_PROBE_MAX       MAX_STATION_NUM
#define DHCPS_PROBE_HALF_MS   (CONFIG_LWIP_DHCPS_OFFER_ARP_PROBE_MS / 2)
#define DHCPS_PROBE_NONE      0   /* send the OFFER now */
#define DHCPS_PROBE_DEFERRED  1   /* probe pending, it owns the message */
#define DHCPS_PROBE_CONFLICT  2   /* candidate withheld, re-run allocation */
#endif

#define DHCPS_STATE_OFFER 1
#define DHCPS_STATE_DECLINE 2
#define DHCPS_STATE_ACK 3
#define DHCPS_STATE_NAK 4
#define DHCPS_STATE_IDLE 5
#define DHCPS_STATE_RELEASE 6

typedef enum {
    DHCPS_HANDLE_CREATED = 0,
    DHCPS_HANDLE_STARTED,
    DHCPS_HANDLE_STOPPED,
    DHCPS_HANDLE_DELETE_PENDING,
} dhcps_handle_state;

typedef struct list_node {
	void *pnode;
	struct list_node *pnext;
} list_node;

typedef struct {
    ip4_addr_t ip;
    ip4_addr_t netmask;
    ip4_addr_t gw;
} ip_info_t;
////////////////////////////////////////////////////////////////////////////////////

static const u32_t magic_cookie  = 0x63538263;

#if CONFIG_LWIP_DHCPS_OFFER_ARP_PROBE
struct dhcps_probe {
    struct dhcps_probe *next;
    dhcps_t *dhcps;
    struct dhcps_msg *msg;      /* owned copy of the DISCOVER */
    u16_t msg_len;              /* allocated size of msg (what send_offer wants) */
    u16_t opt_len;              /* options length (what parse_msg wants) */
    ip4_addr_t ip;              /* candidate address being probed */
    u8_t mac[6];                /* requesting client (chaddr) */
    u8_t phase;                 /* 0 = first ARP request sent, 1 = second sent */
};
#endif

struct dhcps_t {
    struct netif *dhcps_netif;
    ip4_addr_t broadcast_dhcps;
    ip4_addr_t server_address;
    ip4_addr_t dns_server;
    ip4_addr_t client_address;
    ip4_addr_t client_address_plus;
    ip4_addr_t dhcps_mask;
    list_node *plist;
    bool renew;
    dhcps_lease_t dhcps_poll;
    dhcps_time_t dhcps_lease_time;
    dhcps_offer_t dhcps_offer;
    dhcps_offer_t dhcps_dns;
    dhcps_cb_t dhcps_cb;
    void* dhcps_cb_arg;
    struct udp_pcb *dhcps_pcb;
    dhcps_handle_state state;
    bool has_declined_ip;
    bool alloc_new;             /* parse_msg() created a fresh lease node for the current message */
    ip4_addr_t opt_req_ip;      /* option 50 of the current message, 0 if absent */
    bool opt_other_server;      /* option 54 of the current message names another server */
#if CONFIG_LWIP_DHCPS_OFFER_ARP_PROBE
    struct dhcps_probe *probes; /* pending pre-offer probes */
    u8_t probe_count;
#endif
};


static void dhcps_tmr(void* arg);


dhcps_t *dhcps_new(void)
{
    dhcps_t *dhcps = mem_calloc(1, sizeof(dhcps_t));

    if (dhcps == NULL) {
        return NULL;
    }
    dhcps->dhcps_netif = NULL;
    dhcps->dns_server.addr = 0;
#ifdef USE_CLASS_B_NET
    dhcps->dhcps_mask.addr = PP_HTONL(LWIP_MAKEU32(255, 240, 0, 0));
#else
    dhcps->dhcps_mask.addr = PP_HTONL(LWIP_MAKEU32(255, 255, 255, 0));
#endif
    dhcps->plist = NULL;
    dhcps->renew = false;
    dhcps->dhcps_lease_time = DHCPS_LEASE_TIME_DEF;
    dhcps->dhcps_offer = 0xFF;
    dhcps->dhcps_dns = 0x00;
    dhcps->dhcps_pcb = NULL;
    dhcps->state = DHCPS_HANDLE_CREATED;
    dhcps->has_declined_ip = false;
    dhcps->alloc_new = false;
    dhcps->opt_req_ip.addr = 0;
    dhcps->opt_other_server = false;
    return dhcps;
}

void dhcps_delete(dhcps_t *dhcps)
{
    if (dhcps) {
        if (dhcps->state == DHCPS_HANDLE_STARTED) {
            // if the dhcp-server has started already, we have to postpone the deletion
            dhcps->state = DHCPS_HANDLE_DELETE_PENDING;
        } else {
            // otherwise, we're free to delete the handle immediately
            mem_free(dhcps);
        }
    }
}

static void get_ip_info(struct netif * netif, ip_info_t *ip_info)
{
    if (netif != NULL && netif_is_up(netif)) {
        ip4_addr_set(&ip_info->ip, ip_2_ip4(&netif->ip_addr));
        ip4_addr_set(&ip_info->netmask, ip_2_ip4(&netif->netmask));
        ip4_addr_set(&ip_info->gw, ip_2_ip4(&netif->gw));
    }
}

/******************************************************************************
 * FunctionName : dhcps_option_info
 * Description  : get the DHCP message option info
 * Parameters   : op_id -- DHCP message option id
 *                opt_len -- DHCP message option length
 * Returns      : DHCP message option addr
*******************************************************************************/
void *dhcps_option_info(dhcps_t *dhcps, u8_t op_id, u32_t opt_len)
{
    void *option_arg = NULL;
    if (dhcps == NULL) {
        return NULL;
    }

    switch (op_id) {
        case IP_ADDRESS_LEASE_TIME:
            if (opt_len == sizeof(dhcps_time_t)) {
                option_arg = &dhcps->dhcps_lease_time;
            }

            break;

        case REQUESTED_IP_ADDRESS:
            if (opt_len == sizeof(dhcps_lease_t)) {
                option_arg = &dhcps->dhcps_poll;
            }

            break;

        case ROUTER_SOLICITATION_ADDRESS:
            if (opt_len == sizeof(dhcps_offer_t)) {
                option_arg = &dhcps->dhcps_offer;
            }

            break;

        case DOMAIN_NAME_SERVER:
            if (opt_len == sizeof(dhcps_offer_t)) {
                option_arg = &dhcps->dhcps_dns;
            }

            break;
        case SUBNET_MASK:
            if (opt_len == sizeof(dhcps->dhcps_mask)) {
                option_arg = &dhcps->dhcps_mask;
            }

            break;
        default:
            break;
    }

    return option_arg;
}

/******************************************************************************
 * FunctionName : dhcps_set_option_info
 * Description  : set the DHCP message option info
 * Parameters   : op_id -- DHCP message option id
 *                opt_info -- DHCP message option info
 *                opt_len -- DHCP message option length
 * Returns      : none
*******************************************************************************/
err_t dhcps_set_option_info(dhcps_t *dhcps, u8_t op_id, void *opt_info, u32_t opt_len)
{
    if (dhcps == NULL || opt_info == NULL) {
        return ERR_ARG;
    }
    switch (op_id) {
        case IP_ADDRESS_LEASE_TIME:
            if (opt_len == sizeof(dhcps_time_t)) {
                dhcps->dhcps_lease_time = *(dhcps_time_t *)opt_info;
            }

            break;

        case REQUESTED_IP_ADDRESS:
            if (opt_len == sizeof(dhcps_lease_t)) {
                dhcps->dhcps_poll = *(dhcps_lease_t *)opt_info;
            }

            break;

        case ROUTER_SOLICITATION_ADDRESS:
            if (opt_len == sizeof(dhcps_offer_t)) {
                dhcps->dhcps_offer = *(dhcps_offer_t *)opt_info;
            }

            break;

        case DOMAIN_NAME_SERVER:
            if (opt_len == sizeof(dhcps_offer_t)) {
                dhcps->dhcps_dns = *(dhcps_offer_t *)opt_info;
            }
            break;

        case SUBNET_MASK:
            if (opt_len == sizeof(dhcps->dhcps_mask)) {
                dhcps->dhcps_mask = *(ip4_addr_t *)opt_info;
            }


        default:
            break;
    }
    return ERR_OK;
}

/******************************************************************************
 * FunctionName : node_insert_to_list
 * Description  : insert the node to the list
 * Parameters   : phead -- the head node of the list
 *                pinsert -- the insert node of the list
 * Returns      : none
*******************************************************************************/
static void node_insert_to_list(list_node **phead, list_node *pinsert)
{
    list_node *plist = NULL;
    struct dhcps_pool *pdhcps_pool = NULL;
    struct dhcps_pool *pdhcps_node = NULL;

    if (*phead == NULL) {
        *phead = pinsert;
    } else {
        plist = *phead;
        pdhcps_node = pinsert->pnode;
        pdhcps_pool = plist->pnode;

        if (pdhcps_node->ip.addr < pdhcps_pool->ip.addr) {
            pinsert->pnext = plist;
            *phead = pinsert;
        } else {
            while (plist->pnext != NULL) {
                pdhcps_pool = plist->pnext->pnode;

                if (pdhcps_node->ip.addr < pdhcps_pool->ip.addr) {
                    pinsert->pnext = plist->pnext;
                    plist->pnext = pinsert;
                    break;
                }

                plist = plist->pnext;
            }

            if (plist->pnext == NULL) {
                plist->pnext = pinsert;
            }
        }
    }

//	pinsert->pnext = NULL;
}

/******************************************************************************
 * FunctionName : node_delete_from_list
 * Description  : remove the node from list
 * Parameters   : phead -- the head node of the list
 *                pdelete -- the remove node of the list
 * Returns      : none
*******************************************************************************/
void node_remove_from_list(list_node **phead, list_node *pdelete)
{
    list_node *plist = NULL;

    plist = *phead;

    if (plist == NULL) {
        *phead = NULL;
    } else {
        if (plist == pdelete) {
            // Note: Ignoring the "use after free" warnings, as it could only happen
            // if the linked list contains loops
            *phead = plist->pnext; // NOLINT(clang-analyzer-unix.Malloc)
            pdelete->pnext = NULL;
        } else {
            while (plist != NULL) {
                if (plist->pnext == pdelete) { // NOLINT(clang-analyzer-unix.Malloc)
                    plist->pnext = pdelete->pnext;
                    pdelete->pnext = NULL;
                }

                plist = plist->pnext;
            }
        }
    }
}

/******************************************************************************
 * FunctionName : dhcps_addr_in_pool
 * Description  : check whether an address lies inside the configured pool
 * Parameters   : addr -- IPv4 address, network byte order
 * Returns      : true if start_ip <= addr <= end_ip
*******************************************************************************/
static bool dhcps_addr_in_pool(dhcps_t *dhcps, u32_t addr)
{
    u32_t a = lwip_ntohl(addr);

    return a >= lwip_ntohl(dhcps->dhcps_poll.start_ip.addr) &&
           a <= lwip_ntohl(dhcps->dhcps_poll.end_ip.addr);
}

/******************************************************************************
 * FunctionName : dhcps_pool_find_ip
 * Description  : find the pool node (lease or hold) for an address
 * Parameters   : addr -- IPv4 address, network byte order
 * Returns      : the node or NULL
*******************************************************************************/
static struct dhcps_pool *dhcps_pool_find_ip(dhcps_t *dhcps, u32_t addr)
{
    list_node *pback_node = NULL;
    struct dhcps_pool *pdhcps_pool = NULL;

    for (pback_node = dhcps->plist; pback_node != NULL; pback_node = pback_node->pnext) {
        pdhcps_pool = pback_node->pnode;

        if (pdhcps_pool->ip.addr == addr) {
            return pdhcps_pool;
        }
    }

    return NULL;
}

/******************************************************************************
 * FunctionName : dhcps_pool_hold
 * Description  : turn a pool node into a MAC-less hold node so the address is
 *                excluded from allocation for DHCPS_HOLD_TICKS (RFC 2131 4.3.3)
 * Parameters   : pool -- the node
 *                by_mac -- MAC that declined / answered for the address (log only)
 *                why -- reason text (log only)
 * Returns      : none
*******************************************************************************/
static void dhcps_pool_hold(dhcps_t *dhcps, struct dhcps_pool *pool, const u8_t *by_mac, const char *why)
{
    ESP_LWIP_LOGI("dhcps: %d.%d.%d.%d %s by %02x:%02x:%02x:%02x:%02x:%02x, withheld for %d s",
                  ip4_addr1(&pool->ip), ip4_addr2(&pool->ip), ip4_addr3(&pool->ip), ip4_addr4(&pool->ip),
                  why, by_mac[0], by_mac[1], by_mac[2], by_mac[3], by_mac[4], by_mac[5],
                  CONFIG_LWIP_DHCPS_DECLINE_HOLD_SECS);
    memset(pool->mac, 0, sizeof(pool->mac));
    pool->flags |= DHCPS_POOL_FLAG_HOLD;
    pool->lease_timer = DHCPS_HOLD_TICKS;
}

/******************************************************************************
 * FunctionName : dhcps_pool_hold_new
 * Description  : create a hold node for an address that has no pool node yet
 * Parameters   : addr -- IPv4 address, network byte order
 *                by_mac, why -- see dhcps_pool_hold
 * Returns      : none
*******************************************************************************/
static void dhcps_pool_hold_new(dhcps_t *dhcps, u32_t addr, const u8_t *by_mac, const char *why)
{
    struct dhcps_pool *pool = (struct dhcps_pool *)mem_calloc(1, sizeof(struct dhcps_pool));
    list_node *node = NULL;

    if (pool == NULL) {
        return;
    }

    node = (list_node *)mem_calloc(1, sizeof(list_node));

    if (node == NULL) {
        mem_free(pool);
        return;
    }

    pool->ip.addr = addr;
    node->pnode = pool;
    node->pnext = NULL;
    node_insert_to_list(&dhcps->plist, node);
    dhcps_pool_hold(dhcps, pool, by_mac, why);
}

/******************************************************************************
 * FunctionName : dhcps_handle_decline
 * Description  : DHCPDECLINE: the client found the address in use. Withhold
 *                the declined address (option 50) and detach it from the
 *                client's MAC so its next DISCOVER gets a different one.
 * Parameters   : pnode, pool -- the node parse_msg found or allocated for this
 *                MAC (ownership is taken: kept as hold node or freed)
 *                chaddr -- the declining client's MAC
 * Returns      : none
*******************************************************************************/
static void dhcps_handle_decline(dhcps_t *dhcps, list_node *pnode, struct dhcps_pool *pool, const u8_t *chaddr)
{
    u32_t declined = dhcps->opt_req_ip.addr;   /* RFC 2131 table 5: option 50 MUST be present */
    struct dhcps_pool *other = NULL;

    if (pool != NULL && declined != 0 && pool->ip.addr == declined) {
        /* the address we leased to this MAC: keep the node, drop the MAC */
        dhcps_pool_hold(dhcps, pool, chaddr, "declined");
        return;
    }

    /* not this MAC's lease (fresh cursor node or stale client state): free it */
    if (pnode != NULL) {
        node_remove_from_list(&dhcps->plist, pnode);
        mem_free(pnode);
    }

    if (pool != NULL) {
        mem_free(pool);
    }

    if (declined == 0 || !dhcps_addr_in_pool(dhcps, declined)) {
        return;
    }

    other = dhcps_pool_find_ip(dhcps, declined);

    if (other == NULL) {
        /* e.g. server restarted between ACK and DECLINE */
        dhcps_pool_hold_new(dhcps, declined, chaddr, "declined");
    } else if (other->flags & DHCPS_POOL_FLAG_HOLD) {
        other->lease_timer = DHCPS_HOLD_TICKS;
    }
    /* else: leased to another MAC; a stray DECLINE must not evict a valid lease */
}

/******************************************************************************
 * FunctionName : add_msg_type
 * Description  : add TYPE option of DHCP message
 * Parameters   : optptr -- the addr of DHCP message option
 * Returns      : the addr of DHCP message option
*******************************************************************************/
static u8_t *add_msg_type(u8_t *optptr, u8_t type)
{
    *optptr++ = DHCP_OPTION_MSG_TYPE;
    *optptr++ = 1;
    *optptr++ = type;
    return optptr;
}

/******************************************************************************
 * FunctionName : add_server_id
 * Description  : add Server Identifier option (RFC 2131 table 3: MUST be
 *                present in DHCPOFFER, DHCPACK and DHCPNAK)
 * Parameters   : optptr -- the addr of DHCP message option
 * Returns      : the addr of DHCP message option
*******************************************************************************/
static u8_t *add_server_id(dhcps_t *dhcps, u8_t *optptr)
{
    *optptr++ = DHCP_OPTION_SERVER_ID;
    *optptr++ = 4;
    *optptr++ = ip4_addr1(&dhcps->server_address);
    *optptr++ = ip4_addr2(&dhcps->server_address);
    *optptr++ = ip4_addr3(&dhcps->server_address);
    *optptr++ = ip4_addr4(&dhcps->server_address);
    return optptr;
}

/******************************************************************************
 * FunctionName : add_offer_options
 * Description  : add OFFER option of DHCP message
 * Parameters   : optptr -- the addr of DHCP message option
 * Returns      : the addr of DHCP message option
*******************************************************************************/
static u8_t *add_offer_options(dhcps_t *dhcps, u8_t *optptr)
{
    ip4_addr_t ipadd;

    ipadd.addr = *((u32_t *) &dhcps->server_address);

    *optptr++ = DHCP_OPTION_SUBNET_MASK;
    *optptr++ = 4;
    *optptr++ = ip4_addr1(&dhcps->dhcps_mask);
    *optptr++ = ip4_addr2(&dhcps->dhcps_mask);
    *optptr++ = ip4_addr3(&dhcps->dhcps_mask);
    *optptr++ = ip4_addr4(&dhcps->dhcps_mask);

    *optptr++ = DHCP_OPTION_LEASE_TIME;
    *optptr++ = 4;
    *optptr++ = ((dhcps->dhcps_lease_time * DHCPS_LEASE_UNIT) >> 24) & 0xFF;
    *optptr++ = ((dhcps->dhcps_lease_time * DHCPS_LEASE_UNIT) >> 16) & 0xFF;
    *optptr++ = ((dhcps->dhcps_lease_time * DHCPS_LEASE_UNIT) >> 8) & 0xFF;
    *optptr++ = ((dhcps->dhcps_lease_time * DHCPS_LEASE_UNIT) >> 0) & 0xFF;

    *optptr++ = DHCP_OPTION_SERVER_ID;
    *optptr++ = 4;
    *optptr++ = ip4_addr1(&ipadd);
    *optptr++ = ip4_addr2(&ipadd);
    *optptr++ = ip4_addr3(&ipadd);
    *optptr++ = ip4_addr4(&ipadd);

    if (dhcps_router_enabled(dhcps->dhcps_offer)) {
        ip_info_t if_ip = { 0 };
        get_ip_info(dhcps->dhcps_netif, &if_ip);

        ip4_addr_t* gw_ip = (ip4_addr_t*)&if_ip.gw;

        if (!ip4_addr_isany_val(*gw_ip)) {
            *optptr++ = DHCP_OPTION_ROUTER;
            *optptr++ = 4;
            *optptr++ = ip4_addr1(gw_ip);
            *optptr++ = ip4_addr2(gw_ip);
            *optptr++ = ip4_addr3(gw_ip);
            *optptr++ = ip4_addr4(gw_ip);
        }
    }

    *optptr++ = DHCP_OPTION_DNS_SERVER;
    *optptr++ = 4;
    if (dhcps_dns_enabled(dhcps->dhcps_dns)) {
        *optptr++ = ip4_addr1(&dhcps->dns_server);
        *optptr++ = ip4_addr2(&dhcps->dns_server);
        *optptr++ = ip4_addr3(&dhcps->dns_server);
        *optptr++ = ip4_addr4(&dhcps->dns_server);
    }else {
        *optptr++ = ip4_addr1(&ipadd);
        *optptr++ = ip4_addr2(&ipadd);
        *optptr++ = ip4_addr3(&ipadd);
        *optptr++ = ip4_addr4(&ipadd);
    }

    ip4_addr_t broadcast_addr = { .addr = (ipadd.addr & dhcps->dhcps_mask.addr) | ~dhcps->dhcps_mask.addr };
    *optptr++ = DHCP_OPTION_BROADCAST_ADDRESS;
    *optptr++ = 4;
    *optptr++ = ip4_addr1(&broadcast_addr);
    *optptr++ = ip4_addr2(&broadcast_addr);
    *optptr++ = ip4_addr3(&broadcast_addr);
    *optptr++ = ip4_addr4(&broadcast_addr);

    *optptr++ = DHCP_OPTION_INTERFACE_MTU;
    *optptr++ = 2;
    *optptr++ = 0x05;
    *optptr++ = 0xdc;

    *optptr++ = DHCP_OPTION_PERFORM_ROUTER_DISCOVERY;
    *optptr++ = 1;
    *optptr++ = 0x00;

    *optptr++ = 43;
    *optptr++ = 6;

    *optptr++ = 0x01;
    *optptr++ = 4;
    *optptr++ = 0x00;
    *optptr++ = 0x00;
    *optptr++ = 0x00;
    *optptr++ = 0x02;

    return optptr;
}

/******************************************************************************
 * FunctionName : add_end
 * Description  : add end option of DHCP message
 * Parameters   : optptr -- the addr of DHCP message option
 * Returns      : the addr of DHCP message option
*******************************************************************************/
static u8_t *add_end(u8_t *optptr)
{
    *optptr++ = DHCP_OPTION_END;
    return optptr;
}

/******************************************************************************
 * FunctionName : create_msg
 * Description  : create response message
 * Parameters   : m -- DHCP message info
 * Returns      : none
*******************************************************************************/
static void create_msg(dhcps_t *dhcps, struct dhcps_msg *m)
{
    ip4_addr_t client;


    client.addr = *((uint32_t *) &dhcps->client_address);

    m->op = DHCP_REPLY;
    m->htype = DHCP_HTYPE_ETHERNET;
    m->hlen = 6;

#if !ETHARP_SUPPORT_STATIC_ENTRIES
    /* If the DHCP server does not support sending unicast message to the client,
     * need to set the 'flags' field to broadcast */
    m->flags = htons(BOOTP_BROADCAST);
#endif

    memcpy((char *) m->yiaddr, (char *) &client.addr, sizeof(m->yiaddr));
    memcpy((char *) m->options, &magic_cookie, sizeof(magic_cookie));
}

/******************************************************************************
 * FunctionName : dhcps_response_ip_set
 * Description  : set the ip address for sending to the DHCP client
 * Parameters   : m -- DHCP message info
 *                ip4_out -- ip address for sending
 * Returns      : none
*******************************************************************************/
static void dhcps_response_ip_set(dhcps_t *dhcps, struct dhcps_msg *m, ip4_addr_t *ip4_out)
{
#if ETHARP_SUPPORT_STATIC_ENTRIES
    ip4_addr_t ip4_giaddr;
    ip4_addr_t ip4_ciaddr;
    ip4_addr_t ip4_yiaddr;

    struct eth_addr chaddr;
    memcpy(chaddr.addr, m->chaddr, sizeof(chaddr.addr));
    memcpy((char *)&ip4_giaddr.addr, (char *)m->giaddr, sizeof(m->giaddr));
    memcpy((char *)&ip4_ciaddr.addr, (char *)m->ciaddr, sizeof(m->ciaddr));
    memcpy((char *)&ip4_yiaddr.addr, (char *)m->yiaddr, sizeof(m->yiaddr));

    if (!ip4_addr_isany_val(ip4_giaddr)) {
        /* If the 'giaddr' field is non-zero, send return message to the address in 'giaddr'. (RFC 2131)*/
        ip4_addr_set(ip4_out, &ip4_giaddr);
        /* add the IP<->MAC as static entry into the arp table. */
        etharp_add_static_entry(&ip4_giaddr, &chaddr);
    } else {
        if (!ip4_addr_isany_val(ip4_ciaddr)) {
            /* If the 'giaddr' field is zero and the 'ciaddr' is nonzero,
             * the server unicasts DHCPOFFER and DHCPACK message to the address in 'ciaddr'*/
            ip4_addr_set(ip4_out, &ip4_ciaddr);
            etharp_add_static_entry(&ip4_ciaddr, &chaddr);
        } else if (!BROADCAST_BIT_IS_SET(htons(m->flags))) {
            /* If the 'giaddr' is zero and 'ciaddr' is zero, and the broadcast bit is not set,
             * the server unicasts DHCPOFFER and DHCPACK message to the client's hardware address and
             * 'yiaddr' address. */
            ip4_addr_set(ip4_out, &ip4_yiaddr);
            etharp_add_static_entry(&ip4_yiaddr, &chaddr);
        } else {
            /* The server broadcast DHCPOFFER and DHCPACK message to 0xffffffff*/
            ip4_addr_set(ip4_out, &dhcps->broadcast_dhcps);
        }
    }
#else
    ip4_addr_set(ip4_out, &dhcps->broadcast_dhcps);
#endif
}


struct pbuf * dhcps_pbuf_alloc(u16_t len)
{
    u16_t mlen = sizeof(struct dhcps_msg);

    if (len > mlen) {
#if DHCPS_DEBUG
        DHCPS_LOG("dhcps: len=%d mlen=%d", len, mlen);
#endif
        mlen = len;
    }

    return pbuf_alloc(PBUF_TRANSPORT, mlen, PBUF_RAM);
}

/******************************************************************************
 * FunctionName : send_offer
 * Description  : DHCP message OFFER Response
 * Parameters   : m -- DHCP message info
 * Returns      : none
*******************************************************************************/
static void send_offer(dhcps_t *dhcps, struct dhcps_msg *m, u16_t len)
{
    u8_t *end;
    struct pbuf *p, *q;
    u8_t *data;
    u16_t cnt = 0;
    u16_t i;
#if DHCPS_DEBUG
    err_t SendOffer_err_t;
#endif
    create_msg(dhcps, m);

    end = add_msg_type(&m->options[4], DHCPOFFER);
    end = add_offer_options(dhcps, end);
    LWIP_HOOK_DHCPS_POST_APPEND_OPTS(dhcps->dhcps_netif, dhcps, DHCPOFFER, &end)
    end = add_end(end);

    p = dhcps_pbuf_alloc(len);
#if DHCPS_DEBUG
    DHCPS_LOG("udhcp: send_offer>>p->ref = %d\n", p->ref);
#endif

    if (p != NULL) {

#if DHCPS_DEBUG
        DHCPS_LOG("dhcps: send_offer>>pbuf_alloc succeed\n");
        DHCPS_LOG("dhcps: send_offer>>p->tot_len = %d\n", p->tot_len);
        DHCPS_LOG("dhcps: send_offer>>p->len = %d\n", p->len);
#endif
        q = p;

        while (q != NULL) {
            data = (u8_t *)q->payload;

            for (i = 0; i < q->len; i++) {
                data[i] = ((u8_t *) m)[cnt++];
#if DHCPS_DEBUG
                DHCPS_LOG("%02x ", data[i]);

                if ((i + 1) % 16 == 0) {
                    DHCPS_LOG("\n");
                }

#endif
            }

            q = q->next;
        }
    } else {

#if DHCPS_DEBUG
        DHCPS_LOG("dhcps: send_offer>>pbuf_alloc failed\n");
#endif
        return;
    }

    ip_addr_t ip_temp = IPADDR4_INIT(0x0);
    dhcps_response_ip_set(dhcps, m, ip_2_ip4(&ip_temp));
#if DHCPS_DEBUG
    SendOffer_err_t = udp_sendto(dhcps->dhcps_pcb, p, &ip_temp, DHCPS_CLIENT_PORT);
    DHCPS_LOG("dhcps: send_offer>>udp_sendto result %x\n", SendOffer_err_t);
#else
    udp_sendto(dhcps->dhcps_pcb, p, &ip_temp, DHCPS_CLIENT_PORT);
#endif

#if ETHARP_SUPPORT_STATIC_ENTRIES
    /* remove the IP<->MAC from the arp table. */
    etharp_remove_static_entry(ip_2_ip4(&ip_temp));
#endif

    if (p->ref != 0) {
#if DHCPS_DEBUG
        DHCPS_LOG("udhcp: send_offer>>free pbuf\n");
#endif
        pbuf_free(p);
    }
}

/******************************************************************************
 * FunctionName : send_nak
 * Description  : DHCP message NACK Response
 * Parameters   : m -- DHCP message info
 * Returns      : none
*******************************************************************************/
static void send_nak(dhcps_t *dhcps, struct dhcps_msg *m, u16_t len)
{
    u8_t *end;
    struct pbuf *p, *q;
    u8_t *data;
    u16_t cnt = 0;
    u16_t i;
#if DHCPS_DEBUG
    err_t SendNak_err_t;
#endif
    create_msg(dhcps, m);
    /* RFC 2131 table 3: yiaddr MUST be 0 in DHCPNAK (client_address may be stale
     * on the pool-exhausted path) and the Server Identifier MUST be present */
    memset((char *) m->yiaddr, 0, sizeof(m->yiaddr));

    end = add_msg_type(&m->options[4], DHCPNAK);
    end = add_server_id(dhcps, end);
    LWIP_HOOK_DHCPS_POST_APPEND_OPTS(dhcps->dhcps_netif, dhcps, DHCPNAK, &end)
    end = add_end(end);

    p = dhcps_pbuf_alloc(len);
#if DHCPS_DEBUG
    DHCPS_LOG("udhcp: send_nak>>p->ref = %d\n", p->ref);
#endif

    if (p != NULL) {

#if DHCPS_DEBUG
        DHCPS_LOG("dhcps: send_nak>>pbuf_alloc succeed\n");
        DHCPS_LOG("dhcps: send_nak>>p->tot_len = %d\n", p->tot_len);
        DHCPS_LOG("dhcps: send_nak>>p->len = %d\n", p->len);
#endif
        q = p;

        while (q != NULL) {
            data = (u8_t *)q->payload;

            for (i = 0; i < q->len; i++) {
                data[i] = ((u8_t *) m)[cnt++];
#if DHCPS_DEBUG
                DHCPS_LOG("%02x ", data[i]);

                if ((i + 1) % 16 == 0) {
                    DHCPS_LOG("\n");
                }

#endif
            }

            q = q->next;
        }
    } else {

#if DHCPS_DEBUG
        DHCPS_LOG("dhcps: send_nak>>pbuf_alloc failed\n");
#endif
        return;
    }

    ip_addr_t ip_temp = IPADDR4_INIT(0x0);

#if ETHARP_SUPPORT_STATIC_ENTRIES
    ip4_addr_t ip4_giaddr;
    struct eth_addr chaddr;
    memcpy(chaddr.addr, m->chaddr, sizeof(chaddr.addr));
    memcpy((char *)&ip4_giaddr.addr, (char *)m->giaddr, sizeof(m->giaddr));

    if (!ip4_addr_isany_val(ip4_giaddr)) {
        ip4_addr_set(ip_2_ip4(&ip_temp), &ip4_giaddr);
        /* add the IP<->MAC as static entry into the arp table. */
        etharp_add_static_entry(&ip4_giaddr, &chaddr);
    } else {
        /* when 'giaddr' is zero, the server broadcasts any DHCPNAK message to 0xffffffff. (RFC 2131)*/
        ip4_addr_set(ip_2_ip4(&ip_temp), &dhcps->broadcast_dhcps);
    }
#else
    ip4_addr_set(ip_2_ip4(&ip_temp), &dhcps->broadcast_dhcps);
#endif

#if DHCPS_DEBUG
    SendNak_err_t = udp_sendto(dhcps->dhcps_pcb, p, &ip_temp, DHCPS_CLIENT_PORT);
    DHCPS_LOG("dhcps: send_nak>>udp_sendto result %x\n", SendNak_err_t);
#else
    udp_sendto(dhcps->dhcps_pcb, p, &ip_temp, DHCPS_CLIENT_PORT);
#endif

#if ETHARP_SUPPORT_STATIC_ENTRIES
    /* remove the IP<->MAC from the arp table. */
    etharp_remove_static_entry(ip_2_ip4(&ip_temp));
#endif

    if (p->ref != 0) {
#if DHCPS_DEBUG
        DHCPS_LOG("udhcp: send_nak>>free pbuf\n");
#endif
        pbuf_free(p);
    }
}

/******************************************************************************
 * FunctionName : send_ack
 * Description  : DHCP message ACK Response
 * Parameters   : m -- DHCP message info
 * Returns      : none
*******************************************************************************/
static void send_ack(dhcps_t *dhcps, struct dhcps_msg *m, u16_t len)
{
    u8_t *end;
    struct pbuf *p, *q;
    u8_t *data;
    u16_t cnt = 0;
    u16_t i;
    err_t SendAck_err_t;
    create_msg(dhcps, m);

    end = add_msg_type(&m->options[4], DHCPACK);
    end = add_offer_options(dhcps, end);
    LWIP_HOOK_DHCPS_POST_APPEND_OPTS(dhcps->dhcps_netif, dhcps, DHCPACK, &end)
    end = add_end(end);

    p = dhcps_pbuf_alloc(len);
#if DHCPS_DEBUG
    DHCPS_LOG("udhcp: send_ack>>p->ref = %d\n", p->ref);
#endif

    if (p != NULL) {

#if DHCPS_DEBUG
        DHCPS_LOG("dhcps: send_ack>>pbuf_alloc succeed\n");
        DHCPS_LOG("dhcps: send_ack>>p->tot_len = %d\n", p->tot_len);
        DHCPS_LOG("dhcps: send_ack>>p->len = %d\n", p->len);
#endif
        q = p;

        while (q != NULL) {
            data = (u8_t *)q->payload;

            for (i = 0; i < q->len; i++) {
                data[i] = ((u8_t *) m)[cnt++];
#if DHCPS_DEBUG
                DHCPS_LOG("%02x ", data[i]);

                if ((i + 1) % 16 == 0) {
                    DHCPS_LOG("\n");
                }

#endif
            }

            q = q->next;
        }
    } else {

#if DHCPS_DEBUG
        DHCPS_LOG("dhcps: send_ack>>pbuf_alloc failed\n");
#endif
        return;
    }

    ip_addr_t ip_temp = IPADDR4_INIT(0x0);
    dhcps_response_ip_set(dhcps, m, ip_2_ip4(&ip_temp));
    SendAck_err_t = udp_sendto(dhcps->dhcps_pcb, p, &ip_temp, DHCPS_CLIENT_PORT);
#if DHCPS_DEBUG
    DHCPS_LOG("dhcps: send_ack>>udp_sendto result %x\n", SendAck_err_t);
#endif

#if ETHARP_SUPPORT_STATIC_ENTRIES
    /* remove the IP<->MAC from the arp table. */
    etharp_remove_static_entry(ip_2_ip4(&ip_temp));
#endif

    if (SendAck_err_t == ERR_OK) {
        if (dhcps->dhcps_cb) {
            dhcps->dhcps_cb(dhcps->dhcps_cb_arg, m->yiaddr, m->chaddr);
        }
    }

    if (p->ref != 0) {
#if DHCPS_DEBUG
        DHCPS_LOG("udhcp: send_ack>>free pbuf\n");
#endif
        pbuf_free(p);
    }
}

/******************************************************************************
 * FunctionName : parse_options
 * Description  : parse DHCP message options
 * Parameters   : optptr -- DHCP message option info
 *                len -- DHCP message option length
 * Returns      : none
*******************************************************************************/
static u8_t parse_options(dhcps_t *dhcps, u8_t *optptr, s16_t len)
{
    ip4_addr_t client;
    struct dhcps_state s;

    client.addr = *((uint32_t *) &dhcps->client_address);

    u8_t *end = optptr + len;
    u16_t type = 0;

    s.state = DHCPS_STATE_IDLE;
    dhcps->opt_req_ip.addr = 0;
    dhcps->opt_other_server = false;

    while (optptr < end) {
#if DHCPS_DEBUG
        DHCPS_LOG("dhcps: (s16_t)*optptr = %d\n", (s16_t)*optptr);
#endif

        if (*optptr == DHCP_OPTION_PAD) {
            optptr++;
            continue;
        }

        if (*optptr == DHCP_OPTION_END) {
            break;
        }

        if (optptr + 1 >= end) {
            break;
        }

        u8_t opt_len = optptr[1];

        if (optptr + 2 + opt_len > end) {
            break;
        }

        switch ((s16_t) *optptr) {

            case DHCP_OPTION_MSG_TYPE:	//53
                if (opt_len >= 1) {
                    type = optptr[2];
                }
                break;

            case DHCP_OPTION_REQ_IPADDR://50
                if (opt_len >= 4) {
                    memcpy(&dhcps->opt_req_ip.addr, optptr + 2, 4);
                    /* A client the server has no lease for (alloc_new) is never ACKed
                     * just because the requested address happens to equal the pool
                     * cursor: NAK it so it re-DISCOVERs and goes through the normal
                     * allocation (and conflict probe) path. */
                    if (!dhcps->alloc_new && memcmp((char *) &client.addr, (char *) optptr + 2, 4) == 0) {
#if DHCPS_DEBUG
                        DHCPS_LOG("dhcps: DHCP_OPTION_REQ_IPADDR = 0 ok\n");
#endif
                        s.state = DHCPS_STATE_ACK;
                    } else {
#if DHCPS_DEBUG
                        DHCPS_LOG("dhcps: DHCP_OPTION_REQ_IPADDR != 0 err\n");
#endif
                        s.state = DHCPS_STATE_NAK;
                    }
                }

                break;

            case DHCP_OPTION_SERVER_ID://54
                if (opt_len >= 4 &&
                    memcmp((char *) &dhcps->server_address.addr, (char *) optptr + 2, 4) != 0) {
                    dhcps->opt_other_server = true;
                }

                break;
        }

        optptr += opt_len + 2;
    }

    switch (type) {

        case DHCPDISCOVER://1
            s.state = DHCPS_STATE_OFFER;
#if DHCPS_DEBUG
            DHCPS_LOG("dhcps: DHCPD_STATE_OFFER\n");
#endif
            break;

        case DHCPREQUEST://3
            if (dhcps->opt_other_server) {
                /* RFC 2131 4.3.2: servers not selected by the client MUST NOT respond */
                s.state = DHCPS_STATE_IDLE;
#if DHCPS_DEBUG
                DHCPS_LOG("dhcps: DHCPREQUEST for another server, ignored\n");
#endif
                break;
            }

            if (!(s.state == DHCPS_STATE_ACK || s.state == DHCPS_STATE_NAK)) {
                if (dhcps->renew == true) {
                    s.state = DHCPS_STATE_ACK;
                } else {
                    s.state = DHCPS_STATE_NAK;
                }

#if DHCPS_DEBUG
                DHCPS_LOG("dhcps: DHCPD_STATE_NAK\n");
#endif
            }

            break;

        case DHCPDECLINE://4
            s.state = DHCPS_STATE_DECLINE;
#if DHCPS_DEBUG
            DHCPS_LOG("dhcps: DHCPS_STATE_DECLINE\n");
#endif
            break;

        case DHCPRELEASE://7
            s.state = DHCPS_STATE_RELEASE;
#if DHCPS_DEBUG
            DHCPS_LOG("dhcps: DHCPD_STATE_IDLE\n");
#endif
            break;
    }

#if DHCPS_DEBUG
    DHCPS_LOG("dhcps: return s.state = %d\n", s.state);
#endif
    return s.state;
}

/******************************************************************************
 * FunctionName : parse_msg
 * Description  : parse DHCP message from netif
 * Parameters   : m -- DHCP message info
 *                len -- DHCP message length
 * Returns      : DHCP message type
*******************************************************************************/
static s16_t parse_msg(dhcps_t *dhcps, struct dhcps_msg *m, u16_t len)
{
    u32_t lease_timer = (dhcps->dhcps_lease_time * DHCPS_LEASE_UNIT)/DHCPS_COARSE_TIMER_SECS;

    if (memcmp((char *)m->options, &magic_cookie, sizeof(magic_cookie)) == 0) {
#if DHCPS_DEBUG
        DHCPS_LOG("dhcps: len = %d\n", len);
#endif
        ip4_addr_t addr_tmp;

        struct dhcps_pool *pdhcps_pool = NULL;
        list_node *pnode = NULL;
        list_node *pback_node = NULL;
        ip4_addr_t first_address;
        bool flag = false;

        first_address.addr = dhcps->dhcps_poll.start_ip.addr;
        dhcps->client_address.addr = dhcps->client_address_plus.addr;
        dhcps->renew = false;
        dhcps->alloc_new = false;

        if (dhcps->plist != NULL) {
            if (dhcps->has_declined_ip) {
                dhcps->has_declined_ip = false;
            }

            for (pback_node = dhcps->plist; pback_node != NULL; pback_node = pback_node->pnext) {
                pdhcps_pool = pback_node->pnode;

                if (!(pdhcps_pool->flags & DHCPS_POOL_FLAG_HOLD) &&
                    memcmp(pdhcps_pool->mac, m->chaddr, sizeof(pdhcps_pool->mac)) == 0) {
                    if (memcmp(&pdhcps_pool->ip.addr, m->ciaddr, sizeof(pdhcps_pool->ip.addr)) == 0) {
                        dhcps->renew = true;
                    }

                    dhcps->client_address.addr = pdhcps_pool->ip.addr;
                    pdhcps_pool->lease_timer = lease_timer;
                    pnode = pback_node;
                    goto POOL_CHECK;
                } else if (pdhcps_pool->ip.addr == dhcps->client_address_plus.addr) {
                    addr_tmp.addr = htonl(dhcps->client_address_plus.addr);
                    addr_tmp.addr++;
                    dhcps->client_address_plus.addr = htonl(addr_tmp.addr);
                    dhcps->client_address.addr = dhcps->client_address_plus.addr;
                }

                if (flag == false) { // search the fisrt unused ip
                    if (first_address.addr < pdhcps_pool->ip.addr) {
                        flag = true;
                    } else {
                        addr_tmp.addr = htonl(first_address.addr);
                        addr_tmp.addr++;
                        first_address.addr = htonl(addr_tmp.addr);
                    }
                }
            }
        } else {
            if (dhcps->has_declined_ip) {
                dhcps->has_declined_ip = false;
            } else {
                dhcps->client_address.addr = dhcps->dhcps_poll.start_ip.addr;
            }
        }

        if (dhcps->client_address_plus.addr > dhcps->dhcps_poll.end_ip.addr) {
            dhcps->client_address.addr = first_address.addr;
        }

        if (dhcps->client_address.addr > dhcps->dhcps_poll.end_ip.addr) {
            dhcps->client_address_plus.addr = dhcps->dhcps_poll.start_ip.addr;
            pdhcps_pool = NULL;
            pnode = NULL;
        } else {
            pdhcps_pool = (struct dhcps_pool *)mem_calloc(1, sizeof(struct dhcps_pool));
            if (pdhcps_pool == NULL) {
                return 0;
            }

            pdhcps_pool->ip.addr = dhcps->client_address.addr;
            memcpy(pdhcps_pool->mac, m->chaddr, sizeof(pdhcps_pool->mac));
            pdhcps_pool->lease_timer = lease_timer;
            pnode = (list_node *)mem_calloc(1, sizeof(list_node));
            if (pnode == NULL) {
                mem_free(pdhcps_pool);
                pdhcps_pool = NULL;
                return 0;
            }

            pnode->pnode = pdhcps_pool;
            pnode->pnext = NULL;
            node_insert_to_list(&dhcps->plist, pnode);
            dhcps->alloc_new = true;

            if (dhcps->client_address.addr == dhcps->dhcps_poll.end_ip.addr) {
                dhcps->client_address_plus.addr = dhcps->dhcps_poll.start_ip.addr;
            } else {
                addr_tmp.addr = htonl(dhcps->client_address.addr);
                addr_tmp.addr++;
                dhcps->client_address_plus.addr = htonl(addr_tmp.addr);
            }
        }

POOL_CHECK:

        if ((dhcps->client_address.addr > dhcps->dhcps_poll.end_ip.addr) || (ip4_addr_isany(&dhcps->client_address))) {
            if (pnode != NULL) {
                node_remove_from_list(&dhcps->plist, pnode);
                mem_free(pnode);
                pnode = NULL;
            }

            if (pdhcps_pool != NULL) {
                mem_free(pdhcps_pool);
                pdhcps_pool = NULL;
            }

            /* pool exhausted: NAK; make sure the reply carries yiaddr 0 */
            memset(&dhcps->client_address, 0x0, sizeof(dhcps->client_address));
            return 4;
        }

        s16_t ret = parse_options(dhcps, &m->options[4], len);

        /* Drop the lease node on RELEASE / NAK / DECLINE, and also when a message we
         * do not answer (unknown type, INFORM, REQUEST for another server, ...)
         * came from a client that had no lease: the node was only allocated
         * speculatively above and must not consume a pool address. */
        if (ret == DHCPS_STATE_DECLINE) {
            dhcps_handle_decline(dhcps, pnode, pdhcps_pool, m->chaddr);   /* takes ownership */
            pnode = NULL;
            pdhcps_pool = NULL;
            dhcps->has_declined_ip = true;   /* upstream flag; harmless with hold nodes present */
            memset(&dhcps->client_address, 0x0, sizeof(dhcps->client_address));
        } else if (ret == DHCPS_STATE_RELEASE || ret == DHCPS_STATE_NAK ||
                   (ret == DHCPS_STATE_IDLE && dhcps->alloc_new)) {
            if (pnode != NULL) {
                node_remove_from_list(&dhcps->plist, pnode);
                mem_free(pnode);
                pnode = NULL;
            }

            if (pdhcps_pool != NULL) {
                mem_free(pdhcps_pool);
                pdhcps_pool = NULL;
            }

            memset(&dhcps->client_address, 0x0, sizeof(dhcps->client_address));
        }

#if DHCPS_DEBUG
        DHCPS_LOG("dhcps: xid changed\n");
        DHCPS_LOG("dhcps: client_address.addr = %x\n", dhcps->client_address.addr);
#endif
        return ret;
    }

    return 0;
}

#if CONFIG_LWIP_DHCPS_OFFER_ARP_PROBE
static void dhcps_probe_tmr(void *arg);
static bool dhcps_handle_msg(dhcps_t *dhcps, struct dhcps_msg *m, u16_t msg_len, u16_t opt_len);

/******************************************************************************
 * FunctionName : dhcps_arp_conflict
 * Description  : is there a STABLE ARP entry for ip from a host other than the
 *                requesting client? (The client answering for an address it
 *                already holds is not a conflict.)
 * Parameters   : ip -- address to check
 *                mac -- requesting client's MAC
 *                eth_ret -- set to the other host's MAC on conflict
 * Returns      : true on conflict
*******************************************************************************/
static bool dhcps_arp_conflict(dhcps_t *dhcps, const ip4_addr_t *ip, const u8_t *mac, struct eth_addr **eth_ret)
{
    struct eth_addr *eth = NULL;
    const ip4_addr_t *ipr = NULL;

    if (etharp_find_addr(dhcps->dhcps_netif, ip, &eth, &ipr) < 0) {
        return false;
    }

    if (memcmp(eth->addr, mac, ETH_HWADDR_LEN) == 0) {
        return false;
    }

    *eth_ret = eth;
    return true;
}

static struct dhcps_probe *dhcps_probe_find_mac(dhcps_t *dhcps, const u8_t *mac)
{
    struct dhcps_probe *probe;

    for (probe = dhcps->probes; probe != NULL; probe = probe->next) {
        if (memcmp(probe->mac, mac, sizeof(probe->mac)) == 0) {
            return probe;
        }
    }

    return NULL;
}

static void dhcps_probe_unlink(dhcps_t *dhcps, struct dhcps_probe *probe)
{
    struct dhcps_probe **pp = &dhcps->probes;

    while (*pp != NULL && *pp != probe) {
        pp = &(*pp)->next;
    }

    if (*pp == probe) {
        *pp = probe->next;
        dhcps->probe_count--;
    }
}

static void dhcps_probe_free(struct dhcps_probe *probe)
{
    mem_free(probe->msg);
    mem_free(probe);
}

/******************************************************************************
 * FunctionName : dhcps_probe_cancel_all
 * Description  : drop every pending probe (server stop / restart / delete)
*******************************************************************************/
static void dhcps_probe_cancel_all(dhcps_t *dhcps)
{
    struct dhcps_probe *probe = dhcps->probes;
    struct dhcps_probe *next;

    while (probe != NULL) {
        next = probe->next;
        sys_untimeout(dhcps_probe_tmr, probe);
        dhcps_probe_free(probe);
        probe = next;
    }

    dhcps->probes = NULL;
    dhcps->probe_count = 0;
}

/******************************************************************************
 * FunctionName : dhcps_probe_start
 * Description  : decide whether the candidate address in dhcps->client_address
 *                (just allocated by parse_msg for this DISCOVER) must be
 *                ARP-probed before it is offered
 * Parameters   : m, msg_len, opt_len -- the DISCOVER (ownership taken on DEFERRED)
 * Returns      : DHCPS_PROBE_NONE / DHCPS_PROBE_DEFERRED / DHCPS_PROBE_CONFLICT
*******************************************************************************/
static int dhcps_probe_start(dhcps_t *dhcps, struct dhcps_msg *m, u16_t msg_len, u16_t opt_len)
{
    struct netif *netif = dhcps->dhcps_netif;
    struct dhcps_probe *probe;
    struct eth_addr *holder = NULL;
    struct dhcps_pool *pool;

    probe = dhcps_probe_find_mac(dhcps, m->chaddr);

    if (probe != NULL) {
        /* DISCOVER retransmitted while its probe is pending: keep the newest
         * copy (latest xid), keep waiting; one OFFER will be sent */
        mem_free(probe->msg);
        probe->msg = m;
        probe->msg_len = msg_len;
        probe->opt_len = opt_len;
        return DHCPS_PROBE_DEFERRED;
    }

    if (!dhcps->alloc_new) {
        /* client re-asks for the lease it already holds */
        return DHCPS_PROBE_NONE;
    }

    if (netif == NULL || !netif_is_up(netif) || !(netif->flags & NETIF_FLAG_ETHARP) ||
        dhcps->probe_count >= DHCPS_PROBE_MAX) {
        return DHCPS_PROBE_NONE;
    }

    /* zero-cost check first: a stale holder that talks to us (we are its
     * gateway) is already in the ARP table */
    if (dhcps_arp_conflict(dhcps, &dhcps->client_address, m->chaddr, &holder)) {
        pool = dhcps_pool_find_ip(dhcps, dhcps->client_address.addr);

        if (pool != NULL) {
            dhcps_pool_hold(dhcps, pool, holder->addr, "in use (ARP cache)");
            return DHCPS_PROBE_CONFLICT;
        }

        return DHCPS_PROBE_NONE;
    }

    probe = (struct dhcps_probe *)mem_calloc(1, sizeof(struct dhcps_probe));

    if (probe == NULL) {
        return DHCPS_PROBE_NONE;
    }

    probe->dhcps = dhcps;
    probe->msg = m;
    probe->msg_len = msg_len;
    probe->opt_len = opt_len;
    probe->ip.addr = dhcps->client_address.addr;
    memcpy(probe->mac, m->chaddr, sizeof(probe->mac));
    probe->phase = 0;
    probe->next = dhcps->probes;
    dhcps->probes = probe;
    dhcps->probe_count++;

    /* sender = our own address; a holder's reply is addressed to us and lands
     * in the ARP table where dhcps_arp_conflict() finds it */
    etharp_request(netif, &probe->ip);
    sys_timeout(DHCPS_PROBE_HALF_MS, dhcps_probe_tmr, probe);
    return DHCPS_PROBE_DEFERRED;
}

/******************************************************************************
 * FunctionName : dhcps_probe_tmr
 * Description  : probe timer: send the second ARP request, then decide
 * Parameters   : arg -- the probe record
*******************************************************************************/
static void dhcps_probe_tmr(void *arg)
{
    struct dhcps_probe *probe = arg;
    dhcps_t *dhcps = probe->dhcps;
    struct dhcps_msg *msg;
    u16_t msg_len, opt_len;
    ip4_addr_t ip;
    u8_t mac[6];
    list_node *pback_node = NULL;
    struct dhcps_pool *pdhcps_pool = NULL;
    struct dhcps_pool *pool = NULL;
    struct eth_addr *holder = NULL;

    if (dhcps->state != DHCPS_HANDLE_STARTED) {
        /* stop / delete raced us */
        dhcps_probe_unlink(dhcps, probe);
        dhcps_probe_free(probe);
        return;
    }

    if (probe->phase == 0) {
        probe->phase = 1;
        etharp_request(dhcps->dhcps_netif, &probe->ip);
        sys_timeout(DHCPS_PROBE_HALF_MS, dhcps_probe_tmr, probe);
        return;
    }

    /* decision: detach the record first, then act */
    dhcps_probe_unlink(dhcps, probe);
    msg = probe->msg;
    msg_len = probe->msg_len;
    opt_len = probe->opt_len;
    ip = probe->ip;
    memcpy(mac, probe->mac, sizeof(mac));
    mem_free(probe);

    if (!netif_is_up(dhcps->dhcps_netif)) {
        mem_free(msg);
        return;
    }

    /* the lease we are about to offer must still belong to this client */
    for (pback_node = dhcps->plist; pback_node != NULL; pback_node = pback_node->pnext) {
        pdhcps_pool = pback_node->pnode;

        if (!(pdhcps_pool->flags & DHCPS_POOL_FLAG_HOLD) &&
            memcmp(pdhcps_pool->mac, mac, sizeof(mac)) == 0) {
            pool = pdhcps_pool;
            break;
        }
    }

    if (pool == NULL || pool->ip.addr != ip.addr) {
        /* released / evicted meanwhile: the client will retry */
        mem_free(msg);
        return;
    }

    if (dhcps_arp_conflict(dhcps, &ip, mac, &holder)) {
        dhcps_pool_hold(dhcps, pool, holder->addr, "in use (ARP)");

        /* re-run allocation for this DISCOVER: next candidate, next probe */
        if (!dhcps_handle_msg(dhcps, msg, msg_len, opt_len)) {
            mem_free(msg);
        }

        return;
    }

#if DHCPS_DEBUG
    DHCPS_LOG("dhcps: probe clear, sending deferred OFFER\n");
#endif
    dhcps->client_address.addr = ip.addr;   /* create_msg() reads it */
    send_offer(dhcps, msg, msg_len);
    mem_free(msg);
}
#endif /* CONFIG_LWIP_DHCPS_OFFER_ARP_PROBE */

/******************************************************************************
 * FunctionName : dhcps_handle_msg
 * Description  : run the server state machine for one received message and
 *                send the reply
 * Parameters   : m -- the copied DHCP message (heap, owned by the caller)
 *                msg_len -- allocated size of m
 *                opt_len -- length of the options field
 * Returns      : true if ownership of m was taken (reply deferred), false if
 *                the caller must free m
*******************************************************************************/
static bool dhcps_handle_msg(dhcps_t *dhcps, struct dhcps_msg *m, u16_t msg_len, u16_t opt_len)
{
    s16_t state;
    u16_t guard;

    /* bounded loop instead of recursion (small tcpip task stack): one extra
     * pass per candidate the conflict probe withholds */
    for (guard = 0; guard <= DHCPS_MAX_LEASE; guard++) {
        state = parse_msg(dhcps, m, opt_len);
#ifdef LWIP_HOOK_DHCPS_POST_STATE
        state = LWIP_HOOK_DHCPS_POST_STATE(m, msg_len, state);
#endif /* LWIP_HOOK_DHCPS_POST_STATE */

        switch (state) {
            case DHCPS_STATE_OFFER://1
#if DHCPS_DEBUG
                DHCPS_LOG("dhcps: handle_dhcp-> DHCPD_STATE_OFFER\n");
#endif
#if CONFIG_LWIP_DHCPS_OFFER_ARP_PROBE
                {
                    int r = dhcps_probe_start(dhcps, m, msg_len, opt_len);

                    if (r == DHCPS_PROBE_DEFERRED) {
                        return true;
                    }

                    if (r == DHCPS_PROBE_CONFLICT) {
                        continue;   /* candidate withheld: allocate the next one */
                    }
                }
#endif
                send_offer(dhcps, m, msg_len);
                return false;

            case DHCPS_STATE_ACK://3
#if DHCPS_DEBUG
                DHCPS_LOG("dhcps: handle_dhcp-> DHCPD_STATE_ACK\n");
#endif
                send_ack(dhcps, m, msg_len);
                return false;

            case DHCPS_STATE_NAK://4
#if DHCPS_DEBUG
                DHCPS_LOG("dhcps: handle_dhcp-> DHCPD_STATE_NAK\n");
#endif
                send_nak(dhcps, m, msg_len);
                return false;

            default :
                return false;
        }
    }

    return false;
}

/******************************************************************************
 * FunctionName : handle_dhcp
 * Description  : If an incoming DHCP message is in response to us, then trigger the state machine
 * Parameters   : arg -- arg user supplied argument (udp_pcb.recv_arg)
 * 				  pcb -- the udp_pcb which received data
 * 			      p -- the packet buffer that was received
 * 				  addr -- the remote IP address from which the packet was received
 * 				  port -- the remote port from which the packet was received
 * Returns      : none
*******************************************************************************/
static void handle_dhcp(void *arg,
                        struct udp_pcb *pcb,
                        struct pbuf *p,
                        const ip_addr_t *addr,
                        u16_t port)
{
    struct dhcps_t *dhcps = arg;
    struct dhcps_msg *pmsg_dhcps = NULL;
    u16_t tlen, malloc_len;
    u8_t *p_dhcps_msg = NULL;

#if DHCPS_DEBUG
    DHCPS_LOG("dhcps: handle_dhcp-> receive a packet\n");
#endif

    if (p == NULL) {
        return;
    }

    if (p->tot_len > 1500) {
        pbuf_free(p);
        return;
    }

    malloc_len = sizeof(struct dhcps_msg);
#if DHCPS_DEBUG
    DHCPS_LOG("dhcps: handle_dhcp malloc_len=%d rx_len=%d", malloc_len, p->tot_len);
#endif
    if (malloc_len < p->tot_len) {
        malloc_len = p->tot_len;
    }

    pmsg_dhcps = (struct dhcps_msg *)mem_calloc(1, malloc_len);
    if (NULL == pmsg_dhcps) {
        pbuf_free(p);
        return;
    }

    p_dhcps_msg = (u8_t *)pmsg_dhcps;
    tlen = p->tot_len;

#if DHCPS_DEBUG
    DHCPS_LOG("dhcps: handle_dhcp-> p->tot_len = %d\n", tlen);
    DHCPS_LOG("dhcps: handle_dhcp-> p->len = %d\n", p->len);
#endif

    if (tlen == 0 || pbuf_copy_partial(p, p_dhcps_msg, tlen, 0) != tlen) {
        pbuf_free(p);
        mem_free(pmsg_dhcps);
        return;
    }

#if DHCPS_DEBUG
    DHCPS_LOG("dhcps: handle_dhcp-> parse_msg(p)\n");
#endif

    if (!dhcps_handle_msg(dhcps, pmsg_dhcps, malloc_len, tlen >= 240 ? (u16_t)(tlen - 240) : 0)) {
        mem_free(pmsg_dhcps);
    }
    pmsg_dhcps = NULL;

#if DHCPS_DEBUG
    DHCPS_LOG("dhcps: handle_dhcp-> pbuf_free(p)\n");
#endif
    pbuf_free(p);
}

/******************************************************************************
 * FunctionName : dhcps_poll_set
 * Description  : set ip poll from start to end for station
 * Parameters   : ip -- The current ip addr
 * Returns      : none
*******************************************************************************/
static void dhcps_poll_set(dhcps_t *dhcps, u32_t ip)
{
    u32_t server_ip = 0;
    u32_t start_ip = 0;
    u32_t end_ip = 0;
    u32_t range_start_ip = 0;
    u32_t range_end_ip = 0;
    dhcps_lease_t *dhcps_poll = &dhcps->dhcps_poll;
    if (dhcps_poll->enable == true) {
        server_ip = htonl(ip);
        start_ip = htonl(dhcps_poll->start_ip.addr);
        end_ip = htonl(dhcps_poll->end_ip.addr);

        /*config ip information can't contain local ip*/
        if ((server_ip >= start_ip) && (server_ip <= end_ip)) {
            dhcps_poll->enable = false;
        } else {
            /*config ip information must be in the same segment as the local ip*/

            if (!ip4_addr_netcmp(&dhcps_poll->start_ip, &dhcps->server_address, &dhcps->dhcps_mask)
                  || !ip4_addr_netcmp(&dhcps_poll->end_ip, &dhcps->server_address, &dhcps->dhcps_mask)
                  || (end_ip - start_ip + 1 > DHCPS_MAX_LEASE)) {
                dhcps_poll->enable = false;
            }
        }
    }

    if (dhcps_poll->enable == false) {
        server_ip = htonl(ip);
        range_start_ip = server_ip & htonl(dhcps->dhcps_mask.addr);
        range_end_ip = range_start_ip | ~htonl(dhcps->dhcps_mask.addr);

        if (server_ip - range_start_ip > range_end_ip - server_ip) {
            range_start_ip = range_start_ip + 1;
            range_end_ip = server_ip - 1;
        } else {
            range_start_ip = server_ip + 1;
            range_end_ip = range_end_ip - 1;
        }
        if (range_end_ip - range_start_ip + 1 > DHCPS_MAX_LEASE) {
            range_end_ip = range_start_ip + DHCPS_MAX_LEASE - 1;
        }
        bzero(dhcps_poll, sizeof(*dhcps_poll));
        dhcps_poll->start_ip.addr = range_start_ip;
        dhcps_poll->end_ip.addr = range_end_ip;
        dhcps_poll->start_ip.addr = htonl(dhcps_poll->start_ip.addr);
        dhcps_poll->end_ip.addr = htonl(dhcps_poll->end_ip.addr);
        dhcps_poll->enable = true;
    }

}


/******************************************************************************
 * FunctionName : dhcps_set_new_lease_cb
 * Description  : set callback for dhcp server when it assign an IP
 *                to the connected dhcp client
 * Parameters   : cb -- callback for dhcp server
 * Returns      : ERR_OK on success
*******************************************************************************/
err_t dhcps_set_new_lease_cb(dhcps_t *dhcps, dhcps_cb_t cb, void* cb_arg)
{
    if (dhcps == NULL) {
        return ERR_ARG;
    }
    dhcps->dhcps_cb = cb;
    dhcps->dhcps_cb_arg = cb_arg;
    return ERR_OK;
}

/******************************************************************************
 * FunctionName : dhcps_start
 * Description  : start dhcp server function
 * Parameters   : netif -- The current netif addr
 *              : info  -- The current ip info
 * Returns      : none
*******************************************************************************/
err_t dhcps_start(dhcps_t *dhcps, struct netif *netif, ip4_addr_t ip)
{
    if (dhcps == NULL || netif == NULL) {
        return ERR_ARG;
    }
    dhcps->dhcps_netif = netif;
#if CONFIG_LWIP_DHCPS_OFFER_ARP_PROBE
    dhcps_probe_cancel_all(dhcps);
#endif
    if (dhcps->dhcps_pcb != NULL) {
        udp_remove(dhcps->dhcps_pcb);
    }

    dhcps->dhcps_pcb = udp_new();

    if (dhcps->dhcps_pcb == NULL || ip4_addr_isany_val(ip)) {
        DHCPS_LOG("dhcps_start(): could not obtain pcb\n");
        return ERR_ARG;
    }

    IP4_ADDR(&dhcps->broadcast_dhcps, 255, 255, 255, 255);

    dhcps->server_address.addr = ip.addr;
    DHCP_CHECK_SUBNET_MASK_IP(htonl(dhcps->dhcps_mask.addr));
    DHCP_CHECK_IP_MATCH_SUBNET_MASK(htonl(dhcps->dhcps_mask.addr), htonl(ip.addr));
    dhcps_poll_set(dhcps, dhcps->server_address.addr);

    dhcps->client_address_plus.addr = dhcps->dhcps_poll.start_ip.addr;

    udp_bind_netif(dhcps->dhcps_pcb, dhcps->dhcps_netif);
    udp_bind(dhcps->dhcps_pcb, &netif->ip_addr, DHCPS_SERVER_PORT);
    udp_recv(dhcps->dhcps_pcb, handle_dhcp, dhcps);
#if DHCPS_DEBUG
    DHCPS_LOG("dhcps:dhcps_start->udp_recv function Set a receive callback handle_dhcp for UDP_PCB pcb_dhcps\n");
#endif
    dhcps->state = DHCPS_HANDLE_STARTED;
    sys_untimeout(dhcps_tmr, dhcps);   /* start without stop: do not arm a second timer */
    sys_timeout(DHCP_COARSE_TIMER_MSECS, dhcps_tmr, dhcps);
    return ERR_OK;
}

/******************************************************************************
 * FunctionName : dhcps_stop
 * Description  : stop dhcp server function
 * Parameters   : netif -- The current netif addr
 * Returns      : none
*******************************************************************************/
err_t dhcps_stop(dhcps_t *dhcps, struct netif *netif)
{
    if (dhcps == NULL || netif == NULL || dhcps->dhcps_netif != netif) {
#if DHCPS_DEBUG
        DHCPS_LOG("dhcps_stop: netif is NULL or invalid\n");
#endif
        return ERR_ARG;
    }

    if (dhcps->dhcps_pcb != NULL) {
        udp_disconnect(dhcps->dhcps_pcb);
        udp_remove(dhcps->dhcps_pcb);
        dhcps->dhcps_pcb = NULL;
    }

#if CONFIG_LWIP_DHCPS_OFFER_ARP_PROBE
    dhcps_probe_cancel_all(dhcps);
#endif

    list_node *pnode = NULL;
    list_node *pback_node = NULL;
    pnode = dhcps->plist;

    while (pnode != NULL) {
        pback_node = pnode;
        pnode = pback_node->pnext;
        node_remove_from_list(&dhcps->plist, pback_node);
        mem_free(pback_node->pnode);
        pback_node->pnode = NULL;
        mem_free(pback_node);
        pback_node = NULL;
    }
    sys_untimeout(dhcps_tmr, dhcps);
    dhcps->state = DHCPS_HANDLE_STOPPED;
    return ERR_OK;
}

/******************************************************************************
 * FunctionName : kill_oldest_dhcps_pool
 * Description  : remove the oldest node from list
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
static void kill_oldest_dhcps_pool(dhcps_t *dhcps)
{
    list_node *pre = NULL, *p = NULL;
    list_node *minpre = NULL, *minp = NULL;
    struct dhcps_pool *pdhcps_pool = NULL, *pmin_pool = NULL;

    /* find the lease with the least remaining time; hold nodes are not leases
     * and are never evicted */
    for (p = dhcps->plist; p != NULL; pre = p, p = p->pnext) {
        pdhcps_pool = p->pnode;

        if (pdhcps_pool->flags & DHCPS_POOL_FLAG_HOLD) {
            continue;
        }

        pmin_pool = (minp != NULL) ? minp->pnode : NULL;

        if (pmin_pool == NULL || pdhcps_pool->lease_timer < pmin_pool->lease_timer) {
            minp = p;
            minpre = pre;
        }
    }

    if (minp == NULL) {
        return;
    }

    if (minp == dhcps->plist) {
        dhcps->plist = minp->pnext;
    } else {
        minpre->pnext = minp->pnext;
    }
    mem_free(minp->pnode);
    minp->pnode = NULL;
    mem_free(minp);
    minp = NULL;
}

/******************************************************************************
 * FunctionName : dhcps_coarse_tmr
 * Description  : the lease time count
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
static void dhcps_tmr(void *arg)
{
    dhcps_t *dhcps = arg;
    dhcps_handle_state state = dhcps->state;
    if (state == DHCPS_HANDLE_DELETE_PENDING) {
#if CONFIG_LWIP_DHCPS_OFFER_ARP_PROBE
        dhcps_probe_cancel_all(dhcps);
#endif
        mem_free(dhcps);
        return;
    }

    if (state != DHCPS_HANDLE_STARTED) {
        return;
    }
    sys_timeout(DHCP_COARSE_TIMER_MSECS, dhcps_tmr, dhcps);
    u8_t num_dhcps_pool = 0;
    list_node *pback_node = NULL;
    list_node *pnode = NULL;
    struct dhcps_pool *pdhcps_pool = NULL;
    pnode = dhcps->plist;

    while (pnode != NULL) {
        pdhcps_pool = pnode->pnode;
        pdhcps_pool->lease_timer --;

        if (pdhcps_pool->lease_timer == 0) {
            pback_node = pnode;
            pnode = pback_node->pnext;
            node_remove_from_list(&dhcps->plist, pback_node);
            mem_free(pback_node->pnode);
            pback_node->pnode = NULL;
            mem_free(pback_node);
            pback_node = NULL;
        } else {
            pnode = pnode ->pnext;

            if (!(pdhcps_pool->flags & DHCPS_POOL_FLAG_HOLD)) {
                num_dhcps_pool ++;
            }
        }
    }

    if (num_dhcps_pool > MAX_STATION_NUM) {
        kill_oldest_dhcps_pool(dhcps);
    }
}

/******************************************************************************
 * FunctionName : dhcp_search_ip_on_mac
 * Description  : Search ip address based on mac address
 * Parameters   : mac -- The MAC addr
 *				  ip  -- The IP info
 * Returns      : true or false
*******************************************************************************/
bool dhcp_search_ip_on_mac(dhcps_t *dhcps, u8_t *mac, ip4_addr_t *ip)
{
    struct dhcps_pool *pdhcps_pool = NULL;
    list_node *pback_node = NULL;
    bool ret = false;

    if (dhcps == NULL) {
        return false;
    }

    for (pback_node = dhcps->plist; pback_node != NULL; pback_node = pback_node->pnext) {
        pdhcps_pool = pback_node->pnode;

        if (pdhcps_pool->flags & DHCPS_POOL_FLAG_HOLD) {
            continue;
        }

        if (memcmp(pdhcps_pool->mac, mac, sizeof(pdhcps_pool->mac)) == 0) {
            memcpy(&ip->addr, &pdhcps_pool->ip.addr, sizeof(pdhcps_pool->ip.addr));
            ret = true;
            break;
        }
    }

    return ret;
}

/******************************************************************************
 * FunctionName : dhcps_dns_setserver
 * Description  : set DNS server address for dhcpserver
 * Parameters   : dnsserver -- The DNS server address
 * Returns      : ERR_ARG if invalid handle, ERR_OK on success
*******************************************************************************/
err_t dhcps_dns_setserver(dhcps_t *dhcps, const ip_addr_t *dnsserver)
{
    if (dhcps == NULL) {
        return ERR_ARG;
    }
    if (dnsserver != NULL) {
        dhcps->dns_server = *(ip_2_ip4(dnsserver));
    } else {
        dhcps->dns_server = *(ip_2_ip4(IP_ADDR_ANY));
    }
    return ERR_OK;
}

/******************************************************************************
 * FunctionName : dhcps_dns_getserver
 * Description  : get DNS server address for dhcpserver
 * Parameters   : none
 * Returns      : ip4_addr_t
*******************************************************************************/
err_t dhcps_dns_getserver(dhcps_t *dhcps, ip4_addr_t *dnsserver)
{
    if (dhcps) {
        *dnsserver = dhcps->dns_server;
        return ERR_OK;
    }
    return ERR_ARG;
}
#endif // ESP_DHCPS
