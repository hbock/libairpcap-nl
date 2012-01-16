/* -*- mode: C; c-file-style: "k&r"; c-basic-offset: 4; indent-tabs-mode: nil; -*- */
/*
 * Airpcap library implementation for nl80211
 *
 * Copyright 2011-2012 Harry Bock <bock.harryw@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <linux/nl80211.h>

#include "airpcap.h"
#include "airpcap-nl.h"
#include "util.h"

#ifdef CONFIG_LIBNL20
/* /\* libnl 2.0 compatibility code *\/ */
/* #define nl_handle nl_sock */
/* #define nl_handle_alloc_cb nl_socket_alloc_cb */
/* #define nl_handle_destroy nl_socket_free */
#endif /* CONFIG_LIBNL20 */

static PAirpcapHandle airpcap_handle_new(void);
static void airpcap_handle_free(PAirpcapHandle handle);
static int wiphy_match_handler(struct nl_msg *msg, void *data);

VOID AirpcapGetVersion(PUINT VersionMajor,
		       PUINT VersionMinor,
		       PUINT VersionRev,
		       PUINT VersionBuild)
{
    *VersionMajor = 4;
    *VersionMinor = 1;
    *VersionRev   = 1;
    *VersionBuild = 0;
}

static int
nl80211_state_init(PAirpcapHandle handle, PCHAR Ebuf)
{
    struct nl_sock *rt_sock = NULL;
    int err;

    handle->nl_socket = nl_socket_alloc();
    /* Allocate the netlink socket.
     */
    if (NULL == handle->nl_socket) {
        setebuf(Ebuf, "Failed to allocate netlink socket.");
        return -1;
    }
    /* Connect to the generic netlink.
     */
    if (genl_connect(handle->nl_socket)) {
        setebuf(Ebuf, "Failed to connect to generic netlink.");
        goto err;
    }

    if (genl_ctrl_alloc_cache(handle->nl_socket,
                              &handle->nl_cache)) {
        setebuf(Ebuf, "Failed to allocate generic netlink cache.");
        goto err;
    }

    /* Find and get a reference to the nl80211 family.
     * Must hand back the reference via genl_family_put. */
    handle->nl80211 = genl_ctrl_search_by_name(handle->nl_cache,
                                               "nl80211");
    if (NULL == handle->nl80211) {
        setebuf(Ebuf, "Netlink module nl80211 not found.");
        goto err;
    }

    if (0 != ifconfig_get_hwaddr(handle->master_ifname,
                                 (uint8_t *)handle->mac.Address)) {
        setebuf(Ebuf, "Failed to get hardware address: %s",
                strerror(errno));
        goto err;
    }

    return 0;

err:
    if (handle->nl80211)
        genl_family_put(handle->nl80211);
    if (handle->nl_cache)
        nl_cache_free(handle->nl_cache);
    if (handle->nl_socket)
        nl_handle_destroy(handle->nl_socket);

    return -1;
}

static int
error_handler(struct sockaddr_nl *nla UNUSED,
              struct nlmsgerr *err,
              void *arg)
{
	int *ret = arg;
	*ret = err->error;

        /* should this be STOP or SKIP? */
	return NL_STOP;
}
static int
finish_handler(struct nl_msg *msg UNUSED,
               void *arg)
{
	int *ret = arg;
	*ret = 0;

	return NL_SKIP;
}
static int
ack_handler(struct nl_msg *msg UNUSED,
            void *arg)
{
	int *ret = arg;
	*ret = 0;

	return NL_STOP;
}

struct airpcap_interface_list {
    unsigned ifindex;
    unsigned int phyindex;
    struct airpcap_interface_list *next;
};
struct airpcap_interface_dump_data {
    struct airpcap_interface_list *start, *current;
};

static int
nl80211_get_wiphy(struct nl_sock *sock,
                  struct genl_family *family,
                  PAirpcapHandle handle);

static int
interface_dump_handler(struct nl_msg *msg, void *arg)
{
    struct airpcap_interface_dump_data *data = (struct airpcap_interface_dump_data *)arg;
    struct genlmsghdr *header = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(header, 0),
              genlmsg_attrlen(header, 0), NULL);

    if (tb_msg[NL80211_ATTR_WIPHY]) {
        struct airpcap_interface_list *interface;
        interface = (struct airpcap_interface_list *)malloc(sizeof(struct airpcap_interface_list));
        interface->next = NULL;
        interface->phyindex = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
        interface->ifindex = nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]);

        if (NULL == data->start) {
            data->start = data->current = interface;
        } else {
            data->current->next = interface;
            data->current = interface;
        }
    }
    return NL_OK;
}

static
int wiphy_match_handler(struct nl_msg *msg, void *data)
{
    PAirpcapHandle handle = (PAirpcapHandle)data;

    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
    struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
    struct nlattr *tb_rate[NL80211_BITRATE_ATTR_MAX + 1];

    struct nlattr *nl_band;
    struct nlattr *nl_freq;
    struct nlattr *nl_rate;
    
    /* struct nlattr *nl_mode; */
    /* struct nlattr *nl_cmd; */

    /* Policy for parsing NL80211_FREQUENCY attribute */
    static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
        [NL80211_FREQUENCY_ATTR_FREQ]         = { .type = NLA_U32 },
        [NL80211_FREQUENCY_ATTR_DISABLED]     = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_PASSIVE_SCAN] = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_NO_IBSS]      = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_RADAR]        = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
    };
    /* Policy for parsing NL80211_BITRATE attribute */
    static struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
        [NL80211_BITRATE_ATTR_RATE]               = { .type = NLA_U32 },
        [NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] = { .type = NLA_FLAG },
    };

    int bandidx;
    /* remaining items for nla_for_each_nested */
    int band_rem, freq_rem, rate_rem;//, mode_rem, cmd_rem;

    /* parse the generic netlink reply. */
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb_msg, NL80211_ATTR_MAX,
              genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0),
              NULL);

    if (NULL == tb_msg[NL80211_ATTR_WIPHY]) {
        return NL_SKIP;
    }

    unsigned int match_index = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
    if (match_index != handle->phyindex) {
        printf("not this wiphy! expected %d, matched %d\n",
               handle->phyindex,
               match_index);
        return NL_SKIP;
    }

    /* Ignore this result if there is no band data.
     * Why we'd hit this condition... no idea. */
    if (NULL == tb_msg[NL80211_ATTR_WIPHY_BANDS]) {
        return NL_SKIP;
    }

    handle->channel_info_count = 0;
    int freq_count = 0;

    nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], band_rem) {
        struct nlattr *tb_band_freqs;

        nla_parse(tb_band, NL80211_BAND_ATTR_MAX,
                  nla_data(nl_band),
                  nla_len(nl_band),
                  NULL);

        /* Loop through NL80211_BAND_ATTR_FREQS once to
         * get AirpcapChannelInfo array allocation size.
         * Inefficient, but we only do it once. */
        tb_band_freqs = tb_band[NL80211_BAND_ATTR_FREQS];
        nla_for_each_nested(nl_freq, tb_band_freqs, freq_rem) {
            nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
                      nla_data(nl_freq),
                      nla_len(nl_freq),
                      freq_policy);
            /* Ignore disabled frequencies (e.g., due to regulatory
             * domain issues. */
            if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
                continue;
            handle->channel_info_count++;
        }
    }


    handle->channel_info =                                              \
        (AirpcapChannelInfo *)malloc(sizeof(AirpcapChannelInfo) * handle->channel_info_count);
    
    /* FIXME: how to set error from here? */
    if (NULL == handle->channel_info) {
        fprintf(stderr, "Unable to allocate AirpcapChannelInfo\n");
        return NL_SKIP;
    }

    bandidx = 1;
    nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], band_rem) {
        uint32_t frequency;
        struct nlattr *tb_band_freqs;

        nla_parse(tb_band, NL80211_BAND_ATTR_MAX,
                  nla_data(nl_band),
                  nla_len(nl_band),
                  NULL);

        /* If we have an BAND_ATTR_HT_CAPA attribute, then
         * we are 802.11n capable. */
        if (tb_band[NL80211_BAND_ATTR_HT_CAPA]) {
            handle->cap.SupportedMedia |= AIRPCAP_MEDIUM_802_11_N;
        }
        nla_for_each_nested(nl_rate, tb_band[NL80211_BAND_ATTR_RATES], rate_rem) {
            uint32_t rate;
            nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX,
                      nla_data(nl_rate),
                      nla_len(nl_rate),
                      rate_policy);

            if (NULL == tb_rate[NL80211_BITRATE_ATTR_RATE])
                continue;

            /* If we support bit rates > 11.0 Kbps, we definitely
             * support 802.11g. Not quite sure how to be sure
             * that 802.11a or 802.11b modulations are supported... */
            rate = nla_get_u32(tb_rate[NL80211_BITRATE_ATTR_RATE]);
            if (rate > 110) { /* kbps */
                handle->cap.SupportedMedia |= AIRPCAP_MEDIUM_802_11_G;
            }
        }
        
        /* HT capable? */
        handle->cap.SupportedMedia |= AIRPCAP_MEDIUM_802_11_B;

        tb_band_freqs = tb_band[NL80211_BAND_ATTR_FREQS];
        nla_for_each_nested(nl_freq, tb_band_freqs, freq_rem) {
            PAirpcapChannelInfo info;

            nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
                      nla_data(nl_freq),
                      nla_len(nl_freq),
                      freq_policy);

            if (NULL == tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
                continue;
            /* Ignore disabled frequencies (e.g., due to regulatory
             * domain issues. */
            if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
                continue;

            frequency = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
            
            info = &handle->channel_info[freq_count];
            info->Frequency = (UINT)frequency;
            /* TODO */
            info->ExtChannel = 0;
            info->Flags = 0;
            /* Must be {0, 0} according to airpcap docs */
            memset(info->Reserved, 0, sizeof(info->Reserved));
            freq_count++;

            /* Add SupportedBands based on parsed frequencies. */
            if (frequency >= 2412 && frequency <= 2484) {
                handle->cap.SupportedBands |= AIRPCAP_BAND_2GHZ;
            } else if (frequency >= 4915 && frequency <= 5825) {
                handle->cap.SupportedBands |= AIRPCAP_BAND_5GHZ;
            }
        }
    }

    handle->cap.AdapterModelName = "nl80211-compatible PHY";
    /* TODO: how to figure this out from the driver?
     * Do we really need to fill this information in? */
    handle->cap.AdapterBus = AIRPCAP_BUS_PCI_EXPRESS;
    /* How is this exposed in NL80211? */
    handle->cap.CanTransmit = TRUE;
    /* There is no way to set the transmit power in NL80211. */
    handle->cap.CanSetTransmitPower = FALSE;
    handle->cap.ExternalAntennaPlug = FALSE; // unknown

    /* Identify what kind of "Airpcap" we are by our existing
     * capabilities (e.g., transmit and 802.11n support).
     */
    if (handle->cap.SupportedMedia & AIRPCAP_MEDIUM_802_11_N) {
        handle->cap.AdapterId = \
            handle->cap.CanTransmit ? AIRPCAP_ID_NX : AIRPCAP_ID_N;
    } else {
        handle->cap.AdapterId = \
            handle->cap.CanTransmit ? AIRPCAP_ID_TX : AIRPCAP_ID_CLASSIC;
    }
    
    return NL_SKIP;
}

/* Adapted from hostapd/src/drivers/driver_nl80211.c. */
static int
nl_send_and_recv(struct nl_sock *sock,
                 struct nl_msg *msg,
                 nl_recvmsg_msg_cb_t valid_handler,
                 //int (*valid_handler)(struct nl_msg *, void *),
                 void *valid_data_ptr)
{
    struct nl_cb *cb;
    int err = 0;

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (NULL == cb) {
        goto send_and_recv_done;
    }

    err = nl_send_auto_complete(sock, msg);
    if (err < 0)
        goto send_and_recv_done;

    err = 1;

    /* Register a handler for error events. */
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    /* Register a handler for finish events. */
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    /* Register a handler for ACK events. */
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    if (valid_handler) {
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
                  valid_handler, valid_data_ptr);
    }

    while (err > 0) {
        nl_recvmsgs(sock, cb);
    }

send_and_recv_done:
    nl_cb_put(cb);
    nlmsg_free(msg);

    return err;
}

static int
nl80211_get_wiphy(struct nl_sock *sock,
                  struct genl_family *family,
                  PAirpcapHandle handle)
{
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        setebuf(handle->last_error, "Error allocating netlink message.");
        return -1;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
                genl_family_get_id(family), 0,
                /* Get ALL wireless PHY information. */
                0, NL80211_CMD_GET_WIPHY, 0);

    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, handle->phyindex);
    
    int err = nl_send_and_recv(sock, msg, wiphy_match_handler, handle);
    if (err < 0) {
        setebuf(handle->last_error, "Error getting wiphy information from netlink.");
        return -1;
    }
    return 0;

nla_put_failure:
    setebuf(handle->last_error, "NL80211_GET_WIPHY: Error in NLA_PUT_U32.");
    return -1;
}
    
static int
nl80211_device_init(PAirpcapHandle handle, PCHAR Ebuf)
{
    int err;
    struct nl_msg *msg;

    msg = nlmsg_alloc();
    if (!msg) {
        setebuf(Ebuf, "Error allocating netlink message.");
        return -1;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
                genl_family_get_id(handle->nl80211), 0,
                /* Get wireless PHY information. */
                /* Why does iw set NLM_F_DUMP here and
                 * still get only one interface?
                 * Even if I do NLM_F_MATCH with
                 * NL80211_ATTR_IFINDEX, I get every
                 * PHY.  Only 0 works here... */
                0, NL80211_CMD_GET_INTERFACE, 0);

    /* We refer to the device by its interface index, not by
     * the PHY interface. */
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, handle->ifindex);

    struct airpcap_interface_dump_data data;
    data.start = NULL;
    data.current = NULL;
    
    err = nl_send_and_recv(handle->nl_socket, msg,
                           interface_dump_handler, &data);
    if (err < 0) {
        setebuf(Ebuf, "Error getting device information from netlink: %s",
                strerror(-err));
    }
    if (NULL == data.start) {
        printf("No matching wiphy...\n");
    } else {
        struct airpcap_interface_list *iface = data.start;
        handle->phyindex = iface->phyindex;
        
        if (0 != nl80211_get_wiphy(handle->nl_socket,
                                   handle->nl80211,
                                   handle)) {
            /* TODO: free memory */
            printf("error getting wiphy: %s\n", handle->last_error);
        }
    }
    /* TODO : NL80211_CMD_GET_STATION for NL80211_ATTR_WIPHY_FREQ ? */

    return err;
}

#ifdef USE_VIRTUAL_INTERFACES

static
int cmd_new_interface_handler(struct nl_msg *msg UNUSED, void *data UNUSED)
{
    return NL_SKIP;
}
static
int cmd_del_interface_handler(struct nl_msg *msg UNUSED, void *data UNUSED)
{
    return NL_SKIP;
}

/* adapted (lifted) from lorcon2 nl80211_create_vap */
static
int nl80211_create_monitor(PAirpcapHandle handle, PCHAR Ebuf)
{
    struct nl_msg *msg;
    int err;

    /* Check if this interface already exists. */
    handle->monitor_ifindex = if_nametoindex(handle->monitor_ifname);
    if (0 != handle->monitor_ifindex) {
        /* TODO: Check to make sure it is the correct wiphy and
         * already in IFTYPE_MONITOR */
        return 0;
    }
    
    msg = nlmsg_alloc();
    if (NULL == msg) {
        setebuf(Ebuf, "Failed to allocate netlink message.");
        return -1;
    }
    
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
                genl_family_get_id(handle->nl80211), 0, 0, 
                NL80211_CMD_NEW_INTERFACE, 0);

    NLA_PUT_U32(msg,    NL80211_ATTR_IFINDEX, handle->ifindex);
    NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, handle->monitor_ifname);
    NLA_PUT_U32(msg,    NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

    err = nl_send_and_recv(handle->nl_socket, msg,
                           cmd_new_interface_handler,
                           NULL);

    /* PROTIP: If you get -ENFILE (-23 / Too many open files in system),
     * it's (likely) because the interface already exists.
     * Why doesn't it return -EEXIST?!
     */
    if (err < 0) {
    nla_put_failure:
        setebuf(Ebuf, "Failed to create monitor interface %s from %s: %s",
                handle->monitor_ifname,
                handle->master_ifname,
                strerror(-err));
        return -1;
    }

    /* Save this ifindex */
    handle->monitor_ifindex = if_nametoindex(handle->monitor_ifname);
    if (0 == handle->monitor_ifindex) {
        setebuf(Ebuf,
                "nl80211_create_monitor() thought we made a "
                "monitor interface, but it wasn't there when we looked");
        return -1;
    }
    
    return 0;
}


static
int nl80211_destroy_monitor(PAirpcapHandle handle)
{
    unsigned monitor_ifindex = if_nametoindex(handle->monitor_ifname);
    if (0 != monitor_ifindex) {
        /* NL80211_CMD_DEL_INTERFACE
         *  - NL80211_ATTR_IFINDEX
         */
        struct nl_msg *msg;
        int err;

        msg = nlmsg_alloc();
        if (NULL == msg) {
            setebuf(handle->last_error, "Failed to allocate netlink message.");
            return -1;
        }
    
        genlmsg_put(msg, 0, 0,//NL_AUTO_PID, NL_AUTO_SEQ,
                    genl_family_get_id(handle->nl80211), 0, 0, 
                    NL80211_CMD_DEL_INTERFACE, 0);

        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, monitor_ifindex);

        err = nl_send_and_recv(handle->nl_socket, msg,
                               cmd_del_interface_handler,
                               NULL);

        if (err < 0) {
        nla_put_failure:
            /* -ESRCH == "No such process"...? if ifindex cannot be found */
            setebuf(handle->last_error,
                    "Failed to delete monitor interface %s(%u): %s",
                    handle->monitor_ifname, monitor_ifindex,
                    strerror(-err));
            return -1;
        }

        handle->monitor_ifindex = 0;
        return 0;
    }
    return -2;
}
#endif

static
int cmd_set_monitor_handler(struct nl_msg *msg UNUSED, void *data UNUSED)
{
    return NL_SKIP;
}

static
int nl80211_set_monitor(PAirpcapHandle handle, PCHAR Ebuf)
{
    struct nl_msg *msg;
    int err;

    msg = nlmsg_alloc();
    if (NULL == msg) {
        setebuf(Ebuf, "Failed to allocate netlink message.");
        return -1;
    }
    
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
                genl_family_get_id(handle->nl80211), 0, 0, 
                NL80211_CMD_SET_INTERFACE, 0);

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, handle->ifindex);
    NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

    err = nl_send_and_recv(handle->nl_socket, msg,
                           cmd_set_monitor_handler,
                           NULL);

    if (err < 0) {
    nla_put_failure:
        setebuf(Ebuf, "Failed to set interface %s to monitor mode: %s",
                handle->master_ifname,
                strerror(-err));
        return -1;
    }
    
    return 0;
}

/** INTERNAL struct _AirpcapHandle allocator. */
static PAirpcapHandle
airpcap_handle_new(void)
{
    PAirpcapHandle handle;
    
    handle = (PAirpcapHandle)malloc(sizeof(struct _AirpcapHandle));
    if (NULL == handle) {
        return NULL;
    }
    memset(handle, 0, sizeof(*handle));

    return handle;
}

/** INTERNAL struct _AirpcapHandle destructor. */
static void
airpcap_handle_free(PAirpcapHandle handle)
{
    if (handle->channel_info)
        free(handle->channel_info);
    
    free(handle);
}

/* TODO:
 *   - Check if interface supports monitor mode (NL80211_ATTR_SUPPORTED_IFTYPES)
 *     at all - in GET_WIPHY? seems to make sense for it to be there.
 *   - Check if interface is NL80211_ATTR_IFTYPE
 *     NL80211_IFTYPE_MONITOR (use NL80211_CMD_GET_INTERFACE)
 *   - If interface is NOT IFTYPE_MONITOR, search all interfaces
 *     for the same WIPHY index, maybe with NLM_F_DUMP and try to find
 *     an existing one.
 *     Add a flag in AirpcapHandle internally to make this easier?
 *   - If no monitor interface is defined, create one.
 *     Attempt to destroy monitor interface on close? onexit()?
 */
PAirpcapHandle AirpcapOpen(PCHAR DeviceName, PCHAR Ebuf)
{
    PAirpcapHandle handle;

    if (NULL != Ebuf) {
        Ebuf[0] = 0;
    }

    unsigned ifindex = if_nametoindex((char *)DeviceName);
    if (ifindex <= 0) {
        setebuf(Ebuf, "Invalid device specified.");
        return NULL;
    }

    handle = airpcap_handle_new();
    if (NULL == handle) {
        setebuf(Ebuf, "Error allocating handle.");
        return NULL;
    }
    /* Assign interface index after allocation. */
    handle->ifindex = ifindex;
    /* FIXME: handle if name + "mon" is too long for IF_NAMESIZE. */
    strncpy(handle->master_ifname, DeviceName, IF_NAMESIZE);
    
    /* Initialize unique netlink/nl80211 connection and
     * state for this handle. */
    if (-1 == nl80211_state_init(handle, Ebuf)) {
        return NULL;
    }
    /* FIXME: proper deallocation. */
    if (-1 == nl80211_device_init(handle, Ebuf)) {
        return NULL;
    }
    /* if (-1 == nl80211_create_monitor(handle, Ebuf)) { */
    /*     return NULL; */
    /* } */
    if (-1 == nl80211_set_monitor(handle, Ebuf)) {
        return NULL;
    }

    if (FALSE == AirpcapSetDeviceChannel(handle, 6)) {
        /* We might as well just call close here, since
         * all state is essentially allocated and ready.
         */
        strncpy(Ebuf, handle->last_error, AIRPCAP_ERRBUF_SIZE);
        AirpcapClose(handle);
        return NULL;
    }

    return handle;
}

static
void nl80211_state_free(PAirpcapHandle handle)
{
    if (handle) {
        nl_cb_put(handle->nl_cb);
        genl_family_put(handle->nl80211);
        nl_cache_free(handle->nl_cache);
        nl_socket_free(handle->nl_socket);
    }
}

VOID AirpcapClose(PAirpcapHandle AdapterHandle)
{
    if (NULL != AdapterHandle) {
        /* For now, don't destroy the monitor, to allow phyNmon interfaces
         * to persist after AirpcapClose. Perhaps add a libairpcap-nl API call
         * to destroy the VIF? lorcon does not destroy the interface, in any
         * case. */
        //nl80211_destroy_monitor(AdapterHandle);
        nl80211_state_free(AdapterHandle);
        if (AdapterHandle->rtnl_link_cache)
            nl_cache_free(AdapterHandle->rtnl_link_cache);

        airpcap_handle_free(AdapterHandle);
    }
}

PCHAR AirpcapGetLastError(PAirpcapHandle AdapterHandle)
{
    PCHAR ret = NULL;
    if (AdapterHandle) {
        ret = AdapterHandle->last_error;
    }
    return ret;
}

static PAirpcapDeviceDescription
nl80211_get_all_devices(PCHAR Ebuf)
{
    int err;
    struct nl_msg *msg;
    struct nl_sock *sock = NULL;
    struct nl_cache *cache;
    struct genl_family *nl80211;
    PAirpcapDeviceDescription desc_start = NULL, desc_current;

    sock = nl_socket_alloc();
    /* Allocate the netlink socket.
     */
    if (NULL == sock) {
        setebuf(Ebuf, "Failed to allocate netlink socket.");
        goto err;
    }
    /* Connect to the generic netlink.
     */
    if (genl_connect(sock)) {
        setebuf(Ebuf, "Failed to connect to generic netlink.");
        goto err;
    }
    if (genl_ctrl_alloc_cache(sock, &cache)) {
        setebuf(Ebuf, "Failed to allocate generic netlink cache.");
        goto err;
    }

    /* Find and get a reference to the nl80211 family.
     * Must hand back the reference via genl_family_put. */
    nl80211 = genl_ctrl_search_by_name(cache, "nl80211");
    if (NULL == nl80211) {
        setebuf(Ebuf, "Netlink module nl80211 not found.");
        goto err;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        setebuf(Ebuf, "Error allocating netlink message.");
        goto err;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
                genl_family_get_id(nl80211), 0,
                /* Get ALL wireless PHY information. */
                NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, 0);

    /* Build up the list */
    struct airpcap_interface_dump_data data;
    data.start   = NULL;
    data.current = NULL;

    err = nl_send_and_recv(sock, msg, interface_dump_handler, &data);
    if (err < 0) {
        setebuf(Ebuf, "Error getting interface information from netlink: %s",
                strerror(-err));
    }

    for (struct airpcap_interface_list *iface = data.start; iface; iface = iface->next) {
        PAirpcapDeviceDescription desc;
        PAirpcapHandle temp_handle = NULL;
        char ifname[IF_NAMESIZE];
        PCHAR d;

        if (NULL == if_indextoname(iface->ifindex, ifname)) {
            printf("BAD!!!\n");
            continue;
        }

        desc = (PAirpcapDeviceDescription)malloc(sizeof(*desc));
        desc->next = NULL;

        /* Update the list */
        if (NULL == desc_start) {
            desc_start = desc_current = desc;
        } else {
            desc_current->next = desc;
            desc_current = desc;
        }

        temp_handle = airpcap_handle_new();
        temp_handle->phyindex = iface->phyindex;
        if (0 != nl80211_get_wiphy(sock, nl80211, temp_handle)) {
            /* TODO: free memory, etc... */
            printf("error getting wiphy: %s\n", temp_handle->last_error);
            strncpy(Ebuf, temp_handle->last_error, AIRPCAP_ERRBUF_SIZE);
            return NULL;
        }

        desc->Name = strndup(ifname, IF_NAMESIZE);
        desc->Description = (PCHAR)malloc(512);
        
        /* Assign Description member based on what
         * Airpcap device we are going to "emulate".
         *
         * This should hopefully someday be filled in with better
         * information about the adapter or driver from the
         * mac80211 / nl80211 layer. */
        switch (temp_handle->cap.AdapterId) {
        case AIRPCAP_ID_N:
        case AIRPCAP_ID_NX:
            d = "Airpcap NX emulation (802.11n)";
            break;

        case AIRPCAP_ID_TX:
            d = "Airpcap TX emulation (802.11bg)";
            break;

        case AIRPCAP_ID_CLASSIC:
            d = "Airpcap Classic emulation (802.11bg)";
            break;

        default:
            d = "BUG: Unspecified Airpcap emulation";
            break;
        }

        strncpy(desc->Description, d, 512);
        if (temp_handle->cap.SupportedBands & AIRPCAP_BAND_5GHZ) {
            size_t s = strlen(desc->Description);
            strncat(desc->Description,
                    " (5 GHz)", 512 - s);
        }
        /* Free the temporary handle. */
        airpcap_handle_free(temp_handle);
    }

err:
    if (nl80211)
        genl_family_put(nl80211);
    if (cache)
        nl_cache_free(cache);
    if (sock)
        nl_socket_free(sock);

    if (err < 0) {
        return NULL;
    } else {
        return desc_start;
    }
}

BOOL AirpcapGetDeviceList(PAirpcapDeviceDescription *PPAllDevs,
                          PCHAR Ebuf)
{
    BOOL ret = FALSE;
    if (PPAllDevs) {
        *PPAllDevs = nl80211_get_all_devices(Ebuf);
        ret = TRUE;
    }
    return ret;
}

VOID AirpcapFreeDeviceList(PAirpcapDeviceDescription PAllDevs)
{
    PAirpcapDeviceDescription next = NULL;

    while (PAllDevs) {
        next = PAllDevs->next;

        free(PAllDevs->Name);
        free(PAllDevs->Description);
        free(PAllDevs);

        PAllDevs = next;
    }
}

BOOL AirpcapSetDeviceChannel(PAirpcapHandle AdapterHandle,
                             UINT Channel)
{
    BOOL ret = FALSE;

    /* To share common code, we (attempt to) convert Channel to
     * its frequency.  We then call into AirpcapSetDeviceChannelEx,
     * assuming 20 MHz mode is desired.
     */
    if (AdapterHandle) {
        UINT freq;
        if(FALSE == AirpcapConvertChannelToFrequency(Channel, &freq)) {
            setebuf(AdapterHandle->last_error, "Invalid channel %u.", Channel);
            ret = FALSE;
        } else {
            AirpcapChannelInfo info;
            info.Frequency  = freq;
            info.ExtChannel = 0; /* Force 20 MHz mode (HT20 or legacy) */
            info.Flags      = 0; /* TODO: AIRPCAP_CIF_TX_ENABLED? */
            /* Should be set to {0,0} */
            info.Reserved[0] = 0;
            info.Reserved[1] = 0;

            ret = AirpcapSetDeviceChannelEx(AdapterHandle, info);
        }
    }

    return ret;
}

BOOL AirpcapGetDeviceChannel(PAirpcapHandle AdapterHandle, PUINT PChannel)
{
    BOOL ret = FALSE;
    if (AdapterHandle) {
        ret = TRUE;
        if (PChannel) {
            BOOL ftc_ret;
            ftc_ret = AirpcapConvertFrequencyToChannel(AdapterHandle->current_channel.Frequency,
                                                       PChannel, NULL);
            if (FALSE == ftc_ret) {
                setebuf(AdapterHandle->last_error,
                        "Internal error converting last channel frequency. Report a bug.");
                ret = FALSE;
            }
        }
    }
    return ret;
}

static
int cmd_set_channel_handler(struct nl_msg *msg UNUSED, void *data UNUSED)
{
    return NL_SKIP;
}

BOOL AirpcapSetDeviceChannelEx(PAirpcapHandle AdapterHandle,
                               AirpcapChannelInfo ChannelInfo)
{
/* @NL80211_CMD_SET_CHANNEL: Set the channel (using %NL80211_ATTR_WIPHY_FREQ
 *	and %NL80211_ATTR_WIPHY_CHANNEL_TYPE) the given interface (identifed
 *	by %NL80211_ATTR_IFINDEX) shall operate on.
 *	In case multiple channels are supported by the device, the mechanism
 */
    BOOL ret = FALSE;
    if (AdapterHandle) {
        int err;
        uint32_t channel_type;
        struct nl_msg *msg;

        /* Select channel type for CMD_SET_CHANNEL, based
         * on the value in AirpcapChannelInfo.ExtChannel (-1, 0, 1). */
        switch (ChannelInfo.ExtChannel) {
        case 0:
            /* TODO: This should probably be NL80211_CHAN_NO_HT
             * for non-HT capture devices? Does it matter in monitor
             * mode? Experiment. */
            channel_type = NL80211_CHAN_HT20;
            break;
        case 1:
            channel_type = NL80211_CHAN_HT40PLUS;
            break;
        case -1:
            channel_type = NL80211_CHAN_HT40MINUS;
            break;
        default:
            setebuf(AdapterHandle->last_error, "Invalid ExtChannel %hhu.",
                    ChannelInfo.ExtChannel);
            return FALSE;
        }
        
        msg = nlmsg_alloc();
        if (NULL == msg) {
            setebuf(AdapterHandle->last_error, "Error allocating nlmsg.");
            return FALSE;
        }

        genlmsg_put(msg, 0,0,//NL_AUTO_PID, NL_AUTO_SEQ,
                    genl_family_get_id(AdapterHandle->nl80211), 0,
                    0,//NLM_F_MATCH,
                    NL80211_CMD_SET_WIPHY, 0);

        /* Set up CMD_SET_CHANNEL */
        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, AdapterHandle->ifindex);
        NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, ChannelInfo.Frequency);
        NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, channel_type);

        err = nl_send_and_recv(AdapterHandle->nl_socket, msg,
                               cmd_set_channel_handler, NULL);
        if (err < 0) {
        nla_put_failure:
            setebuf(AdapterHandle->last_error, "Channel change failed: %s",
                    strerror(-err));
            ret = FALSE;
        } else {
            /* Save current channel state for GetChannel(Ex). */
            memcpy(&AdapterHandle->current_channel, &ChannelInfo, sizeof(AirpcapChannelInfo));
            ret = TRUE;
        }
    }
    return ret;
}

/* Unfortunately, it does not appear that nl80211 has any method of
 * returning the current center frequency of the device.
 *
 * Also, it seems that at least on my kernel, 2.6.38-12-generic, iwlagn or
 * cfg80211's wext-compat layer lies about the current frequency.
 * I will query linux-wireless about this.
 *
 * So, for now, we simply return the last channel that was set. AirPcaps are
 * set to 6 by default, so we choose to force it to a known channel on
 * AirpcapOpen. */
BOOL AirpcapGetDeviceChannelEx(PAirpcapHandle AdapterHandle,
                               PAirpcapChannelInfo PChannelInfo)
{
    BOOL ret = FALSE;
    if (AdapterHandle) {
        memcpy(PChannelInfo, &AdapterHandle->current_channel,
               sizeof(*PChannelInfo));
        ret = TRUE;
    }
    return ret;
}

/** TODO:
 * Should this query netlink each time, or can
 * we cache it?
 */
BOOL AirpcapGetMacAddress(PAirpcapHandle AdapterHandle,
                          PAirpcapMacAddress PMacAddress)
{
    BOOL ret = FALSE;
    if (AdapterHandle && PMacAddress) {
        memcpy(PMacAddress,
               &AdapterHandle->mac,
               sizeof(*PMacAddress));
        ret = TRUE;
    }
    return ret;
}

BOOL AirpcapGetDeviceSupportedChannels(PAirpcapHandle AdapterHandle,
                                       PAirpcapChannelInfo *ppChannelInfo,
                                       PUINT pNumChannelInfo)
{
    BOOL ret = FALSE;
    if (AdapterHandle && ppChannelInfo && pNumChannelInfo) {
        *ppChannelInfo   = AdapterHandle->channel_info;
        *pNumChannelInfo = AdapterHandle->channel_info_count;
        ret = TRUE;
    }
    return ret;
}

BOOL AirpcapGetDeviceCapabilities(PAirpcapHandle AdapterHandle,
                                  PAirpcapDeviceCapabilities *PCapabilities) {
    BOOL ret = FALSE;
    if (AdapterHandle && PCapabilities) {
        *PCapabilities = &AdapterHandle->cap;
        ret = TRUE;
    }
    return ret;
}

/* AirpcapConvertFrequencyToChannel and
 * AirpcapConvertChannelToFrequency are adapted from CACE's airpcap.c.
 * 
 * Not exactly efficient, but it's unlikely this function is called in
 * code that must be performant.  If I'm wrong, please complain and I
 * will make it faster :)
 */
BOOL AirpcapConvertFrequencyToChannel(UINT Frequency,
                                      PUINT PChannel,
                                      PAirpcapChannelBand PBand)
{
    size_t fc = (sizeof(g_Channels) / sizeof(g_Channels[0]));
    for (size_t f = 0; f < fc; f++) {
        if (Frequency == g_Channels[f].Frequency) {
            if (PChannel)
                *PChannel = g_Channels[f].Channel;
            if (PBand)
                *PBand = g_Channels[f].Band;

            return TRUE;
        }
    }
    return FALSE;
}
BOOL AirpcapConvertChannelToFrequency(UINT Channel,
                                      PUINT PFrequency)
{
    size_t fc = (sizeof(g_Channels) / sizeof(g_Channels[0]));
    for (size_t f = 0; f < fc; f++) {
        if (Channel == g_Channels[f].Channel) {
            if (PFrequency)
                *PFrequency = g_Channels[f].Frequency;

            return TRUE;
        }
    }
    return FALSE;
}
