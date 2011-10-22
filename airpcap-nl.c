/* -*- mode: C; c-file-style: "k&r"; c-basic-offset: 4; indent-tabs-mode: nil; -*- */
/*
 * Airpcap library implementation for nl80211
 *
 * Copyright 2011 Harry Bock <bock.harryw@gmail.com>
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
#include <stdarg.h>
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

#ifdef CONFIG_LIBNL20
/* /\* libnl 2.0 compatibility code *\/ */
/* #define nl_handle nl_sock */
/* #define nl_handle_alloc_cb nl_socket_alloc_cb */
/* #define nl_handle_destroy nl_socket_free */
#endif /* CONFIG_LIBNL20 */

static void setebuf(PCHAR ebuf, const char *format, ...)
{
    if (ebuf) {
        va_list args;
        va_start(args, format);
        /* int message_len = strlen(msg);               */
        /* if (message_len >= AIRPCAP_ERRBUF_SIZE) {          */
        /*     message_len = AIRPCAP_ERRBUF_SIZE - 1;         */
        /* } */
        vsnprintf(ebuf, AIRPCAP_ERRBUF_SIZE, format, args);
        /* strncpy(ebuf, msg, message_len); */
        /* ebuf[message_len] = '\0';                              */
    }
}

void AirpcapGetVersion(PUINT VersionMajor,
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
get_mac_address(struct nl_cache *cache, int ifindex, BYTE *mac)
{
    struct nl_addr *addr;
    struct rtnl_link *link;
    int err = 0;

    link = rtnl_link_get(cache, ifindex);
    addr = rtnl_link_get_addr(link);

    unsigned int   link_binary_length;
    unsigned char *link_binary;
    link_binary_length = nl_addr_get_len(addr);
    link_binary        = nl_addr_get_binary_addr(addr);

    memcpy(mac, link_binary, link_binary_length);

    return err;
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

    /* Get the NETLINK_ROUTE cache; for now it's
     * the only thing we need from the route subsystem. */
    /* TODO: Move me into a global startup routine.
     * Link information (should) not change! */
    rt_sock = nl_socket_alloc();
    err = nl_connect(rt_sock, NETLINK_ROUTE);
    err = rtnl_link_alloc_cache(rt_sock, &handle->rtnl_link_cache);
    if (err < 0) {
        
        setebuf(Ebuf, "Failed to allocate NETLINK_ROUTE link cache: %s\n",
                nl_geterror(err));
        nl_close(rt_sock);
        goto err;
    }
    return get_mac_address(handle->rtnl_link_cache,
                           handle->ifindex,
                           handle->mac.Address);


    return 0;

err:
    if (handle->nl80211)
        genl_family_put(handle->nl80211);
    if (handle->nl_cache)
        nl_cache_free(handle->nl_cache);
    if (handle->nl_socket)
        nl_socket_free(handle->nl_socket);
    if (rt_sock)
        nl_socket_free(rt_sock);


    return -1;
}

static int
error_handler(struct sockaddr_nl *nla UNUSED,
              struct nlmsgerr *err,
              void *arg)
{
	int *ret = arg;
	*ret = err->error;
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

static
int wiphy_dump_handler(struct nl_msg *msg, void *data)
{
    PAirpcapHandle handle = (PAirpcapHandle)data;

    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
    struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
    struct nlattr *tb_rate[NL80211_BITRATE_ATTR_MAX + 1];

    struct nlattr *nl_band;
    struct nlattr *nl_freq;
    struct nlattr *nl_rate;
    struct nlattr *nl_mode;
    struct nlattr *nl_cmd;

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
    int band_rem, freq_rem, rate_rem, mode_rem, cmd_rem;

    /* parse the generic netlink reply. */
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb_msg, NL80211_ATTR_MAX,
              genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0),
              NULL);

    if (NULL == tb_msg[NL80211_ATTR_WIPHY_BANDS])
        return NL_SKIP;

    if (tb_msg[NL80211_ATTR_WIPHY_NAME]) {
        printf("PHY %s\n", nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]));
    }
    else {
        printf("Nuts\n");
    }

    bandidx = 1;
    nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], band_rem) {
        int freq_count;
        uint32_t frequency;
        struct nlattr *tb_band_freqs;

        nla_parse(tb_band, NL80211_BAND_ATTR_MAX,
                  nla_data(nl_band),
                  nla_len(nl_band),
                  NULL);

        tb_band_freqs = tb_band[NL80211_BAND_ATTR_FREQS];

        /* Loop through NL80211_BAND_ATTR_FREQS once to
         * get AirpcapChannelInfo array allocation size.
         * Inefficient, but we only do it once. */
        handle->channel_info_count = 0;
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
        handle->channel_info =                                          \
            (AirpcapChannelInfo *)malloc(sizeof(AirpcapChannelInfo) * handle->channel_info_count);

        /* FIXME: how to set error from here? */
        if (NULL == handle->channel_info) {
            fprintf(stderr, "Unable to allocate AirpcapChannelInfo\n");
            continue;
        }

        freq_count = 0;
        nla_for_each_nested(nl_freq, tb_band_freqs, freq_rem) {
            PAirpcapChannelInfo info = &handle->channel_info[freq_count];

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
            info->Frequency = (UINT)frequency;
            /* TODO */
            info->ExtChannel = 0;
            info->Flags = 0;
            /* Must be {0, 0, 0} according to airpcap docs */
            memset(info->Reserved, 0, sizeof(info->Reserved));
            
            freq_count++;
        }
    }

    return NL_SKIP;
}

/* Adapted from hostapd/src/drivers/driver_nl80211.c. */
static int
nl_send_and_recv(PAirpcapHandle handle,
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

    err = nl_send_auto_complete(handle->nl_socket, msg);
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
        nl_recvmsgs(handle->nl_socket, cb);
    }

send_and_recv_done:
    nl_cb_put(cb);
    nlmsg_free(msg);

    return err;
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
                /* dump all devices, get wireless PHY information. */
                NLM_F_MATCH, NL80211_CMD_GET_WIPHY, 0);

    /* We refer to the device by its interface index, not by
     * the PHY interface. */
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, handle->ifindex);

    err = nl_send_and_recv(handle, msg,
                           wiphy_dump_handler, handle);

    if (err < 0) {
        setebuf(Ebuf, "Error getting device information from netlink.");
    }

    return err;
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

PAirpcapHandle AirpcapOpen(PCHAR DeviceName, PCHAR Ebuf)
{
    PAirpcapHandle handle;

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
    
    /* Initialize unique netlink/nl80211 connection and
     * state for this handle. */
    if (-1 == nl80211_state_init(handle, Ebuf)) {
        return NULL;
    }
    /* TODO: proper deallocation. */
    if (-1 == nl80211_device_init(handle, Ebuf)) {
        return NULL;
    }

    return handle;
}

static void nl80211_state_free(PAirpcapHandle handle)
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
    if (AdapterHandle) {
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

/** STUB FUNCTION.  We have no concept of kernel buffers
 * for drivers.
 */
BOOL AirpcapSetKernelBuffer(PAirpcapHandle AdapterHandle UNUSED,
                            UINT BufferSize UNUSED)
{
    BOOL ret = FALSE;
    if (AdapterHandle) {
        ret = TRUE;
    }
    return ret;
}

/** STUB FUNCTION: Returns the default buffer size.
 * We cannot set kernel buffer size with nl80211, so
 * we pretend it is the default expected Airpcap size,
 * 1 Mbyte.
 */
BOOL AirpcapGetKernelBufferSize(PAirpcapHandle AdapterHandle UNUSED,
                                PUINT PSizeBytes)
{
    BOOL ret = FALSE;
    if (AdapterHandle) {
        if (PSizeBytes) {
            *PSizeBytes = AIRPCAP_DEFAULT_KERNEL_BUFFER_SIZE;
        }
        ret = TRUE;
    }

    return ret;
}

/** STUB function:
 * return TRUE unless AdapterHandle is NULL. */
BOOL AirpcapSetMinToCopy(PAirpcapHandle AdapterHandle UNUSED,
                         UINT MinToCopy UNUSED)
{
    BOOL ret = FALSE;
    if (AdapterHandle) {
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

BOOL AirpcapGetLedsNumber(PAirpcapHandle AdapterHandle,
                          PUINT NumberOfLeds)
{
    BOOL ret = FALSE;

    if (AdapterHandle && NumberOfLeds) {
        *NumberOfLeds = AdapterHandle->led_count;
        ret = TRUE;
    }

    return ret;
}

/** TODO:
 * is there an LED interface? I know ath9k knows about the
 * LEDs on USB adapters like those made by TP-LINK.
 */
BOOL AirpcapTurnLedOn(PAirpcapHandle AdapterHandle UNUSED,
                      UINT LedNumber UNUSED)
{
    return FALSE;
}
BOOL AirpcapTurnLedOff(PAirpcapHandle AdapterHandle UNUSED,
                       UINT LedNumber UNUSED)
{
    return FALSE;
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
