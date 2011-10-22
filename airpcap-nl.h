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
#ifndef __APCAP_AIRPCAP_NL_H

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/netlink.h>

const UINT AIRPCAP_DEFAULT_KERNEL_BUFFER_SIZE = 1024000;

struct _AirpcapHandle {
    /* Internal netlink state. */
    struct nl_sock     *nl_socket;
    struct nl_cache    *nl_cache;
    struct genl_family *nl80211;
    struct nl_cb       *nl_cb;
    struct nl_handle   *nl_handle;

    /* NETLINK_ROUTE interface link cache. */
    struct nl_cache *rtnl_link_cache;

    /* Interface index (net/if.h:if_nametoindex(3)) */
    unsigned ifindex;

    /* Airpcap parameters. */
    CHAR last_error[AIRPCAP_ERRBUF_SIZE];

    AirpcapMacAddress mac;
    /* For AirpcapGetLedsNumber */
    UINT led_count;
    AirpcapChannelInfo *channel_info;
    UINT channel_info_count;
};

#define UNUSED __attribute__((unused))

#endif /* __APCAP_AIRPCAP_NL_H */
