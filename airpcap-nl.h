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
#ifndef __AIRPCAP_NL_H__
#define __AIRPCAP_NL_H__

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/netlink.h>

#include "airpcap-nl-config.h"

#ifdef CONFIG_LIBNL20
/* libnl 2.0 compatibility code, because UNIX APIs are never
 * stable. This is ridiculous. */
#define nl_handle nl_sock
#define nl_handle_alloc nl_socket_alloc
#define nl_handle_destroy nl_socket_free

#else

static inline int __genl_ctrl_alloc_cache(struct nl_handle *h, struct nl_cache **cache) {
	struct nl_cache *tmp = genl_ctrl_alloc_cache(h);
	if (!tmp)
		return -1;
	*cache = tmp;
	return 0;
}
#define genl_ctrl_alloc_cache __genl_ctrl_alloc_cache

#endif /* CONFIG_LIBNL20 */

#define AIRPCAP_DEFAULT_KERNEL_BUFFER_SIZE 1024000

struct _AirpcapHandle {
    /* Internal netlink state. */
    struct nl_handle     *nl_socket;
    struct nl_cache    *nl_cache;
    struct genl_family *nl80211;
    struct nl_cb       *nl_cb;
    struct nl_handle   *nl_handle;

    /* NETLINK_ROUTE interface link cache. */
    struct nl_cache *rtnl_link_cache;

    /* Interface index (net/if.h:if_nametoindex(3)) */
    unsigned ifindex;
    unsigned monitor_ifindex;
    unsigned int phyindex;

    /* FIXME: Is the phy ifname bounded by IFNAMSIZ? */
    char phy_ifname[IFNAMSIZ];
    char master_ifname[IFNAMSIZ];
    char monitor_ifname[IFNAMSIZ];

    /* Airpcap parameters. */
    CHAR last_error[AIRPCAP_ERRBUF_SIZE];
    
    AirpcapDeviceCapabilities cap;
    AirpcapMacAddress mac;
    /* For AirpcapGetLedsNumber */
    UINT led_count;
    AirpcapChannelInfo *channel_info;
    UINT channel_info_count;

    UINT current_tx_power;
    AirpcapChannelInfo current_channel;
    AirpcapValidationType validation;
};

#define UNUSED __attribute__((unused))

struct AirpcapAdapterChannelInfoPrivate {
	uint32_t max_tx_power; /* nl80211 uses units of mBm (100 * dBm value) */
};

/* From CACE airpcap-int.h.
 * Somewhat ugly, but better than re-inventing the
 * wheel for now. */
typedef struct _AirpcapInternalChannelInfo
{
	ULONG				Frequency;
	UINT				Channel;
	AirpcapChannelBand	Band;
}
AirpcapInternalChannelInfo;
//
// Channel conversion table
//
static const AirpcapInternalChannelInfo g_Channels[] =
{
	//
	// BG
	//
	// Frequency = 2407 + 5 * Channel  Except Channel 14 = 2484
	{2412,  1, AIRPCAP_CB_2_4_GHZ},		
	{2417,  2, AIRPCAP_CB_2_4_GHZ},
	{2422,  3, AIRPCAP_CB_2_4_GHZ},
	{2427,  4, AIRPCAP_CB_2_4_GHZ},
	{2432,  5, AIRPCAP_CB_2_4_GHZ},
	{2437,  6, AIRPCAP_CB_2_4_GHZ},
	{2442,  7, AIRPCAP_CB_2_4_GHZ},
	{2447,  8, AIRPCAP_CB_2_4_GHZ},
	{2452,  9, AIRPCAP_CB_2_4_GHZ},
	{2457, 10, AIRPCAP_CB_2_4_GHZ},
	{2462, 11, AIRPCAP_CB_2_4_GHZ},
	{2467, 12, AIRPCAP_CB_2_4_GHZ},
	{2472, 13, AIRPCAP_CB_2_4_GHZ},
	{2484, 14, AIRPCAP_CB_2_4_GHZ},

	//
	// A
	//
	// Frequency = 5000 + 5 * Channel  where Channel >= 0 && Channel < 240
	{5000,   0, AIRPCAP_CB_5_GHZ},
	{5005,   1, AIRPCAP_CB_5_GHZ},
	{5010,   2, AIRPCAP_CB_5_GHZ},
	{5015,   3, AIRPCAP_CB_5_GHZ},
	{5020,   4, AIRPCAP_CB_5_GHZ},
	{5025,   5, AIRPCAP_CB_5_GHZ},
	{5030,   6, AIRPCAP_CB_5_GHZ},
	{5035,   7, AIRPCAP_CB_5_GHZ},
	{5040,   8, AIRPCAP_CB_5_GHZ},
	{5045,   9, AIRPCAP_CB_5_GHZ},
	{5050,  10, AIRPCAP_CB_5_GHZ},
	{5055,  11, AIRPCAP_CB_5_GHZ},
	{5060,  12, AIRPCAP_CB_5_GHZ},
	{5065,  13, AIRPCAP_CB_5_GHZ},
	{5070,  14, AIRPCAP_CB_5_GHZ},
	{5075,  15, AIRPCAP_CB_5_GHZ},
	{5080,  16, AIRPCAP_CB_5_GHZ},
	{5085,  17, AIRPCAP_CB_5_GHZ},
	{5090,  18, AIRPCAP_CB_5_GHZ},
	{5095,  19, AIRPCAP_CB_5_GHZ},

	{5100,  20, AIRPCAP_CB_5_GHZ},
	{5105,  21, AIRPCAP_CB_5_GHZ},
	{5110,  22, AIRPCAP_CB_5_GHZ},
	{5115,  23, AIRPCAP_CB_5_GHZ},
	{5120,  24, AIRPCAP_CB_5_GHZ},
	{5125,  25, AIRPCAP_CB_5_GHZ},
	{5130,  26, AIRPCAP_CB_5_GHZ},
	{5135,  27, AIRPCAP_CB_5_GHZ},
	{5140,  28, AIRPCAP_CB_5_GHZ},
	{5145,  29, AIRPCAP_CB_5_GHZ},
	{5150,  30, AIRPCAP_CB_5_GHZ},
	{5155,  31, AIRPCAP_CB_5_GHZ},
	{5160,  32, AIRPCAP_CB_5_GHZ},
	{5165,  33, AIRPCAP_CB_5_GHZ},
	{5170,  34, AIRPCAP_CB_5_GHZ},
	{5175,  35, AIRPCAP_CB_5_GHZ},
	{5180,  36, AIRPCAP_CB_5_GHZ},
	{5185,  37, AIRPCAP_CB_5_GHZ},
	{5190,  38, AIRPCAP_CB_5_GHZ},
	{5195,  39, AIRPCAP_CB_5_GHZ},

	{5200,  40, AIRPCAP_CB_5_GHZ},
	{5205,  41, AIRPCAP_CB_5_GHZ},
	{5210,  42, AIRPCAP_CB_5_GHZ},
	{5215,  43, AIRPCAP_CB_5_GHZ},
	{5220,  44, AIRPCAP_CB_5_GHZ},
	{5225,  45, AIRPCAP_CB_5_GHZ},
	{5230,  46, AIRPCAP_CB_5_GHZ},
	{5235,  47, AIRPCAP_CB_5_GHZ},
	{5240,  48, AIRPCAP_CB_5_GHZ},
	{5245,  49, AIRPCAP_CB_5_GHZ},
	{5250,  50, AIRPCAP_CB_5_GHZ},
	{5255,  51, AIRPCAP_CB_5_GHZ},
	{5260,  52, AIRPCAP_CB_5_GHZ},
	{5265,  53, AIRPCAP_CB_5_GHZ},
	{5270,  54, AIRPCAP_CB_5_GHZ},
	{5275,  55, AIRPCAP_CB_5_GHZ},
	{5280,  56, AIRPCAP_CB_5_GHZ},
	{5285,  57, AIRPCAP_CB_5_GHZ},
	{5290,  58, AIRPCAP_CB_5_GHZ},
	{5295,  59, AIRPCAP_CB_5_GHZ},

	{5300,  60, AIRPCAP_CB_5_GHZ},
	{5305,  61, AIRPCAP_CB_5_GHZ},
	{5310,  62, AIRPCAP_CB_5_GHZ},
	{5315,  63, AIRPCAP_CB_5_GHZ},
	{5320,  64, AIRPCAP_CB_5_GHZ},
	{5325,  65, AIRPCAP_CB_5_GHZ},
	{5330,  66, AIRPCAP_CB_5_GHZ},
	{5335,  67, AIRPCAP_CB_5_GHZ},
	{5340,  68, AIRPCAP_CB_5_GHZ},
	{5345,  69, AIRPCAP_CB_5_GHZ},
	{5350,  70, AIRPCAP_CB_5_GHZ},
	{5355,  71, AIRPCAP_CB_5_GHZ},
	{5360,  72, AIRPCAP_CB_5_GHZ},
	{5365,  73, AIRPCAP_CB_5_GHZ},
	{5370,  74, AIRPCAP_CB_5_GHZ},
	{5375,  75, AIRPCAP_CB_5_GHZ},
	{5380,  76, AIRPCAP_CB_5_GHZ},
	{5385,  77, AIRPCAP_CB_5_GHZ},
	{5390,  78, AIRPCAP_CB_5_GHZ},
	{5395,  79, AIRPCAP_CB_5_GHZ},

	{5400,  80, AIRPCAP_CB_5_GHZ},
	{5405,  81, AIRPCAP_CB_5_GHZ},
	{5410,  82, AIRPCAP_CB_5_GHZ},
	{5415,  83, AIRPCAP_CB_5_GHZ},
	{5420,  84, AIRPCAP_CB_5_GHZ},
	{5425,  85, AIRPCAP_CB_5_GHZ},
	{5430,  86, AIRPCAP_CB_5_GHZ},
	{5435,  87, AIRPCAP_CB_5_GHZ},
	{5440,  88, AIRPCAP_CB_5_GHZ},
	{5445,  89, AIRPCAP_CB_5_GHZ},
	{5450,  90, AIRPCAP_CB_5_GHZ},
	{5455,  91, AIRPCAP_CB_5_GHZ},
	{5460,  92, AIRPCAP_CB_5_GHZ},
	{5465,  93, AIRPCAP_CB_5_GHZ},
	{5470,  94, AIRPCAP_CB_5_GHZ},
	{5475,  95, AIRPCAP_CB_5_GHZ},
	{5480,  96, AIRPCAP_CB_5_GHZ},
	{5485,  97, AIRPCAP_CB_5_GHZ},
	{5490,  98, AIRPCAP_CB_5_GHZ},
	{5495,  99, AIRPCAP_CB_5_GHZ},

	{5500, 100, AIRPCAP_CB_5_GHZ},
	{5505, 101, AIRPCAP_CB_5_GHZ},
	{5510, 102, AIRPCAP_CB_5_GHZ},
	{5515, 103, AIRPCAP_CB_5_GHZ},
	{5520, 104, AIRPCAP_CB_5_GHZ},
	{5525, 105, AIRPCAP_CB_5_GHZ},
	{5530, 106, AIRPCAP_CB_5_GHZ},
	{5535, 107, AIRPCAP_CB_5_GHZ},
	{5540, 108, AIRPCAP_CB_5_GHZ},
	{5545, 109, AIRPCAP_CB_5_GHZ},
	{5550, 110, AIRPCAP_CB_5_GHZ},
	{5555, 111, AIRPCAP_CB_5_GHZ},
	{5560, 112, AIRPCAP_CB_5_GHZ},
	{5565, 113, AIRPCAP_CB_5_GHZ},
	{5570, 114, AIRPCAP_CB_5_GHZ},
	{5575, 115, AIRPCAP_CB_5_GHZ},
	{5580, 116, AIRPCAP_CB_5_GHZ},
	{5585, 117, AIRPCAP_CB_5_GHZ},
	{5590, 118, AIRPCAP_CB_5_GHZ},
	{5595, 119, AIRPCAP_CB_5_GHZ},

	{5600, 120, AIRPCAP_CB_5_GHZ},
	{5605, 121, AIRPCAP_CB_5_GHZ},
	{5610, 122, AIRPCAP_CB_5_GHZ},
	{5615, 123, AIRPCAP_CB_5_GHZ},
	{5620, 124, AIRPCAP_CB_5_GHZ},
	{5625, 125, AIRPCAP_CB_5_GHZ},
	{5630, 126, AIRPCAP_CB_5_GHZ},
	{5635, 127, AIRPCAP_CB_5_GHZ},
	{5640, 128, AIRPCAP_CB_5_GHZ},
	{5645, 129, AIRPCAP_CB_5_GHZ},
	{5650, 130, AIRPCAP_CB_5_GHZ},
	{5655, 131, AIRPCAP_CB_5_GHZ},
	{5660, 132, AIRPCAP_CB_5_GHZ},
	{5665, 133, AIRPCAP_CB_5_GHZ},
	{5670, 134, AIRPCAP_CB_5_GHZ},
	{5675, 135, AIRPCAP_CB_5_GHZ},
	{5680, 136, AIRPCAP_CB_5_GHZ},
	{5685, 137, AIRPCAP_CB_5_GHZ},
	{5690, 138, AIRPCAP_CB_5_GHZ},
	{5695, 139, AIRPCAP_CB_5_GHZ},

	{5700, 140, AIRPCAP_CB_5_GHZ},
	{5705, 141, AIRPCAP_CB_5_GHZ},
	{5710, 142, AIRPCAP_CB_5_GHZ},
	{5715, 143, AIRPCAP_CB_5_GHZ},
	{5720, 144, AIRPCAP_CB_5_GHZ},
	{5725, 145, AIRPCAP_CB_5_GHZ},
	{5730, 146, AIRPCAP_CB_5_GHZ},
	{5735, 147, AIRPCAP_CB_5_GHZ},
	{5740, 148, AIRPCAP_CB_5_GHZ},
	{5745, 149, AIRPCAP_CB_5_GHZ},
	{5750, 150, AIRPCAP_CB_5_GHZ},
	{5755, 151, AIRPCAP_CB_5_GHZ},
	{5760, 152, AIRPCAP_CB_5_GHZ},
	{5765, 153, AIRPCAP_CB_5_GHZ},
	{5770, 154, AIRPCAP_CB_5_GHZ},
	{5775, 155, AIRPCAP_CB_5_GHZ},
	{5780, 156, AIRPCAP_CB_5_GHZ},
	{5785, 157, AIRPCAP_CB_5_GHZ},
	{5790, 158, AIRPCAP_CB_5_GHZ},
	{5795, 159, AIRPCAP_CB_5_GHZ},

	{5800, 160, AIRPCAP_CB_5_GHZ},
	{5805, 161, AIRPCAP_CB_5_GHZ},
	{5810, 162, AIRPCAP_CB_5_GHZ},
	{5815, 163, AIRPCAP_CB_5_GHZ},
	{5820, 164, AIRPCAP_CB_5_GHZ},
	{5825, 165, AIRPCAP_CB_5_GHZ},
	{5830, 166, AIRPCAP_CB_5_GHZ},
	{5835, 167, AIRPCAP_CB_5_GHZ},
	{5840, 168, AIRPCAP_CB_5_GHZ},
	{5845, 169, AIRPCAP_CB_5_GHZ},
	{5850, 170, AIRPCAP_CB_5_GHZ},
	{5855, 171, AIRPCAP_CB_5_GHZ},
	{5860, 172, AIRPCAP_CB_5_GHZ},
	{5865, 173, AIRPCAP_CB_5_GHZ},
	{5870, 174, AIRPCAP_CB_5_GHZ},
	{5875, 175, AIRPCAP_CB_5_GHZ},
	{5880, 176, AIRPCAP_CB_5_GHZ},
	{5885, 177, AIRPCAP_CB_5_GHZ},
	{5890, 178, AIRPCAP_CB_5_GHZ},
	{5895, 179, AIRPCAP_CB_5_GHZ},

	{5900, 180, AIRPCAP_CB_5_GHZ},
	{5905, 181, AIRPCAP_CB_5_GHZ},
	{5910, 182, AIRPCAP_CB_5_GHZ},
	{5915, 183, AIRPCAP_CB_5_GHZ},
	{5920, 184, AIRPCAP_CB_5_GHZ},
	{5925, 185, AIRPCAP_CB_5_GHZ},
	{5930, 186, AIRPCAP_CB_5_GHZ},
	{5935, 187, AIRPCAP_CB_5_GHZ},
	{5940, 188, AIRPCAP_CB_5_GHZ},
	{5945, 189, AIRPCAP_CB_5_GHZ},
	{5950, 190, AIRPCAP_CB_5_GHZ},
	{5955, 191, AIRPCAP_CB_5_GHZ},
	{5960, 192, AIRPCAP_CB_5_GHZ},
	{5965, 193, AIRPCAP_CB_5_GHZ},
	{5970, 194, AIRPCAP_CB_5_GHZ},
	{5975, 195, AIRPCAP_CB_5_GHZ},
	{5980, 196, AIRPCAP_CB_5_GHZ},
	{5985, 197, AIRPCAP_CB_5_GHZ},
	{5990, 198, AIRPCAP_CB_5_GHZ},
	{5995, 199, AIRPCAP_CB_5_GHZ},

	{6000, 200, AIRPCAP_CB_5_GHZ},
	{6005, 201, AIRPCAP_CB_5_GHZ},
	{6010, 202, AIRPCAP_CB_5_GHZ},
	{6015, 203, AIRPCAP_CB_5_GHZ},
	{6020, 204, AIRPCAP_CB_5_GHZ},
	{6025, 205, AIRPCAP_CB_5_GHZ},
	{6030, 206, AIRPCAP_CB_5_GHZ},
	{6035, 207, AIRPCAP_CB_5_GHZ},
	{6040, 208, AIRPCAP_CB_5_GHZ},
	{6045, 209, AIRPCAP_CB_5_GHZ},
	{6050, 210, AIRPCAP_CB_5_GHZ},
	{6055, 211, AIRPCAP_CB_5_GHZ},
	{6060, 212, AIRPCAP_CB_5_GHZ},
	{6065, 213, AIRPCAP_CB_5_GHZ},
	{6070, 214, AIRPCAP_CB_5_GHZ},
	{6075, 215, AIRPCAP_CB_5_GHZ},
	{6080, 216, AIRPCAP_CB_5_GHZ},
	{6085, 217, AIRPCAP_CB_5_GHZ},
	{6090, 218, AIRPCAP_CB_5_GHZ},
	{6095, 219, AIRPCAP_CB_5_GHZ},

	{6100, 220, AIRPCAP_CB_5_GHZ},
	{6105, 221, AIRPCAP_CB_5_GHZ},
	{6110, 222, AIRPCAP_CB_5_GHZ},
	{6115, 223, AIRPCAP_CB_5_GHZ},
	{6120, 224, AIRPCAP_CB_5_GHZ},
	{6125, 225, AIRPCAP_CB_5_GHZ},
	{6130, 226, AIRPCAP_CB_5_GHZ},
	{6135, 227, AIRPCAP_CB_5_GHZ},
	{6140, 228, AIRPCAP_CB_5_GHZ},
	{6145, 229, AIRPCAP_CB_5_GHZ},
	{6150, 230, AIRPCAP_CB_5_GHZ},
	{6155, 231, AIRPCAP_CB_5_GHZ},
	{6160, 232, AIRPCAP_CB_5_GHZ},
	{6165, 233, AIRPCAP_CB_5_GHZ},
	{6170, 234, AIRPCAP_CB_5_GHZ},
	{6175, 235, AIRPCAP_CB_5_GHZ},
	{6180, 236, AIRPCAP_CB_5_GHZ},
	{6185, 237, AIRPCAP_CB_5_GHZ},
	{6190, 238, AIRPCAP_CB_5_GHZ},
	{6195, 239, AIRPCAP_CB_5_GHZ},
	
	// Frequency = 5000 - 5 * (200 - Channel)  where Channel >= 184 && Channel <= 199
	{4920, 184, AIRPCAP_CB_4_GHZ},
	{4925, 185, AIRPCAP_CB_4_GHZ},
	{4930, 186, AIRPCAP_CB_4_GHZ},
	{4935, 187, AIRPCAP_CB_4_GHZ},
	{4940, 188, AIRPCAP_CB_4_GHZ},
	{4945, 189, AIRPCAP_CB_4_GHZ},
	{4950, 190, AIRPCAP_CB_4_GHZ},
	{4955, 191, AIRPCAP_CB_4_GHZ},
	{4960, 192, AIRPCAP_CB_4_GHZ},
	{4965, 193, AIRPCAP_CB_4_GHZ},
	{4970, 194, AIRPCAP_CB_4_GHZ},
	{4975, 195, AIRPCAP_CB_4_GHZ},
	{4980, 196, AIRPCAP_CB_4_GHZ},
	{4985, 197, AIRPCAP_CB_4_GHZ},
	{4990, 198, AIRPCAP_CB_4_GHZ},
	{4995, 199, AIRPCAP_CB_4_GHZ}
};

#endif /* __AIRPCAP_NL_H__ */
