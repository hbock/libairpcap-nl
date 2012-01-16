/* -*- mode: C; c-file-style: "k&r"; c-basic-offset: 4; indent-tabs-mode: nil; -*- */
/*
  lifted from lorcon2

  lorcon is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  lorcon is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with lorcon; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  
  Copyright (c) 2005 dragorn and Joshua Wright
*/
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "util.h"

int ifconfig_set_flags(const char *in_dev, short flags)
{
    struct ifreq ifr;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }

    /* Fetch interface flags */
    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    ifr.ifr_flags = flags;
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
        close(skfd);
        return -1;
    }

    close(skfd);

    return 0;
}

int ifconfig_get_flags(const char *in_dev, short *flags)
{
    struct ifreq ifr;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }

    /* Fetch interface flags */
    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        close(skfd);
        return -1;
    }

    (*flags) = ifr.ifr_flags;

    close(skfd);

    return 0;
}

int ifconfig_ifupdown(const char *in_dev, int devup)
{
    int ret;
    short rflags;

    if ((ret = ifconfig_get_flags(in_dev, &rflags)) < 0)
        return ret;

    if (devup) {
        rflags |= IFF_UP;
    } else {
        rflags &= ~IFF_UP;
    }

    return ifconfig_set_flags(in_dev, rflags);
}

int ifconfig_get_hwaddr(const char *dev, uint8_t *hwaddr)
{
    struct ifreq ifr;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }

    /* Fetch interface flags */
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
        close(skfd);
        return -1;
    }

    memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, 6);
    close(skfd);
    return 0;
}
