/* -*- mode: C; c-file-style: "k&r"; c-basic-offset: 4; indent-tabs-mode: nil; -*- */
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include "airpcap.h"

void libpcap_test(PAirpcapHandle, PCHAR);

void test(PCHAR name)
{
    PAirpcapHandle handle;
    AirpcapMacAddress mac;
    PAirpcapDeviceCapabilities cap;
    CHAR ebuf[AIRPCAP_ERRBUF_SIZE];

    printf("Attempting to open device %s.\n", name);
        
    handle = AirpcapOpen(name, ebuf);
    if (NULL == handle) {
        fprintf(stderr, "AirpcapOpen error: %s\n", ebuf);
        return;
    }

    AirpcapGetMacAddress(handle, &mac);
    printf("Adapter MAC address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac.Address[i]);
        if (i < 5)
            printf(":");
    }
    printf("\n");

    if (FALSE == AirpcapGetDeviceCapabilities(handle, &cap)) {
        fprintf(stderr, "AirpcapGetDeviceCapabilities failed!\n");
    } else {
        printf("Device capabilities:\n");
        printf("AdapterModelName: %s\n", cap->AdapterModelName);

        printf("Supported bands: ");
        if (cap->SupportedBands & AIRPCAP_BAND_2GHZ)
            printf("2.4GHz ");
        if (cap->SupportedBands & AIRPCAP_BAND_5GHZ)
            printf("5GHz");
        printf("\n");

        printf("Supported media: ");
        if (cap->SupportedMedia & AIRPCAP_MEDIUM_802_11_A)
            printf("802.11a ");
        if (cap->SupportedMedia & AIRPCAP_MEDIUM_802_11_B)
            printf("802.11b ");
        if (cap->SupportedMedia & AIRPCAP_MEDIUM_802_11_G)
            printf("802.11g ");
        if (cap->SupportedMedia & AIRPCAP_MEDIUM_802_11_N)
            printf("802.11n ");
        printf("\n");

        printf("Can inject packets: ");
        if (TRUE == cap->CanTransmit)
            printf("Yes");
        else
            printf("No");
        printf("\n");
        
        printf("Can set transmit power: ");
        if (TRUE == cap->CanSetTransmitPower)
            printf("Yes");
        else
            printf("No");
        printf("\n");
    }

    PAirpcapChannelInfo channel_info;
    UINT channel_info_count;
    BOOL ret;

    ret = AirpcapGetDeviceSupportedChannels(handle,
                                            &channel_info,
                                            &channel_info_count);

    if (TRUE == ret) {
        printf("Channels supported by this device:\n");
        for (UINT c = 0; c < channel_info_count; c++) {
            UINT frequency, channel;
            BOOL ret;
            frequency = channel_info[c].Frequency;

            /* Ignore the band */
            ret = AirpcapConvertFrequencyToChannel(frequency,
                                                   &channel,
                                                   NULL);
            if (FALSE == ret) {
                fprintf(stderr, "BUG: invalid frequency %d!\n", frequency);
                continue;
            }
            printf("   Channel %d (%d MHz)\n",  channel, frequency);
        }
    } else {
        printf("Error getting supported channels:\n");
        printf("%s\n", AirpcapGetLastError(handle));
    }

    UINT chan;
    AirpcapChannelInfo chaninfo;
    if (FALSE == AirpcapGetDeviceChannel(handle, &chan)) {
        printf("Error getting current channel: %s\n", AirpcapGetLastError(handle));
    } else {
        printf("AirpcapGetDeviceChannel = %u\n", chan);
        if (6 != chan) {
            printf("AirpcapGetDeviceChannel did not return 6 on Open - bug?\n");
        }
    }
    if (FALSE == AirpcapGetDeviceChannelEx(handle, &chaninfo)) {
        printf("Error getting current channel: %s\n", AirpcapGetLastError(handle));
    } else {
        printf("AirpcapGetDeviceChannelEx = {Freq = %u, Ext = %hhu, Flags = %hhu}\n",
               chaninfo.Frequency,
               chaninfo.ExtChannel,
               chaninfo.Flags);
        if (2437 != chaninfo.Frequency) {
            printf("AirpcapGetDeviceChannelEx did not return channel 6 on Open - bug?\n");
        }
    }
    chaninfo.Frequency = 2422;
    chaninfo.ExtChannel = 0;
    chaninfo.Flags = 0;
    
    if (FALSE == AirpcapSetDeviceChannelEx(handle, chaninfo)) {
        printf("AirpcapSetDeviceChannelEx failed: %s", AirpcapGetLastError(handle));
    }

    printf("Attempting libpcap test.\n");
    libpcap_test(handle, name);
    
    printf("OK! Closing handle.\n");
    AirpcapClose(handle);
}
void libpcap_test(PAirpcapHandle handle, PCHAR devname)
{
    pcap_t *dev, *dev_writer;
    pcap_dumper_t *writer;
    char errbuf[PCAP_ERRBUF_SIZE];
    int packets;

    printf("libpcap test: %s\n", devname);

    dev = pcap_open_live(devname, 65535, 1, 2, errbuf);
    if (NULL == dev) {
        printf("pcap_open_live failed: %s\n", errbuf);
    }

    dev_writer = pcap_open_dead(pcap_datalink(dev), 65535);
    writer = pcap_dump_open(dev_writer, "test.pcap");
    if (NULL == writer) {
        printf("pcap_dump_open failed: %s\n", pcap_geterr(dev_writer));
        pcap_close(dev_writer);
        pcap_close(dev);
    }

    UINT i;
    UINT channel = 0;
    UINT channel_list[] = {1, 6, 11, 153, 157};
    
    for (i = 0; i < (sizeof(channel_list) / sizeof(UINT)); i++) {
        AirpcapChannelInfo info;
        info.ExtChannel = 0;
        info.Flags = 0;

        channel = channel_list[i];
        AirpcapConvertChannelToFrequency(channel, &info.Frequency);
        printf("AirpcapSetDeviceChannelEx(%u, %u) ", channel, info.Frequency);
        if (FALSE == AirpcapSetDeviceChannelEx(handle, info)) {
            printf("failed: %s\n", AirpcapGetLastError(handle));
            goto done;
        } else {
            printf("OK, sniffing 20 packets\n");
        }
        sleep(1);
        for (packets = 0; packets < 20; packets++) {
            struct pcap_pkthdr *header;
            const u_char *data;
            if (pcap_next_ex(dev, &header, &data) < 0) {
                printf("Packet error: %s\n", pcap_geterr(dev));
                break;
            }

            /* Y U USE WRONG POINTER TYPE LIBPCAP */
            pcap_dump((u_char *)writer, header, data);
        }
    }
done:
    pcap_dump_close(writer);
    pcap_close(dev_writer);
    pcap_close(dev);
}
    
int main(int argc,
	 char **argv)
{
    UINT major, minor, rev, build;
    CHAR ebuf[AIRPCAP_ERRBUF_SIZE];

    AirpcapGetVersion(&major, &minor, &rev, &build);
    printf("Airpcap version %d.%d.%d.%d\n",
           major, minor, rev, build);

    printf("Airpcap device enumeration:\n");
    PAirpcapDeviceDescription desc;
    if (FALSE == AirpcapGetDeviceList(&desc, ebuf)) {
        fprintf(stderr, "AirpcapGetDeviceList error: %s\n", ebuf);
    } else {
        for(PAirpcapDeviceDescription d = desc; d; d = d->next) {
            printf("Device %s: %s\n", d->Name, d->Description);
        } 
   }
    AirpcapFreeDeviceList(desc);
    printf("\n");
    
    if (argc > 1) {
        test(argv[1]);
    }

    return 0;
}
