/* -*- mode: C; c-file-style: "k&r"; c-basic-offset: 4; indent-tabs-mode: nil; -*- */
#include <stdio.h>
#include "airpcap.h"

void test(PAirpcapHandle handle)
{
    AirpcapMacAddress mac;

    AirpcapGetMacAddress(handle, &mac);
    printf("Adapter MAC address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac.Address[i]);
        if (i < 5)
            printf(":");
    }
    printf("\n");

    PAirpcapDeviceCapabilities cap;
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
            printf("\t[%d] Frequency: %d MHz\n",  channel, frequency);
            
            if (0 != channel_info[c].ExtChannel) {
                printf("\tExtension channel info:\n");
            } else {
                printf("\tLegacy 20 MHz channel.\n");
            }
        }
    } else {
        printf("Error getting supported channels:\n");
        printf("%s\n", AirpcapGetLastError(handle));
    }
}
    
int main(int argc,
	 char **argv)
{
    UINT major, minor, rev, build;

    AirpcapGetVersion(&major, &minor, &rev, &build);
    printf("Airpcap version %d.%d.%d.%d\n",
           major, minor, rev, build);

    if (argc > 1) {
        printf("Attempting to open %s...\n", argv[1]);

        PAirpcapHandle handle;
        CHAR ebuf[AIRPCAP_ERRBUF_SIZE];
        
        handle = AirpcapOpen(argv[1], ebuf);
        if (NULL == handle) {
            fprintf(stderr, "AirpcapOpen error: %s\n", ebuf);
            return 1;
        }

        test(handle);
        
        printf("OK! Closing handle.\n");

        AirpcapClose(handle);
    }
    
    return 0;
}
