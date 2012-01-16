/* -*- mode: C; c-file-style: "k&r"; c-basic-offset: 4; indent-tabs-mode: nil; -*- */
#include "airpcap.h"
#include "airpcap-nl.h"
#include "util.h"

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

/* We don't support MF_ACK_FRAMES_ON, yet. Not sure if it's
 * possible in nl80211. */
BOOL AirpcapGetDeviceMacFlags(PAirpcapHandle AdapterHandle,
                              PUINT PAirpcapMacFlags)
{
    if (AdapterHandle && PAirpcapMacFlags) {
        *PAirpcapMacFlags = AIRPCAP_MF_MONITOR_MODE_ON;
        return TRUE;
    }
    return FALSE;
}

BOOL AirpcapSetDeviceMacFlags(PAirpcapHandle AdapterHandle,
                              UINT AirpcapMacFlags)
{
    BOOL ret = FALSE;
    if (AdapterHandle) {
        if (AirpcapMacFlags & ~(AIRPCAP_MF_MONITOR_MODE_ON|AIRPCAP_MF_ACK_FRAMES_ON)) {
            setebuf(AdapterHandle->last_error, "Invalid argument.");
        } else if (AirpcapMacFlags & AIRPCAP_MF_ACK_FRAMES_ON) {
            setebuf(AdapterHandle->last_error, "Frame acknowledgement in monitor mode is not supported.");
        } else if (0 == (AirpcapMacFlags & AIRPCAP_MF_MONITOR_MODE_ON)) {
            /* TODO: Look into setting managed mode only. */
            setebuf(AdapterHandle->last_error, "Monitor mode cannot be disabled.");
        } else {
            ret = TRUE;
        }
    }
    
    return ret;
}
