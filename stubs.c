/* -*- mode: C; c-file-style: "k&r"; c-basic-offset: 4; indent-tabs-mode: nil; -*- */
#include "airpcap.h"
#include "airpcap-nl.h"
#include "util.h"

/** STUB FUNCTION.  We have no concept of kernel buffers
 * for drivers.
 */
BOOL AirpcapSetKernelBuffer(PAirpcapHandle AdapterHandle,
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
BOOL AirpcapGetKernelBufferSize(PAirpcapHandle AdapterHandle,
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
BOOL AirpcapSetMinToCopy(PAirpcapHandle AdapterHandle,
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

BOOL AirpcapGetStats(PAirpcapHandle AdapterHandle, PAirpcapStats PStats UNUSED)
{
    if (AdapterHandle) {
        setebuf(AdapterHandle->last_error, "GetStats is not supported. Use libpcap.");
    }
    return FALSE;
}

BOOL AirpcapGetDeviceTimestamp(PAirpcapHandle AdapterHandle,
                               PAirpcapDeviceTimestamp PTimestamp UNUSED)
{
    if (AdapterHandle) {
        setebuf(AdapterHandle->last_error, "GetDeviceTimestamp is not yet supported.");
    }
    return FALSE;
}

/* We do not support PPI headers or without radiotap headers. */
BOOL AirpcapGetLinkType(PAirpcapHandle AdapterHandle,
                        PAirpcapLinkType PLinkType)
{
    BOOL ret = FALSE;
    if (AdapterHandle) {
        if (PLinkType) {
            *PLinkType = AIRPCAP_LT_802_11_PLUS_RADIO;
            ret = TRUE;
        } else {
            setebuf(AdapterHandle->last_error, "Invalid link type pointer.");
        }
    }

    return ret;
}

BOOL AirpcapSetLinkType(PAirpcapHandle AdapterHandle,
                        AirpcapLinkType LinkType)
{
    BOOL ret = FALSE;
    if (AdapterHandle) {
        switch(LinkType) {
        case AIRPCAP_LT_802_11_PLUS_RADIO:
            ret = TRUE;
            break;

        case AIRPCAP_LT_802_11:
            setebuf(AdapterHandle->last_error, "Link type LT_802_11 not supported.");
            break;

        case AIRPCAP_LT_802_11_PLUS_PPI:
            setebuf(AdapterHandle->last_error, "Link type LT_802_11_PLUS_PPI not supported.");
            break;

        default:
            setebuf(AdapterHandle->last_error, "Invalid link type %d", LinkType);
            break;
        }
    }

    return ret;
}

/* TOCHECK: mac80211 always appends FCS to end of monitor frame, right? */
BOOL AirpcapSetFcsPresence(PAirpcapHandle AdapterHandle, BOOL IsFcsPresent)
{
    BOOL ret = FALSE;
    if (AdapterHandle) {
        if (TRUE == IsFcsPresent) {
            ret = TRUE;
        } else {
            setebuf(AdapterHandle->last_error, "Cannot disable FCS at end of frame.");
        }
    }

    return ret;
}
BOOL AirpcapGetFcsPresence(PAirpcapHandle AdapterHandle, PBOOL PIsFcsPresent)
{
    BOOL ret = FALSE;
    if (AdapterHandle) {
        if (PIsFcsPresent) {
            *PIsFcsPresent = TRUE;
            ret = TRUE;
        } else {
            setebuf(AdapterHandle->last_error, "Invalid FCS presence flag pointer.");
        }
    }

    return ret;
}

BOOL AirpcapSetFilter(PAirpcapHandle AdapterHandle,
                      PVOID Instructions UNUSED,
                      UINT Len UNUSED)
{
    if (AdapterHandle) {
        setebuf(AdapterHandle->last_error, "AirpcapSetFilter is not supported. Use libpcap.");
    }
    return FALSE;
}

/* TODO: This can be implemented. */
BOOL AirpcapSetMacAddress(PAirpcapHandle AdapterHandle,
                          PAirpcapMacAddress PMacAddress UNUSED)
{
    if (AdapterHandle) {
        setebuf(AdapterHandle->last_error, "AirpcapSetMacAddress is not yet supported.");
    }
    return FALSE;
}

BOOL AirpcapGetReadEvent(PAirpcapHandle AdapterHandle,
                         HANDLE *PReadEvent UNUSED)
{
    if (AdapterHandle) {
        setebuf(AdapterHandle->last_error,
                "AirpcapGetReadEvent is not supported; use "
                "pcap_get_selectable_fd() instead.");
    }
    return FALSE;
}

BOOL AirpcapRead(PAirpcapHandle AdapterHandle,
                 PBYTE Buffer UNUSED,
                 UINT BufSize UNUSED,
                 PUINT PReceivedBytes UNUSED)
{
    if (AdapterHandle) {
        setebuf(AdapterHandle->last_error, "AirpcapRead is not supported; use libpcap instead.");
    }
    return FALSE;
}

/* We never decrypt in hardware. This is the responsibility of the user of libpcap. */
BOOL AirpcapGetDriverDecryptionState(PAirpcapHandle AdapterHandle,
                                     PAirpcapDecryptionState PEnable)
{
    BOOL ret = FALSE;
    if (AdapterHandle) {
        if (PEnable) {
            *PEnable = AIRPCAP_DECRYPTION_OFF;
            ret = TRUE;
        } else {
            setebuf(AdapterHandle->last_error, "Invalid PEnable pointer.");
        }
    }
    return ret;
}
BOOL AirpcapGetDecryptionState(PAirpcapHandle AdapterHandle,
                               PAirpcapDecryptionState PEnable)
{
    return AirpcapGetDriverDecryptionState(AdapterHandle, PEnable);
}

BOOL AirpcapSetDriverDecryptionState(PAirpcapHandle AdapterHandle,
                                     AirpcapDecryptionState Enable)
{
    BOOL ret = FALSE;
    if (AdapterHandle) {
        switch (Enable) {
        case AIRPCAP_DECRYPTION_OFF:
            ret = TRUE;
            break;

        case AIRPCAP_DECRYPTION_ON:
            setebuf(AdapterHandle->last_error, "Hardware decryption is not supported.");
            break;

        default:
            setebuf(AdapterHandle->last_error, "Invalid AirpcapDecryptionState passed.");
            break;
        }
    }
    return ret;
}
BOOL AirpcapSetDecryptionState(PAirpcapHandle AdapterHandle,
                               AirpcapDecryptionState Enable)
{
    return AirpcapSetDriverDecryptionState(AdapterHandle, Enable);
}

BOOL AirpcapSetDeviceKeys(PAirpcapHandle AdapterHandle,
                          PAirpcapKeysCollection KeysCollection UNUSED)
{
    if (AdapterHandle) {
        setebuf(AdapterHandle->last_error, "Decryption keys are not supported.");
    }
    return FALSE;
}
BOOL AirpcapSetDriverKeys(PAirpcapHandle AdapterHandle,
                          PAirpcapKeysCollection KeysCollection UNUSED)
{
    if (AdapterHandle) {
        setebuf(AdapterHandle->last_error, "Decryption keys are not supported.");
    }
    return FALSE;
}
BOOL AirpcapGetDeviceKeys(PAirpcapHandle AdapterHandle,
                          PAirpcapKeysCollection PKeysCollection UNUSED,
                          PUINT PKeysCollectionSize)
{
    if (AdapterHandle) {
        setebuf(AdapterHandle->last_error, "Decryption keys are not supported.");
        if (PKeysCollectionSize) {
            *PKeysCollectionSize = 0;
        }
    }
    return FALSE;
}
BOOL AirpcapGetDriverKeys(PAirpcapHandle AdapterHandle,
                          PAirpcapKeysCollection PKeysCollection,
                          PUINT PKeysCollectionSize)
{
    return AirpcapGetDeviceKeys(AdapterHandle, PKeysCollection, PKeysCollectionSize);
}

BOOL AirpcapWrite(PAirpcapHandle AdapterHandle,
                  PCHAR TxPacket UNUSED,
                  ULONG PacketLen UNUSED)
{
    if (AdapterHandle) {
        setebuf(AdapterHandle->last_error,
                "Transmit support not yet implemented. "
                "Use pcap_inject() for now.");
    }
    return FALSE;
}

BOOL AirpcapStoreCurConfigAsAdapterDefault(PAirpcapHandle AdapterHandle)
{
    if (AdapterHandle) {
        setebuf(AdapterHandle->last_error, "Storing device configuration not yet supported.");
    }
    return FALSE;
}
