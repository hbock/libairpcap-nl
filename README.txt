airpcap-nl
----------

airpcap-nl is an implementation of core parts of the Airpcap Windows library
for nl80211 drivers in Linux.  It provides a convenience abstraction for
creating and using monitor interfaces for wireless packet captures on
802.11abgn devices.

Recommended Adapters
====================

Any adapter with good mac80211/cfg80211 support will work with this library.
No wext-only drivers will work! You should convert your application to use
lorcon for that purpose.

The adapters I have had most success with have chipsets supported by
ath9k(_htc) and iwlagn.  I have had limited success with rt2x00 adapters,
but that is mostly due to recent adapters being relatively unsupported.

Implementation status
=====================

Supported calls (with some caveats):

 - AirpcapGetVersion
 - AirpcapGetLastError
 - AirpcapGetDeviceList
 - AirpcapFreeDeviceList
 - AirpcapOpen
 - AirpcapClose
 - AirpcapGetDeviceCapabilities

 - AirpcapGetLinkType
   - Always returns AIRPCAP_LT_802_11_PLUS_RADIO.

 - AirpcapGetDeviceMacFlags
   - Always returns AIRPCAP_MF_MONITOR_MODE_ON set,
     AIRPCAP_MF_ACK_FRAMES_ON cleared.
     
 - AirpcapGetFcsPresence
   - Always returns TRUE.

 - AirpcapSetFcsValidation
   - Does not support AIRPCAP_VT_ACCEPT_CORRUPT_FRAMES.

 - AirpcapGetFcsValidation

 - AirpcapGetDecryptionState
   - Always returns AIRPCAP_DECRYPTION_OFF.

 - AirpcapSetDeviceChannel
 - AirpcapGetDeviceChannel
 - AirpcapSetDeviceChannelEx
 - AirpcapGetDeviceChannelEx 
 - AirpcapGetDeviceSupportedChannels
 - AirpcapConvertFrequencyToChannel
 - AirpcapConvertChannelToFrequency
 - AirpcapGetMacAddress
 - AirpcapSetTxPower
 - AirpcapGetTxPower

Stubbed calls:

 - AirpcapSetLinkType
   - mac80211 does not support anything but AIRPCAP_LT_802_11_PLUS_RADIO

 - AirpcapSetDeviceMacFlags
   - mac80211 does not support frame acknowledgement in monitor mode AFAIK.
     It may be possible to support this with an additional managed interface.

 - AirpcapSetFcsPresence
   - mac80211 cannot configure the driver either way. Most drivers do always
     return frames with FCS.

 - AirpcapSetDeviceKeys
 - AirpcapGetDeviceKeys
 - AirpcapSetDriverKeys
 - AirpcapGetDriverKeys
 - AirpcapSetDecryptionState
   - We do not support hardware decryption.

 - AirpcapSetKernelBuffer
 - AirpcapGetKernelBufferSize
 - AirpcapSetMinToCopy
 - AirpcapGetReadEvent
   - These calls don't make sense outside of the Airpcap driver model.

 - AirpcapSetFilter
 - AirpcapRead
 - AirpcapGetStats
   - These calls are all available in libpcap. Without having access to all
     capture handles open for this device, there's no way to implement
     these.  Equivalent:
     - AirpcapSetFilter: pcap_compile/pcap_setfilter
     - AirpcapRead: pcap_next, pcap_next_ex
     - AirpcapGetStats: pcap_stats

 - AirpcapGetLedsNumber
 - AirpcapTurnLedOn
 - AirpcapTurnLedOff
   - We don't have any access to the LEDs in a consistent way, AFAIK. Some
     mac80211 drivers may support toggling the LEDs, but it's too much hassle
     for a capture interface.  We simply return 0 for AirpcapGetLedsNumber.

Stubbed, but will eventually be supported:
 
 - AirpcapSetMacAddress
   - Easily implemented.

 - AirpcapWrite
   - For now, this can be replaced in application code via pcap_inject.

Stubbed, but may eventually get supported:

 - AirpcapGetDeviceTimestamp
   - This would be incredibly useful, but I have no idea how to get the
     current adapter TSFT from mac80211.  Many drivers support it and it is
     used for radiotap, but there is no exposure in nl80211.

 - AirpcapStoreCurConfigAsAdapterDefault
   - This could be stored on the filesystem and restored on AirpcapOpen.

