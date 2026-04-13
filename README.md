# PQC-implementation-in-Wi-Fi
Practical implementation of PQC algorithms based on modyfing hostapd and wpa_supplicant written in C

# Modified and added elements
This part contains all of changes done
## Beacon
placeholder

## Probe Request 
The frame contains addidtional vendor specific IE (Information element),   
one byte used for specifing configuration of PQC algorithms (bits 4 and 8 not used):
10000000 - ML KEM 512  
01000000 - ML KEM 768  
00100000 - ML KEM 1024  
00001000 - ML DSA 44  
00000100 - ML DSA 65  
00000010 - ML DSA 87 

### STA
**wpa_supplicant/scan.c**  
Adding special fields (IE) in Probe Request frame
* wpabuf_put_u8(pqc_ie, WLAN_EID_VENDOR_SPECIFIC); - value = 221 - ID for IE  
* wpabuf_put_u8(pqc_ie, 5); // length - 5	how many bytes till the end of this specific IE, OUI (3B), our payload 1B, type - 1B = 5B
* wpabuf_put_be24(pqc_ie, 0x00904C); // OUI - test OUI, 3 byte identification, usually 3 first bytes of MAC
* wpabuf_put_u8(pqc_ie, 0x01); // type 
* wpabuf_put_u8(pqc_ie, safe_pqc_byte); // chosen KEM & DSA - payload  

**wpa_supplicant/config_ssid.h** - struct wpa_ssid:
* u8 pqc_choice - chosen algorithms (1B) - versions of KEM and DSA
* int pqc_enabled - whether PQC is used for specific SSID

**wpa_supplicant/config.c** - struct ssid_fields:  
added pqc_eanbled and pqc_choice

**wpa_supplicant/bss.h** - struct wpa_bss:  
added has_pqc and ap_pqc_supported fields - for parsing beacon frame

### AP
**src/ap/sta_info.h** - struct sta_info:  
definition of parameters used in Probe Request parsing  
* u8 pqc_choice - chosen parameters by specific STA  
* bool pqc_negotiated - Flag: whether the IE in probe request sent by STA was correct  

**src/ap/beacon.c** - void handle_probe_req:  
parsing IE in Probe request that was send by STA

# Helpful functions

### int os_get_random(unsigned char *buf, size_t len) 
**/src/utils/os.h**  
Used for delivering randomness, in the future, change to download randomness from the tpm module 
* buf: Buffer for pseudo random data
* len: Length of the buffer
* returns: 0 - success, -1 - failure