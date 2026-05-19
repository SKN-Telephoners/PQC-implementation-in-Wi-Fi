# PQC-implementation-in-Wi-Fi
Practical implementation of PQC algorithms based on modifying hostapd and wpa_supplicant written in C
# SETUP (tests)
### virtual wlan cards
```
sudo modprobe mac80211_hwsim radios=2
```
### dependancies
Install dependancies (to do)  

### compiling
Start by compiling code (both in **hostap/hostapd** and **hostap/wpa_supplicant** directories):
```
make clean  
cp defconfig .config
make -j4 
```
### config files - added to repository 
**/hostap/hostapd** - create new file *test-ap.config:
```
interface=wlan0
driver=nl80211
ssid=PQC
channel=1
hw_mode=g
pqc_enabled=1
pqc_choice=136
```
**/hostap/wpa_supplicant** - create new file *test-sta.config:
```
ctrl_interface=/var/run/wpa_supplicant
update_config=0

network={
	ssid="PQC"
	key_mgmt=NONE
	pqc_enabled=1
	pqc_choice=136
}
```
### running virtual AP & STA
in /hostap/hostapd directory: 
````sudo ./hostapd -d test-ap.conf````  
in /hostap/wpa_supplicant directory: 
````sudo ./wpa_supplicant -i wlan1 -c test-sta.conf -d````

# Modified and added elements
This part contains all the changes done
## Beacon
The beacon frame is extended with a Vendor-Specific Information Element (IE) that advertises PQC support and the exact ML‑KEM / ML‑DSA variants supported by the Access Point (AP).
This allows the STA to negotiate PQC algorithms before PASN/PAKE.
**hostapd/src/ap/beacon.c**
Adding a new IE in beacon frame:
* tailpos = hostapd_eid_pqc_capabilities(hapd, tailpos);
This IE is placed right after RSNXE to keep all [security‑related IEs grouped together](https://dox.ipxe.org/group__ieee80211__ie.html).

**PQC generator function**
```c
u8 * hostapd_eid_pqc_capabilities(struct hostapd_data *hapd, u8 *pos)
{
    if (!hapd->conf->pqc_enabled)
        return pos;

    *pos++ = WLAN_EID_VENDOR_SPECIFIC; // 221
    *pos++ = 5;                        // OUI (3B) + type (1B) + payload (1B)

    *pos++ = 0x00; // OUI byte 1
    *pos++ = 0x90; // OUI byte 2
    *pos++ = 0x4C; // OUI byte 3

    *pos++ = 0x01; // Type: PQC capabilities

    *pos++ = hapd->conf->pqc_choice; // 1‑byte PQC bitmask

    return pos;
}
```
OUI is a producent id.

**PQC IE format/structure**  

| Field        | Length  | Description               |  
|--------------|---------|---------------------------|   
| Element ID   | 1 byte  | 221 (Vendor Specific IE)  |  
| Length       | 1 byte  | Number of bytes that follow (here: 5)      |  
| OUI          | 3 bytes | 00 90 4C (test OUI)       |  
| Type         | 1 byte  | 0x01 (PQC capabilities)   |  
| Payload      | 1 byte  | Bitmask of supported PQC  |  

Each bit in the payload byte represents support for a specific PQC algorithm like in Probe Request

**hostapd/src/ap/beacon.h**
Add declaration
* u8 * hostapd_eid_pqc_capabilities(struct hostapd_data *hapd, u8 *pos);

**src/ap/ap_config.h** - struct hostapd_bss_config:  
used for configuring AP at the start (what PQC parameters will AP be supporting), we need to specify these in test-ap.conf file
* int pqc_enabled;
* u8 pqc_choice;

**hostapd/config_file.c** - function hostapd_config_fill:  
used for reading and parsing configuration of AP from .conf file 
```C
else if (os_strcmp(buf, "pqc_enabled") == 0) { 
        bss->pqc_enabled = atoi(pos);
} else if (os_strcmp(buf, "pqc_choice") == 0) {
        bss->pqc_choice = strtol(pos, NULL, 0);
}  
```


## Probe Request and Probe Response
The frame contains additional vendor specific IE (Information element),   
one byte used for specifying configuration of PQC algorithms (bits 4 and 8 not used):  
10000000 - ML KEM 512  
01000000 - ML KEM 768  
00100000 - ML KEM 1024  
00001000 - ML DSA 44  
00000100 - ML DSA 65  
00000010 - ML DSA 87

### STA
**wpa_supplicant/scan.c** - function wpa_supplicant_extra_ies (new elements):
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
added pqc_enabled and pqc_choice

**wpa_supplicant/bss.h** - struct wpa_bss:  
added has_pqc and ap_pqc_supported fields - for parsing beacon frame
added detection of PQC support in beacon frame and parsing the parameters of supported algorithms by AP

**wpa_supplicant/events.c** - function pqc_process_vendor_ie:  
function for collecting key fragments, uses a bitmask to make sure that all pieces were received
when all fragments are received it triggers the association process

function pqc_try_start_auth - checks if all parameters are received and starts authentication process (PASN/PAKE) if they are

**wpa_supplicant/wpa_supplicant_i.h** - added a buffer and tracking variables to manage the reassembly of the pub key 
```c
u8 pqc_kem_buffer[800];
u32 pqc_fragments_mask;
size_t pqc_kem_received_len;
size_t pqc_kem_expected_len;
u8 pqc_kem_expected_frags;
bool pqc_kem_complete;
bool pqc_auth_started;
```

### AP
**src/ap/sta_info.h** - struct sta_info:  
definition of parameters used in Probe Request parsing
* u8 pqc_choice - chosen parameters by specific STA
* bool pqc_negotiated - Flag: whether the IE in probe request sent by STA was correct
* u8 *ml_kem_512_pub - buffer for storing ML-KEM 512 public key sent by AP in probe response
* size_t ml_kem_512_pub_len - length of the public key sent by AP in probe response
* bool pqc_pub_ready - whether the public key sent by AP in probe response is ready to be sent (after generating it)
* bool pqc_pub_sent - whether the public key sent by AP in probe response was already sent to STA (after sending it, we can free the buffer for public key)
* size_t pqc_pub_frag_count - how many fragments of public key were sent to STA
* u8 *ml_dsa_65_pub - buffer for storing ML-DSA 65 public key 
* size_t ml_dsa_65_pub_len - length of the public key

**src/ap/beacon.c** - void handle_probe_req:  
parse IE in Probe request that was sent by STA and add parameters to specific STA.  
OUI verification must be implemented in this part, in the future
Probe request now handles DSA and KEM key generating triggered by the presence of correct IE in probe request frame.

hostapd_gen_probe_resp: 
function modified to break the key into smaller chunks and adds their id (WPA_PUT_LE16(pos, sta->ml_kem_512_pub_len)) to the fragment so that it can be sent in probe response

## PQC State Machine 
Separates PQC-specific operations from standard Wi-Fi authentication flows. Saves PQC keys and session variables in dedicated structures.  

### STA
```wpa_supplicant/pqc_sm.h```, ```wpa_supplicant/pqc_sm.c```

**struct wpa_pqc_sm**: Centralized storage for PQC session variables (ML-KEM/ML-DSA keys, passwords, identifiers) on the STA side. Initialized in pqc_sm_init() after receiving the public PQC key (ML-KEM) in the Probe Response from the AP, right before sending the authentication request. Deinitialized in pqc_sm_deinit() after a deauthentication request.

### AP 
```src/ap/pqc_ap_sm.h```, ```src/ap/pqc_ap_sm.c```

**struct hostapd_pqc_sm**: Centralized storage for PQC session variables on the AP side. Initialized in pqc_ap_sm_init() after successfully intercepting the PAKE-1 frame. Imports the password and ML-KEM and ML-DSA keys previously generated and stored in ```sta_info``` during the Probe Request phase. Deinitialized in pqc_ap_sm_deinit().

## PAKE
Due to Linux kernel (mac80211) restrictions, standard Vendor Specific Action frames (Category 127) are dropped before the ASSOCIATED state. Therefore, the entire PAKE exchange utilizes Public Action Frames (Category 4, Action 9).

**PQC PAKE frame format**

| Field          | Length    | Description                                   |
|----------------|-----------|-----------------------------------------------|
| Category       | 1 byte    | 4 (Vendor Specific Action Frame)              |
| Action         | 1 byte    | 9                                             |
| OUI            | 3 bytes   | 00 90 4C (test OUI)                           |
| Type           | 1 byte    | 0x10                                          |
| Subtype        | 1 byte    | 0x01 / 0x02 / 0x03 / 0x04                     |
| Payload        | 32 bytes  | Variable (based on which PAKE frame it is)    |

### PAKE-1
#### STA:  
After intercepting authentication request and stopping assosciation function (that also authenticates STA) checks are performed to determine whether PQC is used, if it is:  

**wpa_supplicant/pqc_sm.c**: ```pqc_sm_rx_auth_req``` prepares the crypto payload (ML-KEM encapsulation, random ID generation).

**wpa_supplicant/pqc_pake.c**: ```wpas_pqc_send_pake1``` builds the Public Action frame with subtype 0x01 and sends it via wpa_drv_send_action. It stops the standard SME loop to wait for the AP's response.

#### AP:
**src/ap/ieee802_11.c**: Intercepted at the very beginning of the ```handle_action function``` (before standard hostapd parsing) by checking Category 4, Action 9, OUI, and Type 0x10.

**src/ap/pqc_ap_sm.c**: ```pqc_ap_sm_rx_pake1``` parses the payload, performs KEM decapsulation, and triggers the PAKE-2 response.

### PAKE-2
#### AP: 
**src/ap/pqc_ap_sm.c**: ```hostapd_pqc_send_pake2``` builds and sends the frame (subtype 0x02) containing the encrypted sid and ML-DSA public key directly after processing PAKE-1.

#### STA: 
**wpa_supplicant/events.c**: Intercepted in ```wpa_supplicant_event``` (RX_MGMT action frame) by validating the Public Action headers and subtype 0x02.

**wpa_supplicant/pqc_pake.c**: ```pqc_sm_rx_pake2``` parses the payload, decrypts the sid, saves the AP's DSA public key, and generates the STA's ML-KEM keys for the next phase.

### PAKE-3
#### STA: 
**wpa_supplicant/pqc_pake.c**: ```wpas_pqc_send_pake3``` builds the frame (subtype 0x03) with payload parameters s and T generated by the Double Feistel Network.

#### AP: 
**src/ap/ieee802_11.c**: Intercepted at the top of ```handle_action``` (subtype 0x03).

**src/ap/pqc_ap_sm.c**: ```pqc_ap_sm_rx_pake3``` parses the frame, verifies the Feistel network parameters, and triggers PAKE-4.

### PAKE-4
#### AP: 
**src/ap/pqc_ap_sm.c**: ```hostapd_pqc_send_pake4``` generates ciphertext and verification tags, then builds and sends the PAKE-4 Public Action frame (subtype 0x04).

#### STA: 
**wpa_supplicant/events.c**: Intercepted in the RX_MGMT event handler the same as before (subtype 0x04).

**wpa_supplicant/pqc_pake.c**: ```pqc_sm_rx_pake4``` parses the payload, performs final KEM decapsulation, verifies the HMAC tag, and derives the PMK.

## Association 
Instead of the standard 4-Way Handshake deriving the PMK from a PSK, the PQC authentication injects the PMK negotiated during the PAKE phase.

### STA
**wpa_supplicant/pqc_pake.c**: At the end of ```pqc_sm_rx_pake4```, the newly derived PMK is injected into the WPA state machine using ```wpa_sm_set_pmk()```. It then manually triggers the association process using ```sme_associate()``` (it was stopped before).

**wpa_supplicant/pqc_sm.c**: ```pqc_sm_assoc_success``` is called after a successful association response to generate the second pair of KEM keys.

### AP
**src/ap/pqc_ap_sm.c**: ```pqc_ap_sm_derive_pmk``` derives the PMK locally using session parameters (fsid, Feistel outputs, ciphertext) saved in state machine.

**src/ap/ieee802_11.c** (handle association): Modified to check the ```pqc_enabled``` flag. If enabled, it calls ```pqc_ap_sm_derive_pmk()``` to finalize the PAKE phase.

# Helpful functions
All mathematical and configuration helper functions (our own) are grouped in src/common/pqc_help.c and pqc_help.h:

### int os_get_random(unsigned char *buf, size_t len)
**/src/utils/os.h**  
Used for delivering randomness, in the future, change to download randomness from the tpm module
* buf: Buffer for pseudo random data
* len: Length of the buffer
* returns: 0 - success, -1 - failure

### get_oqs_kem_alg(u8 pqc_choice) / get_oqs_dsa_alg(u8 pqc_choice):
Translates the 1-byte bitmask (e.g., 0x88) negotiated in Probe Request/Response into the exact algorithm string identifiers required by the liboqs library.

### pqc_2f_network(...) / pqc_2f_inverse(...): 
Implements the Double Feistel Network (2F) using HMAC-SHA256. It processes the Wi-Fi password (PSK) into variables s and T without exposing the password in the network, preventing offline dictionary attacks.

### Constants & Macros: 
Defines frame parsing constants (PQC_OUI_0, PQC_OUI_TYPE_PAKE, PQC_PAKE_TYPE_1, etc.) to safely extract data from MAC payloads without relying on hardcoded magic numbers.

# Module lattice cryptographic algorithms

### Setup

````
sudo apt update
sudo apt install cmake gcc libtool libssl-dev make ninja-build build-essential


git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja .. -DOQS_USE_OPENSSL=OFF
ninja
sudo ninja install

````

# ML-KEM (512)

### Key generating

```c
#include <oqs/oqs.h>

OQS_init();

OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);

// Allocate memory for the keypair
uint8_t *public_key = malloc(kem->length_public_key);
uint8_t *secret_key = malloc(kem->length_secret_key);

// Generate the public and secret keys
OQS_KEM_keypair(kem, public_key, secret_key);

OQS_MEM_secure_free(secret_key, kem->length_secret_key);
free(public_key);
OQS_KEM_free(kem);

OQS_destroy();
```

### Message encapsulation

```c
#include <oqs/oqs.h>

// The public key received from the intended recipient
uint8_t *public_key = ...; 

OQS_init();

OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);

uint8_t *ciphertext = malloc(kem->length_ciphertext);
uint8_t *shared_secret = malloc(kem->length_shared_secret);

// Create the ciphertext and the shared secret using the recipient's public key
OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);

OQS_MEM_secure_free(shared_secret, kem->length_shared_secret);
free(ciphertext);
OQS_KEM_free(kem);

OQS_destroy();
```

### Message decapsulation

```c
#include <oqs/oqs.h>

// The secret key generated by this device and kept private
uint8_t *secret_key = ...; 
// The ciphertext received from the sender
uint8_t *received_ciphertext = ...; 

OQS_init();

OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
uint8_t *shared_secret = malloc(kem->length_shared_secret);

OQS_KEM_decaps(kem, shared_secret, received_ciphertext, secret_key);

OQS_MEM_secure_free(shared_secret, kem->length_shared_secret);
OQS_KEM_free(kem);

OQS_destroy();
```

# ML-DSA (65)

### Key generating

```c
#include <oqs/oqs.h>

OQS_init();

OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

// Allocate memory for the keypair
uint8_t *public_key = malloc(sig->length_public_key);
uint8_t *secret_key = malloc(sig->length_secret_key);

// Generate the keys
OQS_SIG_keypair(sig, public_key, secret_key);

OQS_MEM_secure_free(secret_key, sig->length_secret_key);
free(public_key);
OQS_SIG_free(sig);

OQS_destroy();
```

### Message signing

```c
#include <oqs/oqs.h>

uint8_t *secret_key = ...; 
uint8_t *message = ...; 
size_t message_len = ...;

OQS_init();

OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

uint8_t *signature = malloc(sig->length_signature);
size_t signature_len;

OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);


OQS_MEM_insecure_free(signature);
OQS_SIG_free(sig);

OQS_destroy();
```

### Message verification

```c
#include <oqs/oqs.h>

// The public key belonging to the sender
uint8_t *public_key = ...; 
uint8_t *message = ...;
size_t message_len = ...;
uint8_t *signature = ...;
size_t signature_len = ...;

OQS_init();

OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

OQS_STATUS rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);

// for rc == OQS_SUCCESS, the signature is valid, otherwise it is invalid

OQS_SIG_free(sig);

OQS_destroy();
```
