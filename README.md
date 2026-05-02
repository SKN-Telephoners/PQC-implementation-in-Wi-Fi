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
Separates PQC-specific operations from standard Wi-Fi authentication flows. Saves PQC keys in the structure.  
Initialized after receiving public PQC key (ML-KEM) in Probe Response from AP, right before sending authentication request.  
Deinitialized after deauthentication request (both in **wpa_supplicant.c**).    
**/wpa_supplicant/pqc_sm.h, /wpa_supplicant/pqc_sm.c** - these files can also be used for PQC related functions, structs and other objects.  

**struct wpa_pqc_sm** used as centralized storage for PQC session variables (ML-KEM/ML-DSA keys)  


## PAKE

### PQC PAKE-1

STA generates ID, encrypts it with AES-256, performs ML-KEM.encaps, and sends:

| Field   | Value              |
|---------|-------------------|
| Category | 127 (Vendor Specific Action) |
| OUI | 00 90 4C |
| Type | 0x10 (PQC/PAKE) |
| Subtype | 0x01 (PAKE-1) |

**Payload Structure:**

| Field | Length | Description |
|-------|--------|-------------|
| Type | 1 byte | 0x01 |
| c_len | 2 bytes | Ciphertext length |
| c | Variable | ML-KEM ciphertext |
| id_len | 2 bytes | Encrypted ID length |
| {id} | Variable | AES-256(id) |

#### Receiving PAKE-1 in ieee802_11.c

```c
/* PAKE-1 handler */
if (sta)
    hostapd_pqc_rx_pake(hapd, sta, pos, left);
```

#### Parsing PAKE-1

```c
static void hostapd_pqc_rx_pake(struct hostapd_data *hapd,
                                struct sta_info *sta,
                                const u8 *pos, size_t len)
{
    struct pqc_pake1_fields f;

    if (pqc_parse_pake1(pos, len, &f) < 0)
        return;

    sta->pqc_pake1_ct = os_memdup(f.c, f.c_len);
    sta->pqc_pake1_ct_len = f.c_len;

    sta->pqc_pake1_enc_id = os_memdup(f.enc_id, f.id_len);
    sta->pqc_pake1_enc_id_len = f.id_len;

    sta->pqc_pake1_received = true;

    hostapd_pqc_handle_pake1(hapd, sta);
}
```

---

### PQC PAKE-2

AP decapsulates ML-KEM, decrypts {id}, generates SID, constructs FSID, and sends:

| Field   | Value              |
|---------|-------------------|
| Category | 127 (Vendor Specific Action) |
| OUI | 00 90 4C |
| Type | 0x10 (PQC/PAKE) |
| Subtype | 0x02 (PAKE-2) |

**Payload Structure:**

| Field | Length | Description |
|-------|--------|-------------|
| Type | 1 byte | 0x02 |
| sid_len | 2 bytes | Encrypted SID length |
| {sid} | Variable | AES-256(sid) |
| dp_len | 2 bytes | DP length |
| dp | Variable | FSID or H(FSID) |

#### Generating PAKE-2 (pqc_ap_sm.c)

```c
int hostapd_pqc_handle_pake1(struct hostapd_data *hapd, struct sta_info *sta)
{
    u8 K[64], id[16], sid[16], enc_sid[32];
    size_t enc_sid_len = 0;
    u8 fsid[64];
    size_t fsid_len = 0;
    u8 buf[1500];
    size_t buf_len;
    struct pqc_pake2_fields f;

    /* ML-KEM.decaps */
    pqc_kem_decaps(hapd->conf->pqc_kem_id,
                   hapd->conf->pqc_kem_sk,
                   sta->pqc_pake1_ct, sta->pqc_pake1_ct_len,
                   K, sizeof(K));

    /* AES-decrypt {id} */
    pqc_aes_decrypt(sta->pqc_pake1_enc_id,
                    sta->pqc_pake1_enc_id_len,
                    id, sizeof(id));

    /* random sid */
    os_get_random(sid, sizeof(sid));

    /* fsid = sid || id || MAC_AP || MAC_STA */
    os_memcpy(fsid, sid, 16);
    os_memcpy(fsid + 16, id, 16);
    os_memcpy(fsid + 32, hapd->own_addr, ETH_ALEN);
    os_memcpy(fsid + 32 + ETH_ALEN, sta->addr, ETH_ALEN);
    fsid_len = 32 + 2 * ETH_ALEN;

    /* encrypt sid */
    pqc_aes_encrypt(sid, sizeof(sid), enc_sid, &enc_sid_len);

    /* build PAKE-2 */
    f.pake_type = PQC_PAKE_TYPE_2;
    f.enc_sid = enc_sid;
    f.sid_len = enc_sid_len;
    f.dp = fsid;
    f.dp_len = fsid_len;

    buf_len = pqc_build_pake2(buf, sizeof(buf), &f);

    return hostapd_pqc_send_pake2(hapd, sta, buf, buf_len);
}
```

#### Sending PAKE-2

```c
int hostapd_pqc_send_pake2(struct hostapd_data *hapd,
                           struct sta_info *sta,
                           const u8 *payload, size_t payload_len)
{
    struct wpabuf *buf = wpabuf_alloc(5 + payload_len);

    wpabuf_put_u8(buf, WLAN_ACTION_VENDOR_SPECIFIC);
    wpabuf_put_u8(buf, PQC_OUI_0);
    wpabuf_put_u8(buf, PQC_OUI_1);
    wpabuf_put_u8(buf, PQC_OUI_2);
    wpabuf_put_u8(buf, PQC_OUI_TYPE_PAKE);
    wpabuf_put_u8(buf, PQC_PAKE_TYPE_2);

    wpabuf_put_data(buf, payload, payload_len);

    return hostapd_drv_send_action(hapd, hapd->iface->freq, 0,
                                   sta->addr,
                                   wpabuf_head(buf),
                                   wpabuf_len(buf));
}
```

---

### STA-Side Implementation (wpa_supplicant)

#### Generating PAKE-1

```c
int wpas_pqc_send_pake1(struct wpa_supplicant *wpa_s)
{
    u8 id[16], enc_id[32], c[1024];
    size_t enc_id_len = 0, c_len = 0;
    u8 buf[1500];
    size_t buf_len;
    struct pqc_pake1_fields f;

    os_get_random(id, sizeof(id));
    pqc_aes_encrypt(id, sizeof(id), enc_id, &enc_id_len);

    pqc_kem_encaps(wpa_s->pqc->ap_kem_id,
                   wpa_s->pqc->ap_kem_pub,
                   c, &c_len,
                   wpa_s->pqc->shared_secret);

    f.pake_type = PQC_PAKE_TYPE_1;
    f.c = c;
    f.c_len = c_len;
    f.enc_id = enc_id;
    f.id_len = enc_id_len;

    buf_len = pqc_build_pake1(buf, sizeof(buf), &f);

    return wpa_drv_send_action(wpa_s, 0, 0,
                               wpa_s->bssid,
                               buf, buf_len, 0);
}
```

#### Receiving PAKE-2

```c
int pqc_sm_rx_pake2(struct wpa_pqc_sm *sm,
                    const u8 *enc_sid, size_t sid_len,
                    const u8 *dp, size_t dp_len)
{
    u8 sid[16];

    pqc_aes_decrypt(enc_sid, sid_len, sid, sizeof(sid));

    sm->sid_len = sizeof(sid);
    os_memcpy(sm->sid, sid, sizeof(sid));

    /* dp = fsid */
    sm->fsid = os_memdup(dp, dp_len);
    sm->fsid_len = dp_len;

    /* ML-KEM keygen + 2F */
    pqc_kem_keygen(sm->kem_id, sm->pk, sm->sk);

    pqc_2f_network(sm->pwd, sm->pwd_len,
                   sm->r, sm->Z,
                   sm->s, sm->T);

    return wpas_pqc_send_pake3(sm);
}
```


**/wpa_supplicant/pqc.c - static int pqc_2f_network**,  mathematic helper function.  

**PQC PAKE-3 frame format**

| Field          | Length    | Description                                   |
|----------------|-----------|-----------------------------------------------|
| Category       | 1 byte    | 127 (Vendor Specific Action Frame)            |
| OUI            | 3 bytes   | 00 90 4C (test OUI)                           |
| Type / Subtype | 1 byte    | 0x03 (PAKE-3 identification)                  |
| Payload (s)    | 32 bytes  | Output value 's' from 2-round Feistel network |
| Payload (T)    | Variable  | Output value 'T' from 2-round Feistel network |


**/wpa_supplicant/pqc_sm.c - static int wpas_pqc_send_pake3**, builds and computes parameters needed for pake3 frame, uses information saved in state machine previously. After that it tries to send Vendor Specific Action frame using ```wpa_drv_send_action``` function.  
  
**/wpa_supplicant/pqc_sm.c - int pqc_sm_rx_pake2**, used for parsing and processing information (which is later saved in PQC STA state) based on received PAKE2 frame. Saves AP's public DSA key and decrypted sid, generates ML-KEM keys. 

**/wpa_supplicant/events.c**
After receing vendor specific action frame checks are performed in order to determine whether the frame is the one used in PAKE scheme. For now only PAKE-2 is checked (subtype = 0x02). After correct identification PAKE-2 parser function is called.  

# Helpful functions

### int os_get_random(unsigned char *buf, size_t len)
**/src/utils/os.h**  
Used for delivering randomness, in the future, change to download randomness from the tpm module
* buf: Buffer for pseudo random data
* len: Length of the buffer
* returns: 0 - success, -1 - failure

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
