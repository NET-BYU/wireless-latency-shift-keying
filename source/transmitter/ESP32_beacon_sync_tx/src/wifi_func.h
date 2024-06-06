#include <aes/esp_aes.h>
#include <fec.h>

#include "esp_event.h"
#include "esp_event_loop.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "mbedtls/md.h"
#include "nvs_flash.h"

#define ENC_KEY = "9=8[&tR+6}8?=487"
#define INT_KEY = "$B9;8/27.)>24;9T"

const float STRAP_LOSS[4] = {0.8, 0.6, 0.4, 0.2};

static wifi_country_t wifi_country = {
    .cc = "US", .schan = 1, .nchan = 13};  // Most recent esp32 library struct

typedef struct {
  unsigned protocol : 2;
  unsigned type : 2;
  unsigned subtype : 4;
  unsigned to_ds : 1;
  unsigned from_ds : 1;
  unsigned more_frag : 1;
  unsigned retry : 1;
  unsigned pwr_mgmt : 1;
  unsigned more_data : 1;
  unsigned wep : 1;
  unsigned strict : 1;
} wifi_header_frame_control_t;

// https://carvesystems.com/news/writing-a-simple-esp8266-based-sniffer/
typedef struct {
  wifi_header_frame_control_t frame_ctrl;
  //    unsigned duration_id : 16;
  uint8_t addr1[6]; /* receiver MAC address */
  uint8_t addr2[6]; /* sender MAC address */
  uint8_t addr3[6]; /* BSSID filtering address */
  unsigned sequence_ctrl : 16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

typedef struct {
  unsigned interval : 16;
  unsigned capability : 16;
  unsigned tag_number : 8;
  unsigned tag_length : 8;
  char ssid[0];
  uint8_t rates[1];
} wifi_beacon_hdr;

typedef struct {
  uint8_t mac[6];
} __attribute__((packed)) mac_addr;

typedef struct {
  uint16_t seq;
  uint8_t payload[7];
} strap_msg_frag_t;

typedef struct {
  uint8_t k;
  uint8_t m;
  strap_msg_frag_t *msg_frags;
} strap_msg_t;

typedef enum {
  ASSOCIATION_REQ,
  ASSOCIATION_RES,
  REASSOCIATION_REQ,
  REASSOCIATION_RES,
  PROBE_REQ,
  PROBE_RES,
  NU1, /* ......................*/
  NU2, /* 0110, 0111 not used */
  BEACON,
  ATIM,
  DISASSOCIATION,
  AUTHENTICATION,
  DEAUTHENTICATION,
  ACTION,
  ACTION_NACK,
} wifi_mgmt_subtypes_t;

const wifi_promiscuous_filter_t filt = {.filter_mask =
                                            WIFI_PROMIS_FILTER_MASK_DATA};

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(
    wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff,
                                        wifi_promiscuous_pkt_type_t type);
static void wifi_scan_addr_handler(void *buff,
                                   wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_main(uint8_t source_address[6]);

bool ledState = false;

void ledOff() { digitalWrite(GPIO_NUM_2, LOW); }

void ledOn() { digitalWrite(GPIO_NUM_2, HIGH); }

void ledToggle() {
  ledState = !ledState;
  digitalWrite(GPIO_NUM_2, ledState);
}

void wifi_sniffer_main(uint8_t source_address[6]) {
  esp_wifi_set_promiscuous(
      false);  // bring down to change things, then bring it back up
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  // ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_STA, source_address)); // this
  // needs to be done to receive ACK from injected packet
  esp_wifi_set_mac(WIFI_IF_STA,
                   source_address);  // this needs to be done to receive ACK
                                     // from injected packet
  ESP_ERROR_CHECK(esp_wifi_start());
  esp_wifi_set_promiscuous(true);
  //     esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

esp_err_t event_handler(void *ctx, system_event_t *event) { return ESP_OK; }

void wifi_sniffer_init(void) {
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_start());
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_scan_addr_handler);
  fec_init();
}

void wifi_sniffer_stop(void) { esp_wifi_stop(); }

void wifi_sniffer_set_channel(uint8_t channel) {
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type) {
  switch (type) {
    case WIFI_PKT_MGMT:
      return "MGMT";
    case WIFI_PKT_DATA:
      return "DATA";
    default:
    case WIFI_PKT_MISC:
      return "MISC";
  }
}

volatile uint8_t beacon_detected = 0;
int16_t rssi_value;
uint8_t addr_found = 0;

//// this needs to be cleaned up to not transfer every packet to a struct but
/// rather just look at the bits
// looking for the mac address of the router we are targeting. Should give a
// speed boost.
/// as for right now, just change the ssid it is checking against
void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  // https://blog.podkalicki.com/wp-content/uploads/2017/01/esp32_promiscuous_pkt_structure.jpeg
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt =
      (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  // From
  // https://github.com/SHA2017-badge/bpp/blob/master/esp32-recv/main/bpp_sniffer.c
  // https://github.com/n0w/esp8266-simple-sniffer/blob/master/src/main.cpp
  char ssid[32] = {0};

  const wifi_header_frame_control_t *fctl =
      (wifi_header_frame_control_t *)&hdr->frame_ctrl;

  // Details about beacon frames:
  // https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/
  if (fctl->subtype == BEACON) {  // beacon
    wifi_beacon_hdr *beacon = (wifi_beacon_hdr *)ipkt->payload;

    if (beacon->tag_length >= 32) {
      strncpy(ssid, beacon->ssid, 31);
    } else {
      strncpy(ssid, beacon->ssid, beacon->tag_length);
    }
    // Serial.printf("Beacon %s\n", ssid);
    // if (!(strcmp(ssid, "NETGEAR22")))
    // if (!(strcmp(ssid, "WLSK-NET-2G")))
    if (!(strcmp(ssid, "DD-WRT-2G"))) {
      beacon_detected = 1;  // Beacon frame found, inform main loop
      int16_t temp = (int16_t)((wifi_pkt_rx_ctrl_t)ppkt->rx_ctrl).rssi;
      // Serial.println(temp);
      rssi_value = temp;
      // memcpy(&temp,(void*)(&rssi_value),2);
      // Serial.println(rssi_value);
    }
  }
}

void mac2str(const uint8_t *ptr, char *string) {
#ifdef MASKED
  sprintf(string, "XX:XX:XX:%02x:%02x:XX", ptr[0], ptr[1], ptr[2], ptr[3],
          ptr[4], ptr[5]);
#else
  sprintf(string, "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1], ptr[2],
          ptr[3], ptr[4], ptr[5]);
#endif
  return;
}
// debug stuff
char addr1[] = "00:00:00:00:00:00\0";
char addr2[] = "00:00:00:00:00:00\0";
char addr3[] = "00:00:00:00:00:00\0";
uint8_t router_mac[6];
uint8_t ping_target_mac[6];

// Keep track of unique sequence numbers
strap_msg_frag_t *unique_msg_frag =
    (strap_msg_frag_t *)malloc(1024 * sizeof(strap_msg_frag_t));
strap_msg_t msg = {0, 0, unique_msg_frag};
uint16_t seq_index = 0;
uint8_t received_enough_pkts = 0;

void wifi_scan_addr_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
  // Print out the packet
  // Serial.println("New Packet!");
  // Serial.println(wifi_sniffer_packet_type2str(type));

  if (type != WIFI_PKT_DATA) {  // looking for tcp syn packet
    return;
  }
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt =
      (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  // If address 3 of header does not begin with 33:33, then ignore packet
  if (hdr->addr3[0] == 0x33 && hdr->addr3[1] == 0x33) {
    // Header is bytes 3-5 of addr3
    uint8_t *header = (uint8_t *)malloc(3 * sizeof(uint8_t));
    memcpy(header, hdr->addr2, 3);

    // ID is bits 0-5 of header
    uint8_t id = (header[0] & 0xFC) >> 2;

    if (id != 0x12) {
      // Serial.println("ID is not 0x12");
      return;
    }

    uint8_t set_bits = header[0] & 0x03;

    // Flag is bit 8 of header
    uint8_t flag = (header[1] & 0x80) >> 7;

    // Index for redundancy amount is bits 9-10 of header
    uint8_t index = (header[1] & 0x60) >> 5;

    // Total packets in tx is bits 11-16 of header
    uint8_t total = ((header[1] & 0x1F) << 1 | (header[2] & 0x80) >> 7) << 1;

    // Sequence number is bits 17-23 of header
    uint8_t seq = (header[2] & 0x7F);

    // Print header
    Serial.print("Header: ");
    for (int i = 0; i < 3; i++) {
      Serial.printf("%02X", header[i]);
      Serial.print(" ");
    }
    Serial.println();

    // Print out header fields
    Serial.print("ID: ");
    Serial.printf("0x%02X\n", id);
    Serial.print("Set bits: ");
    Serial.println(set_bits);
    Serial.print("Flag: ");
    Serial.println(flag);
    Serial.print("Index: ");
    Serial.println(index);
    Serial.print("Total: ");
    Serial.println(total);
    Serial.print("Sequence: ");
    Serial.println(seq);

    // Payload is last byte of addr3 and all of addr 2
    uint8_t payload[7];
    for (int i = 0; i < 7; i++) {
      payload[0] = hdr->addr2[3];
      payload[1] = hdr->addr2[4];
      payload[2] = hdr->addr2[5];
      payload[3] = hdr->addr3[2];
      payload[4] = hdr->addr3[3];
      payload[5] = hdr->addr3[4];
      payload[6] = hdr->addr3[5];
    }
    // memcpy(payload, hdr->addr2 + 3, 3);
    // memcpy(payload + 3, hdr->addr3 + 2, 4);

    // Print out payload
    Serial.print("Payload: ");
    for (int i = 0; i < 7; i++) {
      Serial.printf("%02X", payload[i]);
      Serial.print(" ");
    }
    Serial.println();

    strap_msg_frag_t *msg_frag =
        (strap_msg_frag_t *)malloc(sizeof(strap_msg_frag_t));
    msg_frag->seq = seq;
    memcpy(msg_frag->payload, payload, 7);

    bool unique = true;

    if (seq_index == 0) {
      msg.msg_frags[seq_index] = *msg_frag;
      seq_index++;
      msg.m = total;
      msg.k = floor(total * (1 - STRAP_LOSS[index]));
    } else {  // Check if sequence number is unique
      for (int i = 0; i < seq_index; i++) {
        Serial.println("Checking sequence number");
        Serial.println(unique_msg_frag[i].seq);
        Serial.println(seq);
        if (unique_msg_frag[i].seq == seq) {
          Serial.println("Duplicate sequence number");
          unique = false;
          break;
        }
      }
      if (unique) {
        Serial.println("Unique sequence number");
        Serial.println(seq);
        msg.msg_frags[seq_index] = *msg_frag;
        seq_index++;
      }
    }

    if (seq_index == msg.k + 1) {
      Serial.println(seq_index);
      Serial.println("Enough packets received");
      received_enough_pkts = 1;

      fec_t *fec_r = fec_new(msg.k, msg.m);
      int *index = (int *)malloc(msg.k * sizeof(int));

      // Initialize index
      for (int i = 0; i < msg.k; i++) {
        index[i] = -1;
      }

      // Place primary indeces in correct location
      for (int i = 0; i < msg.k; i++) {
        uint8_t seq = msg.msg_frags[i].seq;
        if (seq < msg.k) index[seq] = seq;
      }

      // Place secondary indeces in available locations
      uint8_t num_of_sec = 0;
      for (int i = 0; i < msg.k; i++) {
        if (msg.msg_frags[i].seq >= msg.k) {
          num_of_sec++;
          for (int j = 0; j < msg.k; j++) {
            if (index[j] == -1) {
              index[j] = msg.msg_frags[i].seq;
              break;
            }
          }
        }
      }

      unsigned char **received_packets =
          (unsigned char **)malloc(msg.k * sizeof(unsigned char *));
      for (int i = 0; i < msg.k; i++) {
        for (int j = 0; j < msg.k; j++) {
          if (msg.msg_frags[j].seq == index[i]) {
            received_packets[i] =
                (unsigned char *)malloc(7 * sizeof(unsigned char));
            memcpy(received_packets[i], msg.msg_frags[j].payload, 7);
            break;
          }
        }
      }

      // Print received packets
      Serial.println("Received packets:");
      for (int i = 0; i < msg.k; i++) {
        Serial.print("Seq:\t");
        Serial.print(index[i]);
        Serial.print("\tPayload:\t");
        for (int j = 0; j < 7; j++) {
          Serial.printf("%02X", received_packets[i][j]);
          Serial.print(" ");
        }
        Serial.println();
      }
      Serial.println();

      // Print index
      Serial.print("Index: ");
      for (int i = 0; i < msg.k; i++) {
        Serial.print(index[i]);
        Serial.print(" ");
      }
      Serial.println();

      unsigned char **recovered_packets =
          (unsigned char **)malloc(msg.k * sizeof(unsigned char *));

      for (int i = 0; i < msg.k; i++) {
        recovered_packets[i] =
            (unsigned char *)malloc(7 * sizeof(unsigned char));
      }

      fec_decode(fec_r, (const gf *const *const)received_packets,
                 recovered_packets, (unsigned int *)index, 7);

      // Print recovered packets
      Serial.println("Recovered packets:");
      for (int i = 0; i < num_of_sec; i++) {
        Serial.print("Seq:\t");
        Serial.print(index[i]);
        Serial.print("\tPayload:\t");
        for (int j = 0; j < 7; j++) {
          Serial.printf("%02X", recovered_packets[i][j]);
          Serial.print(" ");
        }
        Serial.println();
      }

      // Reconstruct original message
      char *reconstructed_message =
          (char *)malloc(msg.k * 7 * sizeof(char) + 1);
      int rec_ind = 0;
      for (int i = 0; i < msg.k; i++) {
        if (index[i] < msg.k)
          memcpy(reconstructed_message + (i * 7), received_packets[index[i]],
                 7);
        else
          memcpy(reconstructed_message + (i * 7), recovered_packets[rec_ind++],
                 7);
      }
      reconstructed_message[msg.k * 7] = '\0';

      Serial.printf("Reconstructed message: %s\n", reconstructed_message);

      uint8_t *iv = (uint8_t *)malloc(16 * sizeof(uint8_t));
      uint8_t *gsn = (uint8_t *)malloc(8 * sizeof(uint8_t));
      uint8_t *enc_data = (uint8_t *)malloc(16 * sizeof(uint8_t));
      uint8_t *plaintext = (uint8_t *)malloc(16 * sizeof(uint8_t));
      uint8_t *mac = (uint8_t *)malloc(32 * sizeof(uint8_t));

      memcpy(iv, reconstructed_message, 16);
      memcpy(gsn, reconstructed_message + 16, 8);
      memcpy(enc_data, reconstructed_message + 24, 16);
      memcpy(mac, reconstructed_message + 40, 32);

      // Decrypt message
      esp_aes_context ctx;
      esp_aes_init(&ctx);

      unsigned char enc_key[16] = {'9', '=', '8', '[', '&', 't', 'R', '+',
                                   '6', '}', '8', '?', '=', '4', '8', '7'};
      esp_aes_setkey(&ctx, enc_key, 128);

      esp_aes_crypt_cbc(&ctx, ESP_AES_DECRYPT, sizeof(unsigned char) * 16, iv,
                        (uint8_t *)enc_data, (uint8_t *)plaintext);
      esp_aes_free(&ctx);

      // Print decrypted message
      Serial.print("Decrypted message: ");
      for (int i = 0; i < 16; i++) {
        Serial.printf("%c", plaintext[i]);
        Serial.print(" ");
      }
      Serial.println();

      // Verify MAC
      unsigned char int_key[16] = {'$', 'B', '9', ';', '8', '/', '2', '7',
                                   '.', ')', '>', '2', '4', ';', '9', 'T'};
      unsigned char *gsn_enc_data =
          (unsigned char *)malloc(24 * sizeof(unsigned char));
      memcpy(gsn_enc_data, gsn, 8);
      memcpy(gsn_enc_data + 8, enc_data, 16);
      uint8_t *ver_mac = (uint8_t *)malloc(32 * sizeof(uint8_t));
      mbedtls_md_context_t mac_ctx;
      mbedtls_md_init(&mac_ctx);
      mbedtls_md_setup(&mac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                       1);
      mbedtls_md_hmac_starts(&mac_ctx, int_key, 16);
      mbedtls_md_hmac_update(&mac_ctx, gsn_enc_data, 24);
      mbedtls_md_hmac_finish(&mac_ctx, ver_mac);

      // Print mac an ver_mac
      Serial.print("MAC: ");
      for (int i = 0; i < 32; i++) {
        Serial.printf("%02X", mac[i]);
        Serial.print(" ");
      }
      Serial.println();
      Serial.print("Ver MAC: ");
      for (int i = 0; i < 32; i++) {
        Serial.printf("%02X", ver_mac[i]);
        Serial.print(" ");
      }
      Serial.println();

      // Compare mac and ver_mac using memcmp
      if (memcmp(mac, ver_mac, 32) == 0) {
        Serial.println("MACs match");

        // Reset msg struct
        msg.k = 0;
        msg.m = 0;
        // Reallocate memory for msg_frags
        free(msg.msg_frags);
        msg.msg_frags =
            (strap_msg_frag_t *)malloc(1024 * sizeof(strap_msg_frag_t));
        seq_index = 0;
        received_enough_pkts = 0;
      } else {
        Serial.println("MACs do not match");
      }

      // Free memory
      free(index);
      free(received_packets);
      free(recovered_packets);
      free(reconstructed_message);
      free(iv);
      free(gsn);
      free(enc_data);
      free(plaintext);
      free(mac);
      free(gsn_enc_data);
      free(ver_mac);
    }

    if (!received_enough_pkts) {
      // Print sequences
      Serial.printf("K:\t%d\tM:\t%d\n", msg.k, msg.m);
      Serial.print("Unique sequences:\n");
      for (int i = 0; i < seq_index; i++) {
        Serial.print("Seq:\t");
        Serial.print(msg.msg_frags[i].seq);
        Serial.print("\tPayload:\t");
        for (int j = 0; j < 7; j++) {
          Serial.printf("%02X", msg.msg_frags[i].payload[j]);
          Serial.print(" ");
        }
        Serial.println();
      }
      Serial.println();
    }

    // Free memory
    free(header);
    // free(payload);

    // debug stuff
    mac2str(hdr->addr1, addr1);
    mac2str(hdr->addr2, addr2);
    mac2str(hdr->addr3, addr3);
    Serial.print(addr1);
    Serial.print("\t");
    Serial.print(addr2);
    Serial.print("\tThis is the good stuff:\t");
    Serial.print(addr3);
    Serial.println("\t\t");
    Serial.println();
  }

  // // Print MAC address of source and destination
  // Serial.print("Source MAC: ");
  // for (int i = 0; i < 6; i++)
  // {
  //     Serial.printf("%02X", hdr->addr2[i]); // Print each byte with leading
  //     zeros if (i < 5)
  //         Serial.print(":");
  // }
  // Serial.println();

  // Serial.print("Destination MAC: ");
  // for (int i = 0; i < 6; i++)
  // {
  //     Serial.printf("%02X", hdr->addr1[i]); // Print each byte with leading
  //     zeros if (i < 5)
  //         Serial.print(":");
  // }
  // Serial.println();

  // // Access the payload of the packet
  // const uint8_t *payload = ipkt->payload;

  // // Print the payload byte by byte
  // Serial.println("Payload:");
  // for (int i = 0; i < ppkt->rx_ctrl.sig_len; i++)
  // {
  //     Serial.printf("%02X", payload[i]);
  //     Serial.print(" ");
  // }
  // Serial.println();

  // check against the who is the source
  if (hdr->addr3[0] == 0xDE && hdr->addr3[1] == 0xAD && hdr->addr3[2] == 0xBE &&
      hdr->addr3[3] == 0xEF && hdr->addr3[4] == 0xDE &&
      hdr->addr3[5] == 0xAD) {  // found the right packets
    memcpy(router_mac, hdr->addr2, 6);
    memcpy(ping_target_mac, hdr->addr1, 6);
    addr_found = 1;
  }
  // // debug stuff
  // mac2str(hdr->addr1, addr1);
  // mac2str(hdr->addr2, addr2);
  // mac2str(hdr->addr3, addr3);
  // Serial.print(addr1);
  // Serial.print("\t");
  // Serial.print(addr2);
  // Serial.print("\tThis is the good stuff:\t");
  // Serial.print(addr3);
  // Serial.println("\t\t");
}
