#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"

static wifi_country_t wifi_country = {.cc = "US", .schan = 1, .nchan = 13}; // Most recent esp32 library struct

typedef struct
{
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
typedef struct
{
    wifi_header_frame_control_t frame_ctrl;
//    unsigned duration_id : 16;
    uint8_t addr1[6]; /* receiver MAC address */
    uint8_t addr2[6]; /* sender MAC address */
    uint8_t addr3[6]; /* BSSID filtering address */
    unsigned sequence_ctrl : 16;
    uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct
{
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

typedef struct
{
    unsigned interval : 16;
    unsigned capability : 16;
    unsigned tag_number : 8;
    unsigned tag_length : 8;
    char ssid[0];
    uint8_t rates[1];
} wifi_beacon_hdr;

typedef struct
{
    uint8_t mac[6];
} __attribute__((packed)) mac_addr;

typedef enum
{
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

const wifi_promiscuous_filter_t filt = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA};

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
static void wifi_scan_addr_handler(void *buff, wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_main(uint8_t source_address[6]);

bool ledState = false;

void ledOff() {
  digitalWrite(GPIO_NUM_2, LOW);
}

void ledOn() {
  digitalWrite(GPIO_NUM_2, HIGH);
}

void ledToggle() {
  ledState = !ledState;
  digitalWrite(GPIO_NUM_2, ledState);
}

void wifi_sniffer_main(uint8_t source_address[6]) {
    esp_wifi_set_promiscuous(false); // bring down to change things, then bring it back up
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_STA, source_address)); // this needs to be done to receive ACK from injected packet
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_promiscuous(true);
    //     esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

esp_err_t event_handler(void *ctx, system_event_t *event)
{
    return ESP_OK;
}

void wifi_sniffer_init(void)
{
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
}

void wifi_sniffer_stop(void)
{
    esp_wifi_stop();
}

void wifi_sniffer_set_channel(uint8_t channel)
{
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
    switch (type)
    {
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

//// this needs to be cleaned up to not transfer every packet to a struct but rather just look at the bits
// looking for the mac address of the router we are targeting. Should give a speed boost.
/// as for right now, just change the ssid it is checking against
void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT)
        return;
    // https://blog.podkalicki.com/wp-content/uploads/2017/01/esp32_promiscuous_pkt_structure.jpeg
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    // From https://github.com/SHA2017-badge/bpp/blob/master/esp32-recv/main/bpp_sniffer.c
    // https://github.com/n0w/esp8266-simple-sniffer/blob/master/src/main.cpp
    char ssid[32] = {0};

    const wifi_header_frame_control_t *fctl = (wifi_header_frame_control_t *)&hdr->frame_ctrl;

    // Details about beacon frames: https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/
    if (fctl->subtype == BEACON)
    { // beacon
        wifi_beacon_hdr *beacon = (wifi_beacon_hdr *)ipkt->payload;

        if (beacon->tag_length >= 32)
        {
            strncpy(ssid, beacon->ssid, 31);
        }
        else
        {
            strncpy(ssid, beacon->ssid, beacon->tag_length);
        }
        // Serial.printf("Beacon %s\n", ssid);
        // if (!(strcmp(ssid, "NETGEAR22")))
        if (!(strcmp(ssid, "WLSK-NET-2G")))
        {
            beacon_detected = 1; // Beacon frame found, inform main loop
            int16_t temp = (int16_t)((wifi_pkt_rx_ctrl_t)ppkt->rx_ctrl).rssi;
            // Serial.println(temp);
            rssi_value = temp;
            // memcpy(&temp,(void*)(&rssi_value),2);
            // Serial.println(rssi_value);
        }
    }
}

void mac2str(const uint8_t* ptr, char* string)
{
  #ifdef MASKED
  sprintf(string, "XX:XX:XX:%02x:%02x:XX", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
  #else
  sprintf(string, "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
  #endif
  return;
}
// debug stuff
char addr1[] = "00:00:00:00:00:00\0";
  char addr2[] = "00:00:00:00:00:00\0";
  char addr3[] = "00:00:00:00:00:00\0";
uint8_t router_mac[6];
uint8_t ping_target_mac[6];

void wifi_scan_addr_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA) { // looking for tcp syn packet
    return;
  }
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  // check against the who is the source
  if (hdr->addr3[0] == 0xDE &&
  hdr->addr3[1] == 0xAD  &&
  hdr->addr3[2] == 0xBE  && 
  hdr->addr3[3] == 0xEF  && 
  hdr->addr3[4] == 0xDE &&
  hdr->addr3[5] == 0xAD ) { // found the right packets
    memcpy(router_mac,hdr->addr2,6);
    memcpy(ping_target_mac,hdr->addr1,6);
    addr_found = 1;
  }
  // debug stuff
//    mac2str(hdr->addr1, addr1);
//  mac2str(hdr->addr2, addr2);
//  mac2str(hdr->addr3, addr3);
//  Serial.print(addr1);
//  Serial.print("\t");
//  Serial.print(addr2);
//  Serial.print("\t");
//  Serial.print(addr3);
//  Serial.println("\t\t");
}