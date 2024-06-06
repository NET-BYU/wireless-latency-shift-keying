#include "wifi_func.h"

// #define DADDR 0xd8 ,0xec ,0x5e ,0x13 ,0xb2 ,0x15
#define DADDR 0xbc, 0xa5, 0x11, 0x20, 0x08, 0x3b
// #define SADDR 0x76, 0x8a, 0x3d, 0x34, 0x6b, 0xf3
#define SADDR 0xe4, 0x5f, 0x01, 0x13, 0x27, 0xb2

typedef enum
{
  GUARD = 0,
  BARKER_ONE = 1,
  BARKER_ZERO = 2,
  PREAMBLE = 3,
} wlskState_t;

typedef struct
{
  wlskState_t state = GUARD;
  uint8_t txDataIdx = 0;
  uint8_t barkerIdx = 0;
  bool start = false;
} wlskStateHandle_t;

uint8_t channel = 3;
hw_timer_t *timeoutTimer = NULL;
bool timeout = false;
uint32_t timeoutCount = 0;
uint32_t timeoutCountLimit = 5;
uint8_t rx_char = 0;

wlskStateHandle_t stateHandle;

// Data to transmit
uint8_t txData_0[32] = {1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
                        1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1};
uint8_t txData_1[32] = {1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
                        0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0};
uint8_t txData_2[32] = {1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0,
                        0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0};
uint8_t txData_3[32] = {1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1,
                        0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1};
uint8_t txData_4[32] = {1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0,
                        1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0};
uint8_t txData_5[32] = {1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1,
                        1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1};
uint8_t txData_6[32] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0,
                        0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0};
uint8_t txData_7[32] = {1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1,
                        0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0};
uint8_t txData_8[32] = {1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0,
                        0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1};
uint8_t txData_9[32] = {1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1,
                        1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0};

uint8_t transmitData[32] = {0};

void selectTxData(uint8_t idx)
{
  switch (idx)
  {
  case 0:
    memcpy(transmitData, txData_0, sizeof(transmitData));
    break;
  case 1:
    memcpy(transmitData, txData_1, sizeof(transmitData));
    break;
  case 2:
    memcpy(transmitData, txData_2, sizeof(transmitData));
    break;
  case 3:
    memcpy(transmitData, txData_3, sizeof(transmitData));
    break;
  case 4:
    memcpy(transmitData, txData_4, sizeof(transmitData));
    break;
  case 5:
    memcpy(transmitData, txData_5, sizeof(transmitData));
    break;
  case 6:
    memcpy(transmitData, txData_6, sizeof(transmitData));
    break;
  case 7:
    memcpy(transmitData, txData_7, sizeof(transmitData));
    break;
  case 8:
    memcpy(transmitData, txData_8, sizeof(transmitData));
    break;
  case 9:
  default:
    memcpy(transmitData, txData_9, sizeof(transmitData));
    break;
  }
}

uint8_t transmitDataLen = sizeof(transmitData) / sizeof(transmitData[0]);
uint8_t barkerOne[11] = {1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0};
uint8_t barkerZero[11] = {0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1};
uint8_t preamble[31] = {1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0,
                        0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0};

uint8_t barkerOneLen = sizeof(barkerOne) / sizeof(barkerOne[0]);
uint8_t barkerZeroLen = sizeof(barkerZero) / sizeof(barkerZero[0]);
uint8_t preambleLen = sizeof(preamble) / sizeof(preamble[0]);

// Wifi Packet Definition
uint8_t packet3[24] = {0x48, 0x11, 0x3c, 0x00, DADDR, SADDR, DADDR, 0xf0, 0x36};
uint8_t packet3_awake[24] = {0x48, 0x01, 0x8c, 0x00, DADDR,
                             SADDR, DADDR, 0xf0, 0x36};

static bool firstTime = true;
// int rssi_average = 0;
uint8_t rssi_count = 0;

void printState(wlskStateHandle_t *stateHandle)
{
  switch (stateHandle->state)
  {
  case GUARD:
    Serial.printf("Iteration of state: GUARD\r\n");
    break;
  case BARKER_ONE:
    Serial.printf("Iteration of state: BARKER_ONE\r\n");
    break;
  case BARKER_ZERO:
    Serial.printf("Iteration of state: BARKER_ZERO\r\n");
    break;
  }
}

void transmitNullSleep()
{
  esp_wifi_80211_tx(WIFI_IF_STA, packet3, sizeof(packet3),
                    true); // Null STA will go to sleep
}

void transmitNullAwake()
{
  esp_wifi_80211_tx(WIFI_IF_STA, packet3_awake, sizeof(packet3),
                    true); // Null STA wiill stay awake
}

void shiftNetworkLatency()
{
  ledOn();
  delay(10);
  transmitNullSleep();
  delay(3);
  transmitNullSleep();
  delay(80);
  transmitNullAwake();
  delay(3);
  transmitNullAwake();
  ledOff();
}

void wlskStateMachineIteration(wlskStateHandle_t *stateHandle)
{
  printState(stateHandle);  // Debug: print out current state
  switch (stateHandle->state)
  {
  case GUARD:
    // Do nothing unless flag is set to start
    if (stateHandle->start)
    {
      stateHandle->start = false;
      stateHandle->state = PREAMBLE;
      Serial.printf("State set to PREAMBLE\r\n");
    }
    break;
  case PREAMBLE:
    if (preamble[stateHandle->barkerIdx] == 1)
    {
      // Send a null frame
      shiftNetworkLatency();
      // ledOn();
    }
    else
    {
      // Do nothing this state machine iteration
      // ledOff();
    }
    stateHandle->barkerIdx++;
    // Check here if we need state change
    if (stateHandle->barkerIdx >= preambleLen)
    {
      // Done with Preamble, move to the next state
      stateHandle->txDataIdx = 0;
      stateHandle->barkerIdx = 0;
      if (transmitData[0] == 1)
      {
        stateHandle->state = BARKER_ONE;
      }
      else
      {
        stateHandle->state = BARKER_ZERO;
      }
    }
    break;
  case BARKER_ONE:
    if (stateHandle->barkerIdx < barkerOneLen)
    {
      if (barkerOne[stateHandle->barkerIdx] == 1)
      {
        // Send a null frame
        shiftNetworkLatency();
        // ledOn();
      }
      else
      {
        // Do nothing this state machine iteration
        // ledOff();
      }
      stateHandle->barkerIdx++;
      // Check here if we need state change
      if (stateHandle->barkerIdx >= barkerOneLen)
      {
        if (stateHandle->txDataIdx < transmitDataLen - 1)
        {
          // Have another transmit data bit. Determine what it is
          stateHandle->txDataIdx++;
          stateHandle->barkerIdx = 0;
          if (transmitData[stateHandle->txDataIdx] == 1)
          {
            stateHandle->state = BARKER_ONE;
          }
          else
          {
            stateHandle->state = BARKER_ZERO;
          }
        }
        else
        {
          // We are done with the transmit data, return to guard state
          stateHandle->txDataIdx = 0;
          stateHandle->barkerIdx = 0;
          stateHandle->state = GUARD;
          Serial.flush();
          Serial.print("Done, waiting for input...\r\n");
          firstTime = true;
          wifi_sniffer_stop();
          wifi_sniffer_init();
          wifi_sniffer_set_channel(channel);
        }
      }
    }
    break;
  case BARKER_ZERO:
    if (stateHandle->barkerIdx < barkerZeroLen)
    {
      if (barkerZero[stateHandle->barkerIdx] == 1)
      {
        // Send a null frame
        shiftNetworkLatency();
        // ledOn();
      }
      else
      {
        // Do nothing this state machine iteration
        // ledOff();
      }
      stateHandle->barkerIdx++;
      // Check here if we need state change
      if (stateHandle->barkerIdx >= barkerOneLen)
      {
        if (stateHandle->txDataIdx < transmitDataLen - 1)
        {
          // Have another transmit data bit. Determine what it is
          stateHandle->txDataIdx++;
          stateHandle->barkerIdx = 0;
          if (transmitData[stateHandle->txDataIdx] == 1)
          {
            stateHandle->state = BARKER_ONE;
          }
          else
          {
            stateHandle->state = BARKER_ZERO;
          }
        }
        else
        {
          // We are done with the transmit data, return to guard state
          stateHandle->txDataIdx = 0;
          stateHandle->barkerIdx = 0;
          stateHandle->state = GUARD;
          Serial.flush();
          Serial.print("Done, waiting for input...\r\n");
          firstTime = true;
          wifi_sniffer_stop();
          wifi_sniffer_init();
          wifi_sniffer_set_channel(channel);
        }
      }
    }
    break;
  default:
    break;
  }
}

void IRAM_ATTR onTimeout()
{
  // We missed a beacon, just pretend that we got it.
  timeout = true;
}

void startTimeoutTimer()
{
  timeoutTimer = timerBegin(0, 80, true);
  timerAttachInterrupt(timeoutTimer, &onTimeout, false);
  timerAlarmWrite(timeoutTimer, 110000, false);
  timerAlarmEnable(timeoutTimer);
}

void stopTimeoutTimer()
{
  if (timeoutTimer != NULL)
  {
    timerStop(timeoutTimer);
  }
}

void restartTimeoutTimer()
{
  if (timeoutTimer != NULL)
  {
    timerRestart(timeoutTimer);
    timerAlarmEnable(timeoutTimer);
  }
}

void setup()
{
  // Initialize the index locations
  stateHandle.barkerIdx = 0;
  stateHandle.txDataIdx = 0;
  stateHandle.state = GUARD;

  Serial.begin(115200);
  delay(10);
  // uint8_t sa[6] = {SADDR};
  wifi_sniffer_init();
  wifi_sniffer_set_channel(channel);
  pinMode(GPIO_NUM_2, OUTPUT);
  startTimeoutTimer();
  firstTime = true;
}

void loop()
{
  // // Block on input from the Serial.
  if (firstTime && Serial.available())
  {
    // Execute this the first time around. Don't reset until done
    // transmitting
    firstTime = false;

    // Character on RX buffer, clear the buffer
    rx_char = Serial.read();
    uint8_t tx_seq_num = rx_char - 48;
    if ((tx_seq_num >= 0) && (tx_seq_num <= 9))
    {
      selectTxData(tx_seq_num);
      Serial.printf("Sending sequence %d", tx_seq_num);
    }
    else
    {
      Serial.printf("Invalid Entry\r\n");
      firstTime = true;
      return;
    }
    // Wait until we find the 0xdeadbeefdead mac address
    ADDR_FOUND = false;
    while (!ADDR_FOUND)
    {
      // TODO: Put a timeout here so that we reset if we get start char but
      // don't find address
      delay(1000);
      Serial.printf("Scanning for LSK service..\r\n");
    }
    // Delay once we find it
    delay(1000);

    // Init the wifi again and start
    mac2str(ROUTER_MAC, addr1);
    mac2str(PING_TARGET_MAC, addr3);
    Serial.print(addr1);
    Serial.print("\t");
    Serial.print(addr2);
    Serial.print("\t");
    Serial.print(addr3);
    Serial.println("\t\t");
    ADDR_FOUND = 0;
    wifi_sniffer_main(PING_TARGET_MAC);

    // Update Packets
    memcpy(&packet3[4 + 0 * 6], &ROUTER_MAC, 6);
    memcpy(&packet3[4 + 1 * 6], &PING_TARGET_MAC, 6);
    memcpy(&packet3[4 + 2 * 6], &ROUTER_MAC, 6);

    memcpy(&packet3_awake[4 + 0 * 6], &ROUTER_MAC, 6);
    memcpy(&packet3_awake[4 + 1 * 6], &PING_TARGET_MAC, 6);
    memcpy(&packet3_awake[4 + 2 * 6], &ROUTER_MAC, 6);

    Serial.printf("Starting Transmission\r\n");
    stateHandle.start = true;
    BEACON_DETECTED = false;
    Serial.printf("Starting State Machine\r\n");
  }

  if (BEACON_DETECTED || timeout)
  {
    Serial.printf("Beacon Detected\r\n");
    // ledToggle();
    if (BEACON_DETECTED)
    {
      restartTimeoutTimer();
      BEACON_DETECTED = 0; // reset and wait for next beacon frame
      timeoutCount = 0;
    }
    if (timeout)
    {
      if (timeoutCount < timeoutCountLimit)
      {
        timeoutCount++;
        restartTimeoutTimer();
      }
      timeout = false;
    }
    // State Machine iteration
    wlskStateMachineIteration(&stateHandle);
    if (rssi_count++ >= 5)
    {
      rssi_count = 0;
      Serial.printf("RSSI: %d\n", RSSI_VALUE);
    }
  }
}
