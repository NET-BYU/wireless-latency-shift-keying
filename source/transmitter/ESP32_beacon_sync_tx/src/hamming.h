#include <cstdint>
#include <stdint.h>
#include <stdio.h>
#include <vector>

uint8_t encode_hamming_7_4(uint8_t data) {
  data &= 0x0F; // Ensure data is only 4 bits

  // Extract individual data bits
  uint8_t d4 = (data >> 0) & 0x01;
  uint8_t d3 = (data >> 1) & 0x01;
  uint8_t d2 = (data >> 2) & 0x01;
  uint8_t d1 = (data >> 3) & 0x01;

  // Calculate parity bits
  uint8_t p1 = d1 ^ d2 ^ d4;
  uint8_t p2 = d1 ^ d3 ^ d4;
  uint8_t p4 = d2 ^ d3 ^ d4;

  // Construct the encoded byte
  return (p1 << 6) | (p2 << 5) | (d1 << 4) | (p4 << 3) | (d2 << 2) | (d3 << 1) |
         (d4 << 0);
}

std::vector<uint8_t> encode_msg(uint8_t *raw_msg, uint8_t size) {
  if (size % 4) {
    printf("Error: Message size must be a multiple of 4\n");
    return {};
  }
  std::vector<uint8_t> encoded_msg;
  for (int i = 0; i < size; i += 4) {
    uint8_t data = 0;
    // Serial.print("Raw:\t\t");
    for (int j = 0; j < 4; j++) {
      // Serial.print(raw_msg[i+j]);
      data = (data << 1) | raw_msg[i + j];
    }
    // Serial.println();
    // Serial.print("Data:\t\t");
    // Serial.println(data, BIN);
    uint8_t encoded = encode_hamming_7_4(data);
    // Serial.print("Encoded:\t");
    // Serial.println(encoded, BIN);
    // Serial.println();
    for (int j = 0; j < 7; j++) {
        encoded_msg.push_back((encoded >> (6 - j)) & 0x01);
    }
  }
  return encoded_msg;
}

uint8_t decode_hamming_7_4(uint8_t data) {
  // Extract individual bits
  uint8_t p1 = (data >> 6) & 0x01;
  uint8_t p2 = (data >> 5) & 0x01;
  uint8_t d1 = (data >> 4) & 0x01;
  uint8_t p4 = (data >> 3) & 0x01;
  uint8_t d2 = (data >> 2) & 0x01;
  uint8_t d3 = (data >> 1) & 0x01;
  uint8_t d4 = (data >> 0) & 0x01;

  // Calculate syndrome bits
  uint8_t s4 = p1 ^ d1 ^ d2 ^ d4;
  uint8_t s2 = p2 ^ d1 ^ d3 ^ d4;
  uint8_t s1 = p4 ^ d2 ^ d3 ^ d4;

  // Combine syndrome bits to form error location
  uint8_t error = (s1 << 2) | (s2 << 1) | s4;

  // Correct the error if found
  if (error) {
    // printf("Syndrome: ");
    // print_binary(error);
    // printf("Error in bit %d\n", error);
    data ^= (1 << (7 - error));
    // printf("Corrected data: ");
    // print_binary(data);
  }

  // Extract the original 4-bit data
  uint8_t decoded_data = ((data >> 4) & 0x01) << 3 | ((data >> 2) & 0x01) << 2 |
                         ((data >> 1) & 0x01) << 1 | ((data >> 0) & 0x01) << 0;

  return decoded_data;
}

// int main() {
//     uint8_t data = 0x0B;

//     printf("Original data:\t");
//     print_binary(data);
//     data = encode_hamming_7_4(data);
//     printf("Encoded data:\t");
//     print_binary(data);
//     data = decode_hamming_7_4(0b00110011);  // Example with an error
//     printf("Decoded data:\t");
//     print_binary(data);

//     return 0;
// }
