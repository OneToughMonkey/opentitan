/**
 * Exports the 256-bit keys used for the example OpenTitan HMAC and AES
 * operations.
 *
 * Generate a new random key sequence of 32 uint8 values e.g. with
 *  $ od -N32 -w -tu1 -An /dev/random | awk '$1=$1' OFS=', '
 */
#include <stdint.h>

/**
 * Key length in bits.
 */
#define KEY_LEN 256

/**
 * The AES key.
 */
uint8_t const aes_key[KEY_LEN / 8] = {
    129, 183, 118, 69,  233, 47,  171, 141, 3,   255, 116,
    61,  54,  98,  247, 62,  141, 10,  34,  15,  94,  123,
    22,  121, 103, 66,  25,  111, 83,  52,  125, 189};  // replace with your own
                                                        // key

/**
 * The HMAC key.
 */
uint8_t const hmac_key[KEY_LEN / 8] = {
    5,   65, 152, 119, 255, 148, 125, 87,  165, 61, 17,
    197, 38, 56,  254, 225, 252, 24,  69,  90,  25, 127,
    69,  63, 10,  75,  84,  226, 142, 146, 125, 214};  // replace with your own
                                                       // key
