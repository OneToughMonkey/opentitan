/**
 * Contains definitions of constants ands enums to be used in the communication
 * between an OpenTitan device and a client connected via UART for use of the
 * crypto.c example functionality.
 */

/**
 * Size of an AES block in bytes.
 */
#define AES_BLOCK_SIZE 16
/**
 * Word size used by the OpenTitan device in bytes.
 */
#define WORD_SIZE 4
/**
 * String describing the endianness used by the OpenTitan CPU.
 */
#define ENDIANNESS "little"
/**
 * Size of the field in a request to the OpenTitan device containing the length
 * of a following message (with data to hash/authenticate/encrypt) in bytes.
 */
#define MSG_LEN_SIZE WORD_SIZE
/**
 * Size of the field in a request to the OpenTitan device containing the
 * cryptographic mode (HMAC/AES) in bytes.
 */
#define CRYPTO_MODE_SIZE 1
/**
 * Size of the field in a request to the OpenTitan device containing the HMAC
 * module mode (HMAC/SHA256) in bytes.
 */
#define HMAC_MODE_SIZE 1
/**
 * Size of the field in a request to the OpenTitan device containing the AES
 * block cipher mode (ECB/CBC/CTR) in bytes.
 */
#define CIPHER_MODE_SIZE 1
/**
 * Size of the field in a request to the OpenTitan device containing the AES
 * module mode (encrypt/decrypt) in bytes.
 */
#define AES_MODE_SIZE 1

/**
 * Cryptographic mode.
 */
typedef enum crypto_mode {
  /**
   * HMAC mode.
   */
  cryptoModeHmac,
  /**
   * AES mode.
   */
  cryptoModeAes,
} crypto_mode_t;

/**
 * Mode of HMAC module.
 */
typedef enum hmac_mode {
  /**
   * HMAC mode.
   */
  hmacModeHmac,
  /**
   * SHA256 mode.
   */
  hmacModeSha256,
} hmac_mode_t;

/**
 * AES block cipher mode.
 */
typedef enum cipher_mode {
  /**
   * Electronic codebook (ECB) mode.
   */
  cipherModeEcb,
  /**
   * Cipher block chaining (CBC) mode.
   */
  cipherModeCbc,
  /**
   * Counter (CTR) mode.
   */
  cipherModeCtr,
} cipher_mode_t;

/**
 * Mode of AES module.
 */
typedef enum aes_mode {
  /**
   * Encryption mode.
   */
  aesModeEncrypt,
  /**
   * Decryption mode.
   */
  aesModeDecrypt,
} aes_mode_t;

/**
 * Values sent by the OpenTitan device in response to cryptographic requests to
 * signal acknowledgment or errors.
 */
typedef enum crypto_response {
  /**
   * Request acknowledged.
   */
  cryptoResponseAck,
  /**
   * Error in request handling.
   */
  cryptoResponseErr,
} crypto_response_t;
