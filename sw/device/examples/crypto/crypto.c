#include "crypto.h"

#include <stdbool.h>
#include <stdint.h>

#include "key.h"
#include "sw/device/lib/arch/device.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/dif/dif_aes.h"
#include "sw/device/lib/dif/dif_hmac.h"
#include "sw/device/lib/dif/dif_keymgr.h"
#include "sw/device/lib/dif/dif_uart.h"
#include "sw/device/lib/testing/check.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"  // Generated.

#define IGNORE_RET(fun) \
  do                    \
    if (fun) {          \
    }                   \
  while (0)

#define ACK() \
  IGNORE_RET(dif_uart_byte_send_polled(&uart, (uint8_t)cryptoResponseAck))

#define ERR() \
  IGNORE_RET(dif_uart_byte_send_polled(&uart, (uint8_t)cryptoResponseErr))

#define ERR_RETURN() \
  do {               \
    ERR();           \
    return;          \
  } while (0)

static dif_uart_t uart;
static dif_aes_t aes;
static dif_aes_key_share_t aes_key_share;
static dif_aes_transaction_t aes_transaction;
static dif_hmac_t hmac;
static uint8_t hmac_key_big_endian[KEY_LEN / 8];
static dif_hmac_transaction_t hmac_transaction;

static void uart_read_buf(size_t buf_size, uint8_t *buf) {
  size_t rcv_incr;

  for (int rcv = 0; rcv < buf_size; rcv += rcv_incr)
    // we have no strategy for recovering from UART errors
    IGNORE_RET(
        dif_uart_bytes_receive(&uart, buf_size - rcv, buf + rcv, &rcv_incr));
}

static void uart_write_buf(size_t buf_size, uint8_t *buf) {
  size_t snd_incr;

  for (int snd = 0; snd < buf_size; snd += snd_incr)
    // we have no strategy for recovering from UART errors
    IGNORE_RET(
        dif_uart_bytes_send(&uart, buf + snd, buf_size - snd, &snd_incr));
}

static void uart_drop(size_t num_bytes) {
  uint8_t hole[64];
  size_t drp_incr;

  for (int drp = 0; drp < num_bytes; drp += drp_incr) {
    drp_incr = num_bytes - drp < sizeof hole ? num_bytes - drp : sizeof hole;
    uart_read_buf(drp_incr, hole);
  }
}

static void handle_hmac_request(void) {
  // parse request

  uint8_t req_buf[MSG_LEN_SIZE + HMAC_MODE_SIZE];

  uart_read_buf(sizeof req_buf, req_buf);

  uint32_t msg_len = *(uint32_t *)req_buf;
  uint8_t hmac_mode = req_buf[MSG_LEN_SIZE];

  // HMAC/SHA256 setup

  switch (hmac_mode) {
    case hmacModeHmac:
      if (dif_hmac_mode_hmac_start(&hmac, hmac_key_big_endian,
                                   hmac_transaction) != kDifHmacOk)
        ERR_RETURN();
      break;
    case hmacModeSha256:
      if (dif_hmac_mode_sha256_start(&hmac, hmac_transaction) != kDifHmacOk)
        ERR_RETURN();
      break;
    default:
      ERR_RETURN();
  }

  // confirm request

  ACK();

  // read msg_len bytes from UART into HMAC FIFO in 64 byte blocks

  uint8_t hmac_data[64];
  size_t rcv_incr, psh_incr;

  for (int rcv = 0; rcv < msg_len; rcv += rcv_incr) {
    rcv_incr =
        msg_len - rcv < sizeof hmac_data ? msg_len - rcv : sizeof hmac_data;

    uart_read_buf(rcv_incr, hmac_data);

    for (int psh = 0; psh < rcv_incr; psh += psh_incr)
      if (dif_hmac_fifo_push(&hmac, (void *)hmac_data + psh, rcv_incr - psh,
                             &psh_incr) == kDifHmacFifoBadArg) {
        uart_drop(msg_len - rcv - rcv_incr);
        ERR_RETURN();
      }
  }

  // compute digest

  if (dif_hmac_process(&hmac) != kDifHmacOk)
    ERR_RETURN();

  dif_hmac_digest_t hmac_digest;
  dif_hmac_digest_result_t hmac_digest_result;

  do {
    hmac_digest_result = dif_hmac_finish(&hmac, &hmac_digest);
    if (hmac_digest_result == kDifHmacDigestBadArg)
      ERR_RETURN();
  } while (hmac_digest_result == kDifHmacDigestProcessing);

  // confirm digest computation

  ACK();

  // write digest back to UART

  uart_write_buf(sizeof hmac_digest.digest, (uint8_t *)hmac_digest.digest);
}

static void handle_aes_request(void) {
  // parse request up to IV field

  uint8_t
      req_buf[MSG_LEN_SIZE + CIPHER_MODE_SIZE + AES_MODE_SIZE + AES_BLOCK_SIZE];

  uart_read_buf(sizeof req_buf, req_buf);

  uint32_t msg_len = *(uint32_t *)req_buf;
  uint8_t cipher_mode = req_buf[MSG_LEN_SIZE];
  uint8_t aes_mode = req_buf[MSG_LEN_SIZE + CIPHER_MODE_SIZE];

  // set aes_transaction.mode

  switch (aes_mode) {
    case aesModeEncrypt:
      aes_transaction.mode = kDifAesModeEncrypt;
      break;
    case aesModeDecrypt:
      aes_transaction.mode = kDifAesModeDecrypt;
      break;
    default:
      ERR_RETURN();
  }

  // AES setup, copy IV when required

  dif_aes_iv_t aes_iv;

  switch (cipher_mode) {
    case cipherModeEcb:
      if (dif_aes_start_ecb(&aes, &aes_transaction, aes_key_share) != kDifAesOk)
        ERR_RETURN();
      break;
    case cipherModeCbc:
      memcpy(aes_iv.iv,
             req_buf + MSG_LEN_SIZE + CIPHER_MODE_SIZE + AES_MODE_SIZE,
             AES_BLOCK_SIZE);
      if (dif_aes_start_cbc(&aes, &aes_transaction, aes_key_share, aes_iv) !=
          kDifAesOk)
        ERR_RETURN();
      break;
    case cipherModeCtr:
      memcpy(aes_iv.iv,
             req_buf + MSG_LEN_SIZE + CIPHER_MODE_SIZE + AES_MODE_SIZE,
             AES_BLOCK_SIZE);
      if (dif_aes_start_ctr(&aes, &aes_transaction, aes_key_share, aes_iv) !=
          kDifAesOk)
        ERR_RETURN();
      break;
    default:
      ERR_RETURN();
  }

  // confirm request

  ACK();

  // read msg_len AES blocks into AES and write encrypted blocks back to UART

  dif_aes_data_t aes_data;
  bool aes_ready;

  for (int i = 0; i < msg_len; i++) {
    do
      if (dif_aes_get_status(&aes, kDifAesStatusInputReady, &aes_ready) !=
          kDifAesOk) {
        ERR();
        goto aes_end;
      }
    while (!aes_ready);

    uart_read_buf(sizeof aes_data.data, (uint8_t *)aes_data.data);

    if (dif_aes_load_data(&aes, aes_data) != kDifAesOk) {
      ERR();
      goto aes_end;
    }

    do
      if (dif_aes_get_status(&aes, kDifAesStatusOutputValid, &aes_ready) !=
          kDifAesOk) {
        ERR();
        goto aes_end;
      }
    while (!aes_ready);

    if (dif_aes_read_output(&aes, &aes_data) != kDifAesOk) {
      ERR();
      goto aes_end;
    }

    // confirm encryption of block and send encrypted block

    ACK();
    uart_write_buf(sizeof aes_data.data, (uint8_t *)aes_data.data);
  }

aes_end:
  IGNORE_RET(dif_aes_end(&aes));
}

static void handle_crypto_request(void) {
  uint8_t crypto_mode;

  IGNORE_RET(dif_uart_byte_receive_polled(&uart, &crypto_mode));

  switch (crypto_mode) {
    case cryptoModeHmac:
      handle_hmac_request();
      break;
    case cryptoModeAes:
      handle_aes_request();
      break;
    default:
      IGNORE_RET(dif_uart_fifo_reset(&uart, kDifUartFifoResetRx));
      ERR();
  }
}

int main(int argc, char **argv) {
  // UART init

  CHECK(
      dif_uart_init(
          (dif_uart_params_t){
              .base_addr = mmio_region_from_addr(TOP_EARLGREY_UART0_BASE_ADDR),
          },
          &uart) == kDifUartOk);
  CHECK(dif_uart_configure(&uart, (dif_uart_config_t){
                                      .baudrate = kUartBaudrate,
                                      .clk_freq_hz = kClockFreqPeripheralHz,
                                      .parity_enable = kDifUartToggleDisabled,
                                      .parity = kDifUartParityEven,
                                  }) == kDifUartConfigOk);

  // AES init

  CHECK(dif_aes_init(
            (dif_aes_params_t){
                .base_addr = mmio_region_from_addr(TOP_EARLGREY_AES_BASE_ADDR),
            },
            &aes) == kDifAesOk);

  memcpy(aes_key_share.share0, aes_key, KEY_LEN / 8);

  aes_transaction.key_len = kDifAesKey256;
  aes_transaction.operation = kDifAesOperationAuto;
  aes_transaction.masking = kDifAesMaskingForceZero;

  // HMAC init

  CHECK(dif_hmac_init(
            &(dif_hmac_config_t){
                .base_addr = mmio_region_from_addr(TOP_EARLGREY_HMAC_BASE_ADDR),
            },
            &hmac) == kDifHmacOk);

  hmac_transaction.message_endianness = kDifHmacEndiannessLittle;
  hmac_transaction.digest_endianness = kDifHmacEndiannessLittle;

  // key has to be in big endian byte order for HMAC DIF
  for (int i = 0; i < KEY_LEN / 8 / WORD_SIZE; i++)
    for (int j = 0; j < WORD_SIZE; j++)
      hmac_key_big_endian[i * WORD_SIZE + j] =
          hmac_key[(i + 1) * WORD_SIZE - 1 - j];

  // UART request loop

  for (;;)
    handle_crypto_request();
}
