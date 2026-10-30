/*
 * Goodix 53xd (TLS) fingerprint sensor driver for libfprint
 *
 * Copyright (C) 2026 Arian Kulmer <arian.kulmer@web.de>
 *
 * The protocol is derived from the goodix-fp-dump project
 * (https://github.com/goodix-fp-linux-dev/goodix-fp-dump), Copyright (c) 2022
 * Goodix Fingerprint Linux Development, MIT license (see
 * LICENSES/MIT-goodix-fp-dump.txt). The device_config and fdt_idle_mode blobs
 * are copied from its driver_53xd.py.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * The sensor only talks to a host that knows its TLS pre-shared key. Units
 * shipped with laptops carry a key provisioned by the Windows driver, so they
 * must first be re-provisioned with the well-known all-zero key (for example
 * with goodix-fp-dump's run_532d.py). The driver refuses to touch sensors
 * that are not provisioned and never writes firmware or keys itself.
 *
 * Finger presence comes from the sensor's finger detection (FDT): it reports
 * a reading per area, and once armed with thresholds derived from the empty
 * sensor it sends an event when a finger lands or lifts. Detect-mode frames,
 * which a finger pulls towards zero, confirm the finger before a capture. If
 * the FDT readings are unusable, the driver polls those frames instead.
 *
 * The images are far too small for minutiae matching. Matching is done by
 * Milan, the algorithm of the vendor driver (see goodix53xd_milan.c), so this
 * is a matching device that stores Milan templates in the prints.
 */

#define FP_COMPONENT "goodix53xd"

#include "drivers_api.h"
#include "fpi-byte-utils.h"
#include "goodix53xd.h"
#include "goodix53xd_milan.h"
#include "goodix53xd_proto.h"
#include "goodix53xd_tls.h"

#define FIRMWARE_PREFIX "GF5298_GM168SEC_APP_130"

#define PSK_FLAGS 0xbb020001

/* SHA-256 based hash the sensor reports for the all-zero PSK */
static const guint8 pmk_hash[32] = {
  0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, 0x6c, 0x8f, 0xc1, 0x8b,
  0x8e, 0x9f, 0x8e, 0x20, 0x08, 0x97, 0x14, 0x85, 0x6e, 0xe2, 0x33, 0xb3,
  0x90, 0x2a, 0x59, 0x1d, 0x0d, 0x5f, 0x29, 0x25,
};

static const guint8 psk[32] = { 0 };

static const guint8 device_config[] = {
  0x70, 0x11, 0x60, 0x71, 0x2c, 0x9d, 0x2c, 0xc9, 0x1c, 0xe5, 0x18, 0xfd,
  0x00, 0xfd, 0x00, 0xfd, 0x03, 0xba, 0x00, 0x01, 0x80, 0xca, 0x00, 0x08,
  0x00, 0x84, 0x00, 0xbe, 0xc3, 0x86, 0x00, 0xb1, 0xb6, 0x88, 0x00, 0xba,
  0xba, 0x8a, 0x00, 0xb3, 0xb3, 0x8c, 0x00, 0xbc, 0xbc, 0x8e, 0x00, 0xb1,
  0xb1, 0x90, 0x00, 0xbb, 0xbb, 0x92, 0x00, 0xb1, 0xb1, 0x94, 0x00, 0x00,
  0x00, 0x96, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x9a, 0x00, 0x00,
  0x00, 0xd2, 0x00, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd6, 0x00, 0x00,
  0x00, 0xd8, 0x00, 0x00, 0x00, 0x50, 0x00, 0x01, 0x05, 0xd0, 0x00, 0x00,
  0x00, 0x70, 0x00, 0x00, 0x00, 0x72, 0x00, 0x78, 0x56, 0x74, 0x00, 0x34,
  0x12, 0x20, 0x00, 0x10, 0x40, 0x2a, 0x01, 0x02, 0x04, 0x22, 0x00, 0x01,
  0x20, 0x24, 0x00, 0x32, 0x00, 0x80, 0x00, 0x01, 0x00, 0x5c, 0x00, 0x01,
  0x01, 0x56, 0x00, 0x24, 0x20, 0x58, 0x00, 0x01, 0x02, 0x32, 0x00, 0x04,
  0x02, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x00, 0x58, 0x82, 0x00, 0x7f,
  0x08, 0x2a, 0x01, 0x82, 0x07, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x14,
  0x00, 0x80, 0x00, 0x01, 0x40, 0x5c, 0x00, 0xe7, 0x00, 0x56, 0x00, 0x06,
  0x14, 0x58, 0x00, 0x04, 0x02, 0x32, 0x00, 0x0c, 0x02, 0x66, 0x00, 0x00,
  0x02, 0x7c, 0x00, 0x00, 0x58, 0x82, 0x00, 0x80, 0x08, 0x2a, 0x01, 0x08,
  0x00, 0x5c, 0x00, 0x01, 0x01, 0x54, 0x00, 0x00, 0x01, 0x62, 0x00, 0x08,
  0x04, 0x64, 0x00, 0x10, 0x00, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x00,
  0x58, 0x2a, 0x01, 0x08, 0x00, 0x5c, 0x00, 0xdc, 0x00, 0x52, 0x00, 0x08,
  0x00, 0x54, 0x00, 0x00, 0x01, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x00,
  0x58, 0x20, 0xc5, 0x1d,
};

/* Idle FDT mode; the last byte selects whether the sensor replies */
static const guint8 fdt_idle_mode[] = {
  0x0d, 0x01, 0x28, 0x01, 0x22, 0x01, 0x28, 0x01, 0x24, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
};

/* FDT mode blocks are [op, 0x01, 4x u16 DAC, 8x u16 threshold, reply flag].
 * A reading reply is [irq u16][touch u16][8x u16 area readings]. */
#define FDT_OP_MANUAL     0x0d
#define FDT_OP_DOWN       0x0c
#define FDT_OP_UP         0x0e
#define FDT_BASE_OFFSET   10
#define FDT_AREAS         8
#define FDT_READING_LEN   (4 + 2 * FDT_AREAS)

/* Finger-down is only a wake-up: the finger is still landing when it fires,
 * so detect frames confirm the coverage before capturing. */
#define FDT_DOWN_TIMEOUT  20000
#define FDT_UP_TIMEOUT    1000
#define LANDING_POLL_MS   50
#define LANDING_POLLS     10

/* Sensor register 0x022c brackets every image read (value, then value with
 * the low byte set to 0x02 afterwards). */
#define REG_CAPTURE 0x022c

typedef struct
{
  const char *name;
  guint8      flags;
  guint8      reg[2];
  guint16     dac[4];
} CaptureMode;

/* Without a finger this mode gives mid-range values; a finger saturates it
 * towards zero. Used for calibration and presence detection. */
static const CaptureMode mode_detect = {
  "detect", 0x01, { 0x0a, 0x03 }, { 0x128, 0x122, 0x128, 0x124 },
};

/* The fingerprint mode saturates without a finger, but puts finger contact
 * into the middle of the range. */
static const CaptureMode mode_finger = {
  "finger", 0x41, { 0x05, 0x03 }, { 0x0a5, 0x09f, 0x0a5, 0x0a1 },
};

/* Fraction of the calibration level below which a pixel counts as covered */
#define COVERED_LEVEL     0.5
#define FINGER_ON_RATIO   0.40
#define FINGER_OFF_RATIO  0.10
#define CALIBRATION_MIN   1200
#define CALIBRATION_MAX   3600
#define CALIBRATION_TRIES 3

#define ENROLL_SAMPLES    12

/* Matcher state; GOODIX53XD_STATE_FILE overrides it for testing */
#define STATE_FILE        "/var/lib/fprint/goodix53xd-milan.state"

typedef enum {
  REPLY_NONE,     /* ACK only */
  REPLY_MSG,      /* protocol message carrying the same command */
  REPLY_TLS,      /* raw TLS pack */
  REPLY_TLS_DATA, /* TLS application data pack */
} ReplyKind;

struct _FpiDeviceGoodix53xd
{
  FpDevice parent;

  /* Current command */
  GByteArray   *tx;
  Goodix53xdCmd cmd;
  ReplyKind     reply_kind;
  GByteArray   *rx;
  const guint8 *reply;
  gsize         reply_len;

  Goodix53xdTls *tls;
  GByteArray    *tls_out;
  guint          tls_records;

  /* Capture */
  const CaptureMode *capture_mode;
  guint16           *frame;
  guint16           *calibration;
  double             calibration_level;
  guint              calibration_tries;

  gboolean           await_finger_off;

  /* Finger detection */
  gboolean           fdt_usable;
  guint8             fdt_base[2 * FDT_AREAS];
  Goodix53xdCmd      fdt_cmd;
  gboolean           fdt_event;
  GError            *fdt_error;
  guint              landing_polls;

  /* Matching */
  Goodix53xdMilan                  *milan;
  GoodixMilanEnrollmentTransaction *enroll_tx;
  guint                             enroll_bad_records;
  guint                             enroll_bad_continue;
  GPtrArray                        *gallery;   /* FpPrint, borrowed */
  GPtrArray                        *templates; /* GBytes, same order */
};

G_DEFINE_TYPE (FpiDeviceGoodix53xd, fpi_device_goodix53xd, FP_TYPE_DEVICE)

/* ------------------------------------------------------------------------ */
/* USB packs                                                                 */

enum rx_states {
  RX_FIRST,
  RX_REST,
  RX_NUM_STATES,
};

static void
rx_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data,
       GError *error)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);
  gssize total;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  g_byte_array_append (self->rx, transfer->buffer, transfer->actual_length);
  total = goodix53xd_pack_total_len (self->rx->data, self->rx->len);

  if (total < 0 || self->rx->len < (gsize) total)
    {
      if (transfer->actual_length == 0)
        {
          fpi_ssm_mark_failed (transfer->ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "Short USB read"));
          return;
        }
      fpi_ssm_jump_to_state (transfer->ssm, RX_REST);
      return;
    }

  fpi_ssm_mark_completed (transfer->ssm);
}

static void
rx_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
  gsize len = GOODIX53XD_PACKET_SIZE;
  gssize total;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case RX_FIRST:
      g_byte_array_set_size (self->rx, 0);
      break;

    case RX_REST:
      /* Read exactly what is missing so a transfer never waits for a
       * short packet that will not come. */
      total = goodix53xd_pack_total_len (self->rx->data, self->rx->len);
      len = total < 0 ? GOODIX53XD_PACKET_SIZE : total - self->rx->len;
      len = (len + GOODIX53XD_PACKET_SIZE - 1) / GOODIX53XD_PACKET_SIZE *
            GOODIX53XD_PACKET_SIZE;
      break;
    }

  fpi_usb_transfer_fill_bulk (transfer, GOODIX53XD_EP_IN, len);
  transfer->ssm = ssm;
  fpi_usb_transfer_submit (transfer, GOODIX53XD_USB_TIMEOUT, NULL, rx_cb, NULL);
}

static void
start_rx (FpiSsm *parent, FpDevice *dev)
{
  fpi_ssm_start_subsm (parent, fpi_ssm_new (dev, rx_run_state, RX_NUM_STATES));
}

static void
send_pack (FpiSsm *ssm, FpDevice *dev, GByteArray *pack)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
  gsize len = (pack->len + GOODIX53XD_PACKET_SIZE - 1) /
              GOODIX53XD_PACKET_SIZE * GOODIX53XD_PACKET_SIZE;

  /* The sensor expects zero padding up to the packet size */
  fpi_usb_transfer_fill_bulk (transfer, GOODIX53XD_EP_OUT, len);
  memset (transfer->buffer, 0, len);
  memcpy (transfer->buffer, pack->data, pack->len);
  transfer->short_is_error = TRUE;
  transfer->ssm = ssm;
  fpi_usb_transfer_submit (transfer, GOODIX53XD_USB_TIMEOUT, NULL,
                           fpi_ssm_usb_transfer_cb, NULL);
}

/* ------------------------------------------------------------------------ */
/* Commands                                                                  */

/* An FDT event can arrive just as another command is sent, for example
 * after cancelling an FDT wait. */
static gboolean
is_fdt_event (FpiDeviceGoodix53xd *self)
{
  const guint8 *data = self->rx->data;

  /* ACKs are message 0xb0 and FDT down/up have no reply message, so a
   * 0x32/0x34 message is always an event, even while sending 0x32/0x34 */
  return self->rx->len > 4 && data[0] == GOODIX53XD_FLAGS_MSG &&
         (data[4] == GOODIX53XD_CMD_MCU_SWITCH_TO_FDT_DOWN ||
          data[4] == GOODIX53XD_CMD_MCU_SWITCH_TO_FDT_UP);
}

enum cmd_states {
  CMD_SEND,
  CMD_ACK,
  CMD_CHECK_ACK,
  CMD_REPLY,
  CMD_CHECK_REPLY,
  CMD_NUM_STATES,
};

static void
cmd_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);
  GError *error = NULL;
  const guint8 *payload;
  gsize len;
  guint8 flags;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CMD_SEND:
      send_pack (ssm, dev, self->tx);
      break;

    case CMD_ACK:
    case CMD_REPLY:
      start_rx (ssm, dev);
      break;

    case CMD_CHECK_ACK:
      if (is_fdt_event (self))
        {
          fp_dbg ("Skipping stray FDT event");
          fpi_ssm_jump_to_state (ssm, CMD_ACK);
          return;
        }
      if (!goodix53xd_decode_msg (self->rx->data, self->rx->len,
                                  GOODIX53XD_CMD_ACK, &payload, &len, &error) ||
          !goodix53xd_check_ack (payload, len, self->cmd, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }

      if (self->reply_kind == REPLY_NONE)
        fpi_ssm_mark_completed (ssm);
      else
        fpi_ssm_next_state (ssm);
      break;

    case CMD_CHECK_REPLY:
      if (is_fdt_event (self))
        {
          fp_dbg ("Skipping stray FDT event");
          fpi_ssm_jump_to_state (ssm, CMD_REPLY);
          return;
        }
      if (self->reply_kind == REPLY_MSG)
        {
          if (!goodix53xd_decode_msg (self->rx->data, self->rx->len, self->cmd,
                                      &self->reply, &self->reply_len, &error))
            {
              fpi_ssm_mark_failed (ssm, error);
              return;
            }
        }
      else
        {
          flags = self->reply_kind == REPLY_TLS ? GOODIX53XD_FLAGS_TLS :
                  GOODIX53XD_FLAGS_TLS_DATA;
          if (!goodix53xd_decode_pack (self->rx->data, self->rx->len, flags,
                                       &self->reply, &self->reply_len, &error))
            {
              fpi_ssm_mark_failed (ssm, error);
              return;
            }
        }
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
send_cmd (FpiSsm *parent, FpDevice *dev, Goodix53xdCmd cmd,
          const guint8 *payload, gsize len, ReplyKind reply_kind)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);

  g_clear_pointer (&self->tx, g_byte_array_unref);
  self->tx = goodix53xd_encode_msg (cmd, payload, len, TRUE);
  self->cmd = cmd;
  self->reply_kind = reply_kind;
  self->reply = NULL;
  self->reply_len = 0;

  fpi_ssm_start_subsm (parent, fpi_ssm_new (dev, cmd_run_state, CMD_NUM_STATES));
}

static void
send_tls_records (FpiSsm *ssm, FpDevice *dev, const guint8 *data, gsize len)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);

  g_clear_pointer (&self->tx, g_byte_array_unref);
  self->tx = goodix53xd_encode_pack (GOODIX53XD_FLAGS_TLS, data, len);
  send_pack (ssm, dev, self->tx);
}

static void
write_capture_register (FpiSsm *ssm, FpDevice *dev, guint8 value0,
                        guint8 value1)
{
  guint8 payload[5] = { 0x00, REG_CAPTURE & 0xff, REG_CAPTURE >> 8,
                        value0, value1 };

  send_cmd (ssm, dev, GOODIX53XD_CMD_WRITE_SENSOR_REGISTER, payload,
            sizeof (payload), REPLY_NONE);
}

/* ------------------------------------------------------------------------ */
/* Frames                                                                    */

static void
decode_frame (const guint8 *raw, guint16 *frame)
{
  for (gsize i = 0, p = 0; i < GOODIX53XD_FRAME_BYTES; i += 6)
    {
      const guint8 *c = raw + i;

      frame[p++] = ((c[0] & 0xf) << 8) | c[1];
      frame[p++] = (c[3] << 4) | (c[0] >> 4);
      frame[p++] = ((c[5] & 0xf) << 8) | c[2];
      frame[p++] = (c[4] << 4) | (c[5] >> 4);
    }
}

static inline gboolean
is_border (gsize x, gsize y)
{
  return x < GOODIX53XD_BORDER || y < GOODIX53XD_BORDER ||
         x >= GOODIX53XD_FRAME_WIDTH - GOODIX53XD_BORDER ||
         y >= GOODIX53XD_FRAME_HEIGHT - GOODIX53XD_BORDER;
}

static double
frame_mean (const guint16 *frame)
{
  double sum = 0;
  gsize n = 0;

  for (gsize y = 0; y < GOODIX53XD_FRAME_HEIGHT; y++)
    for (gsize x = 0; x < GOODIX53XD_FRAME_WIDTH; x++)
      if (!is_border (x, y))
        {
          sum += frame[y * GOODIX53XD_FRAME_WIDTH + x];
          n++;
        }

  return sum / n;
}

static double
covered_ratio (const guint16 *frame, double level)
{
  gsize covered = 0, n = 0;

  for (gsize y = 0; y < GOODIX53XD_FRAME_HEIGHT; y++)
    for (gsize x = 0; x < GOODIX53XD_FRAME_WIDTH; x++)
      if (!is_border (x, y))
        {
          if (frame[y * GOODIX53XD_FRAME_WIDTH + x] < level * COVERED_LEVEL)
            covered++;
          n++;
        }

  return (double) covered / n;
}

/* ------------------------------------------------------------------------ */
/* Capture: register write, image request, decryption, register restore      */

enum capture_states {
  CAPTURE_SET_REGISTER,
  CAPTURE_GET_IMAGE,
  CAPTURE_DECRYPT,
  CAPTURE_RESTORE_REGISTER,
  CAPTURE_NUM_STATES,
};

static void
capture_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);
  const CaptureMode *mode = self->capture_mode;
  g_autoptr(GByteArray) plain = NULL;
  GError *error = NULL;
  guint8 payload[10];

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CAPTURE_SET_REGISTER:
      write_capture_register (ssm, dev, mode->reg[0], mode->reg[1]);
      break;

    case CAPTURE_GET_IMAGE:
      payload[0] = mode->flags;
      payload[1] = 0x03;
      for (int i = 0; i < 4; i++)
        {
          payload[2 + 2 * i] = mode->dac[i] & 0xff;
          payload[3 + 2 * i] = mode->dac[i] >> 8;
        }
      send_cmd (ssm, dev, GOODIX53XD_CMD_MCU_GET_IMAGE, payload,
                sizeof (payload), REPLY_TLS_DATA);
      break;

    case CAPTURE_DECRYPT:
      /* The TLS records follow a 9 byte header */
      if (self->reply_len < 9)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "Image reply too short"));
          return;
        }

      plain = g_byte_array_sized_new (GOODIX53XD_FRAME_PLAIN);
      if (!goodix53xd_tls_decrypt (self->tls, self->reply + 9,
                                   self->reply_len - 9, GOODIX53XD_FRAME_PLAIN,
                                   plain, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }

      if (plain->len < GOODIX53XD_FRAME_PLAIN)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "Image truncated (%u bytes)",
                                                         plain->len));
          return;
        }

      decode_frame (plain->data, self->frame);
      fpi_ssm_next_state (ssm);
      break;

    case CAPTURE_RESTORE_REGISTER:
      write_capture_register (ssm, dev, mode->reg[0], 0x02);
      break;
    }
}

static void
start_capture (FpiSsm *parent, FpDevice *dev, const CaptureMode *mode)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);

  self->capture_mode = mode;
  fpi_ssm_start_subsm (parent,
                       fpi_ssm_new (dev, capture_run_state, CAPTURE_NUM_STATES));
}

/* ------------------------------------------------------------------------ */
/* Finger detection                                                          */

/* Thresholds are the empty-sensor readings halved, written to both bytes.
 * @refresh rejects readings well below the current thresholds, which mean a
 * finger is still on the sensor. */
static gboolean
update_fdt_base (FpiDeviceGoodix53xd *self, const guint8 *reading, gsize len,
                 gboolean refresh)
{
  guint8 base[2 * FDT_AREAS];

  if (len < FDT_READING_LEN)
    return FALSE;

  for (gsize i = 0; i < FDT_AREAS; i++)
    {
      guint16 value = FP_READ_UINT16_LE (reading + 4 + 2 * i) >> 1;

      if (value == 0 || value > 0xff ||
          (refresh && value < self->fdt_base[2 * i] * 3 / 4))
        return FALSE;
      base[2 * i] = base[2 * i + 1] = value;
    }

  memcpy (self->fdt_base, base, sizeof (base));
  return TRUE;
}

static void
send_fdt (FpiSsm *ssm, FpDevice *dev, Goodix53xdCmd cmd, guint8 op,
          gboolean reply)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);
  guint8 mode[sizeof (fdt_idle_mode)];

  memcpy (mode, fdt_idle_mode, sizeof (mode));
  mode[0] = op;
  memcpy (mode + FDT_BASE_OFFSET, self->fdt_base, sizeof (self->fdt_base));
  mode[sizeof (mode) - 1] = reply;

  /* Arming only acknowledges; the event follows when the finger moves */
  send_cmd (ssm, dev, cmd, mode, sizeof (mode),
            cmd == GOODIX53XD_CMD_MCU_SWITCH_TO_FDT_MODE && reply ?
            REPLY_MSG : REPLY_NONE);
}

/* Every FDT mode is sent twice: first without the reply flag, which clears a
 * pending interrupt or a pending wait, then with it. Otherwise an arm fires
 * at once, and a reading requested while armed never arrives. */
enum fdt_states {
  FDT_REFRESH_CLEAR,
  FDT_REFRESH,
  FDT_CHECK_REFRESH,
  FDT_CLEAR,
  FDT_ARM,
  FDT_WAIT,
  FDT_CHECK_EVENT,
  FDT_DISARM,
  FDT_DISARM_READ,
  FDT_DISARMED,
  FDT_NUM_STATES,
};

static void
fdt_wait_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data,
             GError *error)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);

  if (!error)
    {
      g_byte_array_set_size (self->rx, 0);
      g_byte_array_append (self->rx, transfer->buffer, transfer->actual_length);
      fpi_ssm_next_state (transfer->ssm);
      return;
    }

  if (g_cancellable_is_cancelled (fpi_device_get_cancellable (dev)))
    {
      g_clear_error (&self->fdt_error);
      self->fdt_error = error;
    }
  else if (g_error_matches (error, G_USB_DEVICE_ERROR,
                            G_USB_DEVICE_ERROR_TIMED_OUT))
    {
      g_error_free (error);
    }
  else
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  /* The sensor stays armed until switched back to a manual reading */
  fpi_ssm_jump_to_state (transfer->ssm, FDT_DISARM);
}

static void
fdt_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);
  gboolean down = self->fdt_cmd == GOODIX53XD_CMD_MCU_SWITCH_TO_FDT_DOWN;
  guint8 op = down ? FDT_OP_DOWN : FDT_OP_UP;
  FpiUsbTransfer *transfer;
  const guint8 *payload;
  gsize len;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FDT_REFRESH_CLEAR:
    case FDT_REFRESH:
      /* Track drift: re-derive the thresholds while the sensor is empty */
      if (!down)
        {
          fpi_ssm_jump_to_state (ssm, FDT_CLEAR);
          return;
        }
      send_fdt (ssm, dev, GOODIX53XD_CMD_MCU_SWITCH_TO_FDT_MODE, FDT_OP_MANUAL,
                fpi_ssm_get_cur_state (ssm) == FDT_REFRESH);
      break;

    case FDT_CHECK_REFRESH:
      if (!update_fdt_base (self, self->reply, self->reply_len, TRUE))
        fp_dbg ("Keeping FDT thresholds, reading looks covered");
      fpi_ssm_next_state (ssm);
      break;

    case FDT_CLEAR:
      send_fdt (ssm, dev, self->fdt_cmd, op, FALSE);
      break;

    case FDT_ARM:
      send_fdt (ssm, dev, self->fdt_cmd, op, TRUE);
      break;

    case FDT_WAIT:
      transfer = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX53XD_EP_IN,
                                  GOODIX53XD_PACKET_SIZE);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer,
                               down ? FDT_DOWN_TIMEOUT : FDT_UP_TIMEOUT,
                               fpi_device_get_cancellable (dev),
                               fdt_wait_cb, NULL);
      break;

    case FDT_CHECK_EVENT:
      if (!goodix53xd_decode_msg (self->rx->data, self->rx->len, self->fdt_cmd,
                                  &payload, &len, NULL))
        {
          fp_dbg ("Ignoring unexpected message while waiting for FDT event");
          fpi_ssm_jump_to_state (ssm, FDT_WAIT);
          return;
        }
      fp_dbg ("FDT finger %s event", down ? "down" : "up");
      self->fdt_event = TRUE;
      /* goodix-fp-dump also returns to manual mode before capturing */
      fpi_ssm_next_state (ssm);
      break;

    case FDT_DISARM:
    case FDT_DISARM_READ:
      send_fdt (ssm, dev, GOODIX53XD_CMD_MCU_SWITCH_TO_FDT_MODE, FDT_OP_MANUAL,
                fpi_ssm_get_cur_state (ssm) == FDT_DISARM_READ);
      break;

    case FDT_DISARMED:
      if (self->fdt_error)
        fpi_ssm_mark_failed (ssm, g_steal_pointer (&self->fdt_error));
      else
        fpi_ssm_mark_completed (ssm);
      break;
    }
}

/* Arms finger-down or finger-up detection and waits for the event or a
 * timeout; fdt_event tells which. */
static void
start_fdt (FpiSsm *parent, FpDevice *dev, Goodix53xdCmd cmd)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);

  self->fdt_cmd = cmd;
  self->fdt_event = FALSE;
  fpi_ssm_start_subsm (parent, fpi_ssm_new (dev, fdt_run_state, FDT_NUM_STATES));
}

/* ------------------------------------------------------------------------ */
/* Activation                                                                */

enum activate_states {
  ACTIVATE_DRAIN,
  ACTIVATE_NOP,
  ACTIVATE_NOP_DRAIN,
  ACTIVATE_FIRMWARE,
  ACTIVATE_CHECK_FIRMWARE,
  ACTIVATE_PSK,
  ACTIVATE_CHECK_PSK,
  ACTIVATE_RESET,
  ACTIVATE_CHECK_RESET,
  ACTIVATE_CHIP_ID,
  ACTIVATE_OTP,
  ACTIVATE_TLS_REQUEST,
  ACTIVATE_TLS_SERVER_HELLO,
  ACTIVATE_TLS_CLIENT_RECORD,
  ACTIVATE_TLS_CLIENT_FEED,
  ACTIVATE_TLS_SERVER_FINISH,
  ACTIVATE_TLS_SETTLE,
  ACTIVATE_UPLOAD_CONFIG,
  ACTIVATE_CHECK_CONFIG,
  ACTIVATE_FDT_IDLE,
  ACTIVATE_FDT_IDLE_REPLY,
  ACTIVATE_CHECK_FDT,
  ACTIVATE_CALIBRATE,
  ACTIVATE_CHECK_CALIBRATION,
  ACTIVATE_NUM_STATES,
};

/* Reads that may legitimately time out: stale data before the first command
 * and the optional NOP acknowledgement. */
static void
drain_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data,
          GError *error)
{
  if (error)
    {
      gboolean timeout = g_error_matches (error, G_USB_DEVICE_ERROR,
                                          G_USB_DEVICE_ERROR_TIMED_OUT);

      g_error_free (error);
      if (timeout)
        {
          fpi_ssm_next_state (transfer->ssm);
          return;
        }
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }

  /* Got something; keep draining */
  fpi_ssm_jump_to_state (transfer->ssm, fpi_ssm_get_cur_state (transfer->ssm));
}

static void
drain (FpiSsm *ssm, FpDevice *dev)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  fpi_usb_transfer_fill_bulk (transfer, GOODIX53XD_EP_IN, 0x4000);
  transfer->ssm = ssm;
  fpi_usb_transfer_submit (transfer, 100, NULL, drain_cb, NULL);
}

static gboolean
check_reply_len (FpiSsm *ssm, FpiDeviceGoodix53xd *self, gsize min,
                 const char *what)
{
  if (self->reply_len >= min)
    return TRUE;

  fpi_ssm_mark_failed (ssm,
                       fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                 "Short %s reply", what));
  return FALSE;
}

static void
activate_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);
  g_autoptr(GByteArray) out = NULL;
  g_autofree gchar *firmware = NULL;
  GError *error = NULL;
  guint8 payload[16];

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_DRAIN:
    case ACTIVATE_NOP_DRAIN:
      drain (ssm, dev);
      break;

    case ACTIVATE_NOP:
      memset (payload, 0, 4);
      g_clear_pointer (&self->tx, g_byte_array_unref);
      self->tx = goodix53xd_encode_msg (GOODIX53XD_CMD_NOP, payload, 4, FALSE);
      send_pack (ssm, dev, self->tx);
      break;

    case ACTIVATE_FIRMWARE:
      memset (payload, 0, 2);
      send_cmd (ssm, dev, GOODIX53XD_CMD_FIRMWARE_VERSION, payload, 2, REPLY_MSG);
      break;

    case ACTIVATE_CHECK_FIRMWARE:
      firmware = g_strndup ((const gchar *) self->reply, self->reply_len);
      fp_dbg ("Firmware: %s", firmware);
      if (!g_str_has_prefix (firmware, FIRMWARE_PREFIX))
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                         "Unsupported firmware %s",
                                                         firmware));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_PSK:
      FP_WRITE_UINT32_LE (payload, sizeof (pmk_hash));
      FP_WRITE_UINT32_LE (payload + 4, 0);
      FP_WRITE_UINT32_LE (payload + 8, PSK_FLAGS);
      FP_WRITE_UINT32_LE (payload + 12, 0);
      send_cmd (ssm, dev, GOODIX53XD_CMD_PRESET_PSK_READ, payload, 16, REPLY_MSG);
      break;

    case ACTIVATE_CHECK_PSK:
      if (!check_reply_len (ssm, self, 9, "PSK"))
        return;
      if (self->reply[0] != 0x00 ||
          FP_READ_UINT32_LE (self->reply + 1) != PSK_FLAGS ||
          FP_READ_UINT32_LE (self->reply + 5) != sizeof (pmk_hash) ||
          self->reply_len < 9 + sizeof (pmk_hash) ||
          memcmp (self->reply + 9, pmk_hash, sizeof (pmk_hash)) != 0)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                         "Sensor is not provisioned "
                                                         "with the known TLS key"));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_RESET:
      payload[0] = 0x05;   /* reset sensor, no MCU soft reset */
      payload[1] = 20;     /* sleep time */
      send_cmd (ssm, dev, GOODIX53XD_CMD_RESET, payload, 2, REPLY_MSG);
      break;

    case ACTIVATE_CHECK_RESET:
      if (!check_reply_len (ssm, self, 1, "reset"))
        return;
      if (self->reply[0] != 0x01)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "Sensor reset failed"));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_CHIP_ID:
      payload[0] = 0x00;
      payload[1] = 0x00;
      payload[2] = 0x00;
      payload[3] = 4;
      send_cmd (ssm, dev, GOODIX53XD_CMD_READ_SENSOR_REGISTER, payload, 4,
                REPLY_MSG);
      break;

    case ACTIVATE_OTP:
      memset (payload, 0, 2);
      send_cmd (ssm, dev, GOODIX53XD_CMD_READ_OTP, payload, 2, REPLY_MSG);
      break;

    case ACTIVATE_TLS_REQUEST:
      g_clear_pointer (&self->tls, goodix53xd_tls_free);
      self->tls = goodix53xd_tls_new (psk, sizeof (psk), &error);
      if (!self->tls)
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      memset (payload, 0, 2);
      send_cmd (ssm, dev, GOODIX53XD_CMD_REQUEST_TLS_CONNECTION, payload, 2,
                REPLY_TLS);
      break;

    case ACTIVATE_TLS_SERVER_HELLO:
      /* reply holds the ClientHello */
      out = g_byte_array_new ();
      if (!goodix53xd_tls_handshake (self->tls, self->reply, self->reply_len,
                                     out, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      self->tls_records = 0;
      g_byte_array_set_size (self->tls_out, 0);
      send_tls_records (ssm, dev, out->data, out->len);
      break;

    case ACTIVATE_TLS_CLIENT_RECORD:
      /* ClientKeyExchange, ChangeCipherSpec, Finished: one pack each */
      start_rx (ssm, dev);
      break;

    case ACTIVATE_TLS_CLIENT_FEED:
      {
        const guint8 *records;
        gsize len;

        if (!goodix53xd_decode_pack (self->rx->data, self->rx->len,
                                     GOODIX53XD_FLAGS_TLS, &records, &len,
                                     &error) ||
            !goodix53xd_tls_handshake (self->tls, records, len,
                                       self->tls_out, &error))
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }

        if (++self->tls_records < 3)
          {
            fpi_ssm_jump_to_state (ssm, ACTIVATE_TLS_CLIENT_RECORD);
            return;
          }

        if (!goodix53xd_tls_is_established (self->tls) ||
            self->tls_out->len == 0)
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                           "TLS handshake incomplete"));
            return;
          }

        /* Keep the server's ChangeCipherSpec + Finished for the next state */
        g_clear_pointer (&self->tx, g_byte_array_unref);
        self->tx = goodix53xd_encode_pack (GOODIX53XD_FLAGS_TLS,
                                           self->tls_out->data,
                                           self->tls_out->len);
        fpi_ssm_next_state (ssm);
      }
      break;

    case ACTIVATE_TLS_SERVER_FINISH:
      fp_dbg ("TLS session established");
      send_pack (ssm, dev, self->tx);
      break;

    case ACTIVATE_TLS_SETTLE:
      fpi_ssm_next_state_delayed (ssm, 10);
      break;

    case ACTIVATE_UPLOAD_CONFIG:
      send_cmd (ssm, dev, GOODIX53XD_CMD_UPLOAD_CONFIG_MCU, device_config,
                sizeof (device_config), REPLY_MSG);
      break;

    case ACTIVATE_CHECK_CONFIG:
      if (!check_reply_len (ssm, self, 1, "config"))
        return;
      if (self->reply[0] != 0x01)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "Config upload rejected"));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_FDT_IDLE:
    case ACTIVATE_FDT_IDLE_REPLY:
      {
        guint8 mode[sizeof (fdt_idle_mode)];
        gboolean reply = fpi_ssm_get_cur_state (ssm) == ACTIVATE_FDT_IDLE_REPLY;

        memcpy (mode, fdt_idle_mode, sizeof (mode));
        mode[sizeof (mode) - 1] = reply;
        send_cmd (ssm, dev, GOODIX53XD_CMD_MCU_SWITCH_TO_FDT_MODE, mode,
                  sizeof (mode), reply ? REPLY_MSG : REPLY_NONE);
      }
      break;

    case ACTIVATE_CHECK_FDT:
      self->fdt_usable = update_fdt_base (self, self->reply, self->reply_len,
                                          FALSE);
      if (!self->fdt_usable)
        fp_warn ("No usable finger detection readings, polling instead");
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_CALIBRATE:
      start_capture (ssm, dev, &mode_detect);
      break;

    case ACTIVATE_CHECK_CALIBRATION:
      self->calibration_level = frame_mean (self->frame);
      fp_dbg ("Calibration level %.0f", self->calibration_level);

      if (self->calibration_level < CALIBRATION_MIN ||
          self->calibration_level > CALIBRATION_MAX)
        {
          if (++self->calibration_tries < CALIBRATION_TRIES)
            {
              /* Probably a finger resting on the sensor */
              fpi_ssm_jump_to_state_delayed (ssm, ACTIVATE_CALIBRATE, 500);
              return;
            }
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                         "Calibration failed "
                                                         "(level %.0f)",
                                                         self->calibration_level));
          return;
        }

      memcpy (self->calibration, self->frame,
              GOODIX53XD_FRAME_PIXELS * sizeof (guint16));
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static const char *
state_path (void)
{
  const char *path = g_getenv ("GOODIX53XD_STATE_FILE");

  return path ? path : STATE_FILE;
}

static void
activate_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);

  if (error)
    {
      g_clear_pointer (&self->tls, goodix53xd_tls_free);
      g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                      GOODIX53XD_INTERFACE, 0, NULL);
    }
  else
    {
      g_clear_pointer (&self->milan, goodix53xd_milan_free);
      self->milan = goodix53xd_milan_new ();
      goodix53xd_milan_load_state (self->milan, state_path ());
    }

  fpi_device_open_complete (dev, error);
}

/* ------------------------------------------------------------------------ */
/* Scanning                                                                  */

enum scan_states {
  SCAN_DETECT,
  SCAN_EVALUATE,
  SCAN_WAIT,
  SCAN_WAIT_DONE,
  SCAN_CAPTURE,
  SCAN_PROCESS,
  SCAN_NUM_STATES,
};

/* Development aid: GOODIX53XD_DUMP_DIR=<dir> saves every capture */
static void
dump_raw (const char *dir, gint64 n, const char *name, const guint16 *frame)
{
  g_autofree char *path = g_strdup_printf ("%s/%" G_GINT64_FORMAT "-%s.pgm", dir, n, name);
  g_autoptr(GString) out = g_string_new (NULL);

  g_string_append_printf (out, "P5 %d %d 4095\n", GOODIX53XD_FRAME_WIDTH,
                          GOODIX53XD_FRAME_HEIGHT);
  for (gsize i = 0; i < GOODIX53XD_FRAME_PIXELS; i++)
    {
      g_string_append_c (out, frame[i] >> 8);
      g_string_append_c (out, frame[i] & 0xff);
    }
  g_file_set_contents (path, out->str, out->len, NULL);
}

static void
dump_images (FpiDeviceGoodix53xd *self)
{
  gint64 counter = g_get_real_time () / 1000;
  const char *dir = g_getenv ("GOODIX53XD_DUMP_DIR");

  if (!dir)
    return;

  dump_raw (dir, counter, "finger-raw", self->frame);
  dump_raw (dir, counter, "calibration-raw", self->calibration);
  fp_dbg ("Dumped capture %" G_GINT64_FORMAT " to %s", counter, dir);
}

/* Returns TRUE once enough samples have been accepted */
static gboolean
process_enroll (FpiDeviceGoodix53xd *self)
{
  FpDevice *dev = FP_DEVICE (self);
  g_autoptr(GoodixMilanRuntimeOutput) out = NULL;
  GoodixMilanEnrollmentResult result = { 0 };
  GoodixMilanEnrollmentAttemptStatus status;
  FpDeviceRetry retry;
  guint count;

  out = goodix53xd_milan_run (self->milan, GOODIX_MILAN_PURPOSE_ENROLL, NULL);

  /* As in the vendor driver, a sample that was admitted but yielded nothing
   * to merge breaks a streak of rejected merges. */
  if (out->enrollment_sample_admitted &&
      !goodix_milan_runtime_enrollment_admitted (out) &&
      self->enroll_bad_continue < 3)
    self->enroll_bad_continue = 0;

  if (!goodix_milan_runtime_enrollment_admitted (out))
    {
      retry = out->coverage < GOODIX_MILAN_ENROLL_MIN_COVERAGE ?
              FP_DEVICE_RETRY_CENTER_FINGER : FP_DEVICE_RETRY_REMOVE_FINGER;
      fpi_device_enroll_progress (dev,
                                  goodix_milan_enrollment_transaction_count (self->enroll_tx),
                                  NULL, fpi_device_retry_new (retry));
      return FALSE;
    }

  status = goodix_milan_enrollment_transaction_attempt (&self->enroll_tx,
                                                        out->probe_template,
                                                        &self->enroll_bad_records,
                                                        &self->enroll_bad_continue,
                                                        &result);
  count = goodix_milan_enrollment_transaction_count (self->enroll_tx);

  switch (status)
    {
    case GOODIX_MILAN_ENROLLMENT_ACCEPTED:
      fp_dbg ("Enroll sample %u/%d accepted", count, ENROLL_SAMPLES);
      fpi_device_enroll_progress (dev, count, NULL, NULL);
      return count >= ENROLL_SAMPLES;

    case GOODIX_MILAN_ENROLLMENT_RETRY_CENTER:
      /* Too little overlap with the samples so far */
      fp_dbg ("Enroll sample rejected (overlap %d, detail %u)",
              result.overlap, result.reject_detail);
      retry = FP_DEVICE_RETRY_CENTER_FINGER;
      break;

    case GOODIX_MILAN_ENROLLMENT_RETRY_REMOVE:
    default:
      retry = FP_DEVICE_RETRY_REMOVE_FINGER;
      break;
    }

  fpi_device_enroll_progress (dev, count, NULL, fpi_device_retry_new (retry));
  return FALSE;
}

static void
report_match (FpiDeviceGoodix53xd *self, FpPrint *match, GError *retry)
{
  FpDevice *dev = FP_DEVICE (self);

  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_report (dev, retry ? FPI_MATCH_ERROR :
                              match ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                              NULL, retry);
  else
    fpi_device_identify_report (dev, match, NULL, retry);
}

static gboolean
process_match (FpiDeviceGoodix53xd *self, GError **error)
{
  g_autoptr(GoodixMilanRuntimeOutput) out = NULL;

  /* fprintd identifies against all prints before enrolling, so an empty
   * gallery is normal there */
  if (self->templates->len == 0)
    {
      report_match (self, NULL, NULL);
      return TRUE;
    }

  out = goodix53xd_milan_run (self->milan, GOODIX_MILAN_PURPOSE_IDENTIFY,
                              self->templates);

  switch (out->status)
    {
    case GOODIX_MILAN_RUNTIME_MATCH:
      if (out->winner_index >= self->gallery->len)
        break;
      fp_info ("Match with score %d", out->score);
      goodix53xd_milan_save_state (self->milan, state_path ());
      report_match (self, g_ptr_array_index (self->gallery, out->winner_index),
                    NULL);
      return TRUE;

    case GOODIX_MILAN_RUNTIME_NO_MATCH:
      fp_info ("No match (best score %d)", out->score);
      report_match (self, NULL, NULL);
      return TRUE;

    case GOODIX_MILAN_RUNTIME_RETRY:
      report_match (self, NULL,
                    fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER));
      return TRUE;

    case GOODIX_MILAN_RUNTIME_INVALID_DATA:
    case GOODIX_MILAN_RUNTIME_CANCELLED:
      break;
    }

  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
               "Matcher failed (status %d): %s", out->status,
               out->error ? out->error->message : "no details");
  return FALSE;
}

static void
scan_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);
  GError *error = NULL;
  gboolean done;
  double ratio;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SCAN_DETECT:
      /* Cancellation is only honoured here: an interrupted command would
       * leave the TLS session out of sequence. */
      if (g_cancellable_set_error_if_cancelled (fpi_device_get_cancellable (dev),
                                                &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      start_capture (ssm, dev, &mode_detect);
      break;

    case SCAN_EVALUATE:
      ratio = covered_ratio (self->frame, self->calibration_level);

      if (self->await_finger_off && ratio <= FINGER_OFF_RATIO)
        {
          fp_dbg ("Finger off");
          self->await_finger_off = FALSE;
          self->landing_polls = 0;
          fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NEEDED,
                                                   FP_FINGER_STATUS_PRESENT);
        }
      else if (!self->await_finger_off && ratio >= FINGER_ON_RATIO)
        {
          fp_dbg ("Finger on (%.0f%% covered)", ratio * 100);
          fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_PRESENT,
                                                   FP_FINGER_STATUS_NEEDED);
          fpi_ssm_jump_to_state (ssm, SCAN_CAPTURE);
          return;
        }
      else if (!self->await_finger_off && self->landing_polls > 0)
        {
          /* Finger-down fired; wait for the finger to settle */
          self->landing_polls--;
          fpi_ssm_jump_to_state_delayed (ssm, SCAN_DETECT, LANDING_POLL_MS);
          return;
        }

      if (self->fdt_usable)
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_jump_to_state_delayed (ssm, SCAN_DETECT, GOODIX53XD_POLL_MS);
      break;

    case SCAN_WAIT:
      start_fdt (ssm, dev, self->await_finger_off ?
                 GOODIX53XD_CMD_MCU_SWITCH_TO_FDT_UP :
                 GOODIX53XD_CMD_MCU_SWITCH_TO_FDT_DOWN);
      break;

    case SCAN_WAIT_DONE:
      if (self->fdt_event && !self->await_finger_off)
        self->landing_polls = LANDING_POLLS;
      fpi_ssm_jump_to_state (ssm, SCAN_DETECT);
      break;

    case SCAN_CAPTURE:
      start_capture (ssm, dev, &mode_finger);
      break;

    case SCAN_PROCESS:
      dump_images (self);
      goodix53xd_milan_set_frames (self->milan, self->frame, self->calibration);

      if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_ENROLL)
        {
          done = process_enroll (self);
        }
      else
        {
          done = process_match (self, &error);
          if (error)
            {
              fpi_ssm_mark_failed (ssm, error);
              return;
            }
        }

      if (done)
        {
          fpi_ssm_mark_completed (ssm);
          return;
        }

      self->await_finger_off = TRUE;
      fpi_ssm_jump_to_state (ssm, SCAN_DETECT);
      break;
    }
}

static void
enroll_finish (FpiDeviceGoodix53xd *self, GError *error)
{
  FpDevice *dev = FP_DEVICE (self);
  g_autoptr(GBytes) template = NULL;
  GVariant *data = NULL;
  FpPrint *print;

  if (!error)
    {
      template = goodix_milan_enrollment_transaction_publish (self->enroll_tx);
      if (template)
        data = goodix_milan_print_build_data (template, &error);
      else
        error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                          "Failed to build template");
    }
  g_clear_pointer (&self->enroll_tx, goodix_milan_enrollment_transaction_free);

  if (error)
    {
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  goodix53xd_milan_save_state (self->milan, state_path ());
  fpi_device_get_enroll_data (dev, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data", data, NULL);
  g_variant_unref (data);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
scan_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);

  g_clear_pointer (&self->gallery, g_ptr_array_unref);
  g_clear_pointer (&self->templates, g_ptr_array_unref);

  switch (fpi_device_get_current_action (dev))
    {
    case FPI_DEVICE_ACTION_ENROLL:
      enroll_finish (self, error);
      break;

    case FPI_DEVICE_ACTION_VERIFY:
      fpi_device_verify_complete (dev, error);
      break;

    case FPI_DEVICE_ACTION_IDENTIFY:
      fpi_device_identify_complete (dev, error);
      break;

    case FPI_DEVICE_ACTION_NONE:
    case FPI_DEVICE_ACTION_PROBE:
    case FPI_DEVICE_ACTION_OPEN:
    case FPI_DEVICE_ACTION_CLOSE:
    case FPI_DEVICE_ACTION_CAPTURE:
    case FPI_DEVICE_ACTION_LIST:
    case FPI_DEVICE_ACTION_DELETE:
    case FPI_DEVICE_ACTION_CLEAR_STORAGE:
      g_assert_not_reached ();
    }
}

static void
scan_start (FpiDeviceGoodix53xd *self)
{
  /* A finger still resting on the sensor must be lifted first */
  self->await_finger_off = TRUE;
  fpi_ssm_start (fpi_ssm_new (FP_DEVICE (self), scan_run_state, SCAN_NUM_STATES),
                 scan_complete);
}

/* ------------------------------------------------------------------------ */
/* Device interface                                                          */

static void
dev_open (FpDevice *dev)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);
  GError *error = NULL;

  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (dev),
                                     GOODIX53XD_INTERFACE, 0, &error))
    {
      fpi_device_open_complete (dev, error);
      return;
    }

  /* Bring up the TLS session and calibrate once per open */
  self->calibration_tries = 0;
  fpi_ssm_start (fpi_ssm_new (dev, activate_run_state, ACTIVATE_NUM_STATES),
                 activate_complete);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);
  GError *error = NULL;

  g_clear_pointer (&self->tls, goodix53xd_tls_free);
  g_clear_pointer (&self->milan, goodix53xd_milan_free);
  g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                  GOODIX53XD_INTERFACE, 0, &error);
  fpi_device_close_complete (dev, error);
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);

  g_clear_pointer (&self->enroll_tx, goodix_milan_enrollment_transaction_free);
  self->enroll_tx = goodix_milan_enrollment_transaction_new ();
  self->enroll_bad_records = 0;
  self->enroll_bad_continue = 0;
  scan_start (self);
}

static gboolean
add_to_gallery (FpiDeviceGoodix53xd *self, FpPrint *print, GError **error)
{
  g_autoptr(GVariant) data = NULL;
  GBytes *template = NULL;
  FpiPrintType type;

  g_object_get (print, "fpi-type", &type, "fpi-data", &data, NULL);
  if (type != FPI_PRINT_RAW || !data)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "Print holds no template");
      return FALSE;
    }
  if (!goodix_milan_print_parse_data (data, &template, error))
    return FALSE;

  g_ptr_array_add (self->gallery, print);
  g_ptr_array_add (self->templates, template);
  return TRUE;
}

static void
dev_match (FpDevice *dev)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (dev);
  GError *error = NULL;

  self->gallery = g_ptr_array_new ();
  self->templates = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);

  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    {
      FpPrint *print;

      fpi_device_get_verify_data (dev, &print);
      add_to_gallery (self, print, &error);
    }
  else
    {
      GPtrArray *prints;

      fpi_device_get_identify_data (dev, &prints);
      for (guint i = 0; i < prints->len; i++)
        {
          g_autoptr(GError) local_error = NULL;

          /* Skip prints this driver cannot use rather than failing */
          if (!add_to_gallery (self, g_ptr_array_index (prints, i), &local_error))
            fp_warn ("Ignoring print %u: %s", i, local_error->message);
        }
    }

  if (error)
    {
      g_clear_pointer (&self->gallery, g_ptr_array_unref);
      g_clear_pointer (&self->templates, g_ptr_array_unref);
      if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_complete (dev, error);
      else
        fpi_device_identify_complete (dev, error);
      return;
    }

  scan_start (self);
}

static const FpIdEntry id_table[] = {
  { .vid = 0x27c6, .pid = 0x532d, },
  { .vid = 0,      .pid = 0,      },
};

static void
fpi_device_goodix53xd_init (FpiDeviceGoodix53xd *self)
{
  self->rx = g_byte_array_new ();
  self->tls_out = g_byte_array_new ();
  self->frame = g_new0 (guint16, GOODIX53XD_FRAME_PIXELS);
  self->calibration = g_new0 (guint16, GOODIX53XD_FRAME_PIXELS);
}

static void
fpi_device_goodix53xd_finalize (GObject *object)
{
  FpiDeviceGoodix53xd *self = FPI_DEVICE_GOODIX53XD (object);

  g_clear_pointer (&self->tx, g_byte_array_unref);
  g_clear_pointer (&self->rx, g_byte_array_unref);
  g_clear_pointer (&self->tls_out, g_byte_array_unref);
  g_clear_pointer (&self->tls, goodix53xd_tls_free);
  g_clear_pointer (&self->frame, g_free);
  g_clear_pointer (&self->calibration, g_free);
  g_clear_pointer (&self->milan, goodix53xd_milan_free);
  g_clear_pointer (&self->enroll_tx, goodix_milan_enrollment_transaction_free);
  g_clear_pointer (&self->gallery, g_ptr_array_unref);
  g_clear_pointer (&self->templates, g_ptr_array_unref);
  g_clear_error (&self->fdt_error);

  G_OBJECT_CLASS (fpi_device_goodix53xd_parent_class)->finalize (object);
}

static void
fpi_device_goodix53xd_class_init (FpiDeviceGoodix53xdClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  object_class->finalize = fpi_device_goodix53xd_finalize;

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Goodix 53xd TLS Fingerprint Sensor";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = ENROLL_SAMPLES;
  /* Waiting for a finger does not heat the sensor, so the lock screen may
   * keep a verify running indefinitely */
  dev_class->temp_hot_seconds = -1;

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_match;
  dev_class->identify = dev_match;

  fpi_device_class_auto_initialize_features (dev_class);
}
