/*
 * Goodix 53xd (TLS) fingerprint sensor driver for libfprint
 * Message framing
 *
 * Copyright (C) 2026 Arian Kulmer <arian.kulmer@web.de>
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

#include "drivers_api.h"
#include "goodix53xd_proto.h"

static guint8
sum_bytes (const guint8 *data, gsize len)
{
  guint8 sum = 0;

  for (gsize i = 0; i < len; i++)
    sum += data[i];

  return sum;
}

GByteArray *
goodix53xd_encode_pack (guint8 flags, const guint8 *payload, gsize len)
{
  GByteArray *pack = g_byte_array_sized_new (GOODIX53XD_PACK_HEADER_LEN + len);
  guint8 header[GOODIX53XD_PACK_HEADER_LEN];

  g_assert (len <= G_MAXUINT16);

  header[0] = flags;
  header[1] = len & 0xff;
  header[2] = len >> 8;
  header[3] = sum_bytes (header, 3);

  g_byte_array_append (pack, header, sizeof (header));
  g_byte_array_append (pack, payload, len);

  return pack;
}

GByteArray *
goodix53xd_encode_msg (Goodix53xdCmd cmd, const guint8 *payload, gsize len,
                       gboolean checksum)
{
  g_autoptr(GByteArray) msg = g_byte_array_sized_new (len + 4);
  guint8 header[3];
  guint8 trailer;

  g_assert (len < G_MAXUINT16);

  header[0] = cmd;
  header[1] = (len + 1) & 0xff;
  header[2] = (len + 1) >> 8;

  g_byte_array_append (msg, header, sizeof (header));
  g_byte_array_append (msg, payload, len);

  trailer = checksum ? 0xaa - sum_bytes (msg->data, msg->len) : 0x88;
  g_byte_array_append (msg, &trailer, 1);

  return goodix53xd_encode_pack (GOODIX53XD_FLAGS_MSG, msg->data, msg->len);
}

/* Returns the total size of the pack starting at @data, or -1 if the header
 * is not complete yet. */
gssize
goodix53xd_pack_total_len (const guint8 *data, gsize len)
{
  if (len < GOODIX53XD_PACK_HEADER_LEN)
    return -1;

  return GOODIX53XD_PACK_HEADER_LEN + (data[1] | (data[2] << 8));
}

gboolean
goodix53xd_decode_pack (const guint8 *data, gsize len, guint8 expected_flags,
                        const guint8 **payload, gsize *payload_len,
                        GError **error)
{
  gssize total = goodix53xd_pack_total_len (data, len);

  if (total < 0 || len < (gsize) total)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Truncated pack (%" G_GSIZE_FORMAT " bytes)", len);
      return FALSE;
    }

  if (sum_bytes (data, 3) != data[3])
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Invalid pack header checksum");
      return FALSE;
    }

  if (data[0] != expected_flags)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected pack flags 0x%02x (wanted 0x%02x)",
                   data[0], expected_flags);
      return FALSE;
    }

  *payload = data + GOODIX53XD_PACK_HEADER_LEN;
  *payload_len = total - GOODIX53XD_PACK_HEADER_LEN;
  return TRUE;
}

gboolean
goodix53xd_decode_msg (const guint8 *data, gsize len, Goodix53xdCmd expected_cmd,
                       const guint8 **payload, gsize *payload_len,
                       GError **error)
{
  const guint8 *msg;
  gsize msg_len, body_len;

  if (!goodix53xd_decode_pack (data, len, GOODIX53XD_FLAGS_MSG, &msg, &msg_len,
                               error))
    return FALSE;

  if (msg_len < 4)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Message too short");
      return FALSE;
    }

  /* The length field counts the payload plus the checksum byte */
  body_len = msg[1] | (msg[2] << 8);
  if (body_len < 1 || 3 + body_len > msg_len)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Invalid message length %" G_GSIZE_FORMAT, body_len);
      return FALSE;
    }

  if (msg[2 + body_len] != (guint8) (0xaa - sum_bytes (msg, 2 + body_len)))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Invalid message checksum");
      return FALSE;
    }

  if (msg[0] != expected_cmd)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Unexpected command 0x%02x (wanted 0x%02x)",
                   msg[0], expected_cmd);
      return FALSE;
    }

  *payload = msg + 3;
  *payload_len = body_len - 1;
  return TRUE;
}

gboolean
goodix53xd_check_ack (const guint8 *payload, gsize len, Goodix53xdCmd cmd,
                      GError **error)
{
  if (len < 2 || !(payload[1] & 0x01))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Invalid ACK");
      return FALSE;
    }

  if (payload[0] != cmd)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "ACK for command 0x%02x, wanted 0x%02x", payload[0], cmd);
      return FALSE;
    }

  return TRUE;
}
