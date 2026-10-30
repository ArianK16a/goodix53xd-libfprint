/*
 * Goodix 53xd (TLS) fingerprint sensor driver for libfprint
 * Message framing
 *
 * Copyright (C) 2026 Arian Kulmer <arian.kulmer@web.de>
 *
 * Based on the protocol documented by the goodix-fp-linux-dev project
 * (goodix-fp-dump).
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

#pragma once

#include <glib.h>

/* Every USB transfer carries one "pack": flags, length, header checksum and
 * payload. Packs with GOODIX53XD_FLAGS_MSG wrap a protocol message (command,
 * length, payload, checksum); the TLS packs carry raw TLS records. */
#define GOODIX53XD_FLAGS_MSG      0xa0
#define GOODIX53XD_FLAGS_TLS      0xb0
#define GOODIX53XD_FLAGS_TLS_DATA 0xb2

#define GOODIX53XD_PACK_HEADER_LEN 4

typedef enum {
  GOODIX53XD_CMD_NOP                    = 0x00,
  GOODIX53XD_CMD_MCU_GET_IMAGE          = 0x20,
  GOODIX53XD_CMD_MCU_SWITCH_TO_FDT_DOWN = 0x32,
  GOODIX53XD_CMD_MCU_SWITCH_TO_FDT_UP   = 0x34,
  GOODIX53XD_CMD_MCU_SWITCH_TO_FDT_MODE = 0x36,
  GOODIX53XD_CMD_WRITE_SENSOR_REGISTER  = 0x80,
  GOODIX53XD_CMD_READ_SENSOR_REGISTER   = 0x82,
  GOODIX53XD_CMD_UPLOAD_CONFIG_MCU      = 0x90,
  GOODIX53XD_CMD_RESET                  = 0xa2,
  GOODIX53XD_CMD_READ_OTP               = 0xa6,
  GOODIX53XD_CMD_FIRMWARE_VERSION       = 0xa8,
  GOODIX53XD_CMD_ACK                    = 0xb0,
  GOODIX53XD_CMD_REQUEST_TLS_CONNECTION = 0xd0,
  GOODIX53XD_CMD_PRESET_PSK_READ        = 0xe4,
} Goodix53xdCmd;

GByteArray *goodix53xd_encode_pack (guint8        flags,
                                    const guint8 *payload,
                                    gsize         len);

GByteArray *goodix53xd_encode_msg (Goodix53xdCmd cmd,
                                   const guint8 *payload,
                                   gsize         len,
                                   gboolean      checksum);

gssize      goodix53xd_pack_total_len (const guint8 *data,
                                       gsize         len);

gboolean    goodix53xd_decode_pack (const guint8  *data,
                                    gsize          len,
                                    guint8         expected_flags,
                                    const guint8 **payload,
                                    gsize         *payload_len,
                                    GError       **error);

gboolean    goodix53xd_decode_msg (const guint8  *data,
                                   gsize          len,
                                   Goodix53xdCmd  expected_cmd,
                                   const guint8 **payload,
                                   gsize         *payload_len,
                                   GError       **error);

gboolean    goodix53xd_check_ack (const guint8 *payload,
                                  gsize         len,
                                  Goodix53xdCmd cmd,
                                  GError      **error);
