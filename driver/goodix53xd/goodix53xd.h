/*
 * Goodix 53xd (TLS) fingerprint sensor driver for libfprint
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

#pragma once

#include "fpi-device.h"

#define GOODIX53XD_EP_IN       0x83
#define GOODIX53XD_EP_OUT      0x01
#define GOODIX53XD_INTERFACE   0
#define GOODIX53XD_PACKET_SIZE 64

#define GOODIX53XD_USB_TIMEOUT 2000
#define GOODIX53XD_POLL_MS     100

/* The sensor delivers 80 rows of 64 pixels, 12 bits each, packed as
 * 4 pixels per 6 bytes. The decrypted payload has a 4 byte trailer. */
#define GOODIX53XD_FRAME_WIDTH  64
#define GOODIX53XD_FRAME_HEIGHT 80
#define GOODIX53XD_FRAME_PIXELS (GOODIX53XD_FRAME_WIDTH * GOODIX53XD_FRAME_HEIGHT)
#define GOODIX53XD_FRAME_BYTES  (GOODIX53XD_FRAME_PIXELS / 4 * 6)
#define GOODIX53XD_FRAME_PLAIN  (GOODIX53XD_FRAME_BYTES + 4)

/* The outermost pixel ring is unusable and gets cropped */
#define GOODIX53XD_BORDER     1
#define GOODIX53XD_IMG_WIDTH  (GOODIX53XD_FRAME_WIDTH - 2 * GOODIX53XD_BORDER)
#define GOODIX53XD_IMG_HEIGHT (GOODIX53XD_FRAME_HEIGHT - 2 * GOODIX53XD_BORDER)

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix53xd, fpi_device_goodix53xd, FPI,
                      DEVICE_GOODIX53XD, FpDevice)
