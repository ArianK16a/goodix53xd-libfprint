/*
 * Goodix 53xd (TLS) fingerprint sensor driver for libfprint
 * TLS-PSK session
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

#include <glib.h>

/* The sensor acts as TLS client and the host as server. Records are shuttled
 * through memory BIOs, so no sockets or threads are involved. */
typedef struct _Goodix53xdTls Goodix53xdTls;

Goodix53xdTls *goodix53xd_tls_new (const guint8 *psk,
                                   gsize         psk_len,
                                   GError      **error);
void           goodix53xd_tls_free (Goodix53xdTls *tls);

/* Feed records received from the sensor and advance the handshake. Any
 * records the server wants to send are appended to @out. */
gboolean       goodix53xd_tls_handshake (Goodix53xdTls *tls,
                                         const guint8  *in,
                                         gsize          in_len,
                                         GByteArray    *out,
                                         GError       **error);
gboolean       goodix53xd_tls_is_established (Goodix53xdTls *tls);

/* Decrypt application data records into @out; reads until @want bytes are
 * available or the input is exhausted. */
gboolean       goodix53xd_tls_decrypt (Goodix53xdTls *tls,
                                       const guint8  *in,
                                       gsize          in_len,
                                       gsize          want,
                                       GByteArray    *out,
                                       GError       **error);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (Goodix53xdTls, goodix53xd_tls_free)
