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

#define FP_COMPONENT "goodix53xd"

#include "drivers_api.h"
#include "goodix53xd_tls.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

/* The only suite the sensor firmware offers */
#define GOODIX53XD_TLS_CIPHERS "PSK-AES128-CBC-SHA256"

struct _Goodix53xdTls
{
  SSL_CTX *ctx;
  SSL     *ssl;
  BIO     *rbio;   /* sensor -> host */
  BIO     *wbio;   /* host -> sensor */
  gboolean bios_attached;
  guint8   psk[64];
  gsize    psk_len;
};

static int tls_ex_index = -1;

static void
set_openssl_error (GError **error, const char *what)
{
  char buf[256];
  unsigned long err = ERR_get_error ();

  ERR_error_string_n (err, buf, sizeof (buf));
  ERR_clear_error ();
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "TLS %s failed: %s", what, err ? buf : "unknown error");
}

static unsigned int
psk_server_cb (SSL *ssl, const char *identity, unsigned char *psk,
               unsigned int max_psk_len)
{
  Goodix53xdTls *tls = SSL_get_ex_data (ssl, tls_ex_index);

  if (tls->psk_len > max_psk_len)
    return 0;

  memcpy (psk, tls->psk, tls->psk_len);
  return tls->psk_len;
}

Goodix53xdTls *
goodix53xd_tls_new (const guint8 *psk, gsize psk_len, GError **error)
{
  g_autoptr(Goodix53xdTls) tls = g_new0 (Goodix53xdTls, 1);

  g_return_val_if_fail (psk_len <= sizeof (tls->psk), NULL);

  if (tls_ex_index < 0)
    tls_ex_index = SSL_get_ex_new_index (0, NULL, NULL, NULL, NULL);

  memcpy (tls->psk, psk, psk_len);
  tls->psk_len = psk_len;

  tls->ctx = SSL_CTX_new (TLS_server_method ());
  if (!tls->ctx ||
      !SSL_CTX_set_min_proto_version (tls->ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_max_proto_version (tls->ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_cipher_list (tls->ctx, GOODIX53XD_TLS_CIPHERS))
    {
      set_openssl_error (error, "setup");
      return NULL;
    }
  SSL_CTX_set_psk_server_callback (tls->ctx, psk_server_cb);

  tls->ssl = SSL_new (tls->ctx);
  tls->rbio = BIO_new (BIO_s_mem ());
  tls->wbio = BIO_new (BIO_s_mem ());
  if (!tls->ssl || !tls->rbio || !tls->wbio)
    {
      set_openssl_error (error, "setup");
      return NULL;
    }

  /* SSL takes ownership of both BIOs */
  SSL_set_bio (tls->ssl, tls->rbio, tls->wbio);
  tls->bios_attached = TRUE;
  SSL_set_ex_data (tls->ssl, tls_ex_index, tls);
  SSL_set_accept_state (tls->ssl);

  return g_steal_pointer (&tls);
}

void
goodix53xd_tls_free (Goodix53xdTls *tls)
{
  if (!tls)
    return;

  if (!tls->bios_attached)
    {
      BIO_free (tls->rbio);
      BIO_free (tls->wbio);
    }
  SSL_free (tls->ssl);
  SSL_CTX_free (tls->ctx);
  explicit_bzero (tls->psk, sizeof (tls->psk));
  g_free (tls);
}

static void
drain_output (Goodix53xdTls *tls, GByteArray *out)
{
  guint8 buf[4096];
  int n;

  while ((n = BIO_read (tls->wbio, buf, sizeof (buf))) > 0)
    g_byte_array_append (out, buf, n);
}

gboolean
goodix53xd_tls_handshake (Goodix53xdTls *tls, const guint8 *in, gsize in_len,
                          GByteArray *out, GError **error)
{
  int ret;

  if (in_len > 0 && BIO_write (tls->rbio, in, in_len) != (int) in_len)
    {
      set_openssl_error (error, "input");
      return FALSE;
    }

  ret = SSL_do_handshake (tls->ssl);
  drain_output (tls, out);

  if (ret == 1)
    return TRUE;

  switch (SSL_get_error (tls->ssl, ret))
    {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return TRUE;

    default:
      set_openssl_error (error, "handshake");
      return FALSE;
    }
}

gboolean
goodix53xd_tls_is_established (Goodix53xdTls *tls)
{
  return SSL_is_init_finished (tls->ssl);
}

gboolean
goodix53xd_tls_decrypt (Goodix53xdTls *tls, const guint8 *in, gsize in_len,
                        gsize want, GByteArray *out, GError **error)
{
  guint8 buf[4096];

  if (in_len > 0 && BIO_write (tls->rbio, in, in_len) != (int) in_len)
    {
      set_openssl_error (error, "input");
      return FALSE;
    }

  while (out->len < want)
    {
      int n = SSL_read (tls->ssl, buf, MIN (sizeof (buf), want - out->len));

      if (n > 0)
        {
          g_byte_array_append (out, buf, n);
          continue;
        }

      if (SSL_get_error (tls->ssl, n) == SSL_ERROR_WANT_READ)
        break;

      set_openssl_error (error, "read");
      return FALSE;
    }

  /* Drop surplus plaintext, otherwise it would prefix the next reply */
  while (SSL_pending (tls->ssl) > 0)
    {
      int n = SSL_read (tls->ssl, buf, sizeof (buf));

      if (n <= 0)
        break;
      fp_warn ("Dropped %d surplus plaintext bytes", n);
    }

  return TRUE;
}
