/* Offline Milan harness for Goodix 532d captures.
 *
 * usage: harness <setup.bin> enroll <live.bin>... -- probe <live.bin>...
 * Frames are 88x108 little-endian u16 (see tools/milan_frames.py). A file
 * <live.bin>.setup overrides setup.bin for that frame. RESET_STATE containing
 * "state" and/or "profile" resets that Milan state before probing.
 *
 * Copyright (C) 2026 Arian Kulmer <arian.kulmer@web.de>
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "milan/runtime.h"
#include "milan/match/match.h"
#include "milan/print.h"

#define ENROLL_SAMPLES 12

static guint16 *
load_frame (const char *path)
{
  gchar *data = NULL;
  gsize len = 0;

  if (!g_file_get_contents (path, &data, &len, NULL) ||
      len != GOODIX_MILAN_SENSOR_PIXELS * 2)
    {
      fprintf (stderr, "bad frame %s (%zu bytes)\n", path, len);
      exit (2);
    }
  return (guint16 *) data;
}

static guint16 *load_frame (const char *path);
static guint16 *global_setup;

/* Per-capture setup frame <live>.setup next to the live frame, if present */
static guint16 *
setup_for (const char *live)
{
  g_autofree char *p = g_strconcat (live, ".setup", NULL);
  static guint16 *last;

  if (!g_file_test (p, G_FILE_TEST_EXISTS))
    return global_setup;
  g_free (last);
  last = load_frame (p);
  return last;
}

static GoodixMilanRuntimeOutput *
run (guint64 epoch, GoodixMilanPreprocessPurpose purpose,
     GoodixMilanPreprocessState *state, GoodixMilanProfileState *profile,
     guint16 *setup, guint16 *live, GBytes *template)
{
  GoodixMilanRuntimeGalleryInput *gallery[1];
  GoodixMilanRuntimeInput *input;
  GoodixMilanRuntimeOutput *out;
  gsize n = 0;

  if (template)
    gallery[n++] = goodix_milan_runtime_gallery_input_new (0, template);

  input = goodix_milan_runtime_input_new (epoch, 1, purpose, state, profile,
                                          setup, live, 0, 0x97, 0xd0,
                                          GOODIX_MILAN_PRINT_SENSOR_TYPE,
                                          n ? gallery : NULL, n);
  out = goodix_milan_runtime_run (input);
  goodix_milan_runtime_input_free (input);
  for (gsize i = 0; i < n; i++)
    goodix_milan_runtime_gallery_input_free (gallery[i]);

  if (out->preprocess_state_valid)
    *state = out->preprocess_state;
  *profile = out->profile_state;
  return out;
}

int
main (int argc, char **argv)
{
  GoodixMilanPreprocessState state;
  GoodixMilanProfileState profile;
  g_autoptr(GoodixMilanEnrollmentTransaction) tx = goodix_milan_enrollment_transaction_new ();
  guint bad_records = 0, bad_continue = 0;
  GBytes *template = NULL;
  guint16 *setup;
  int i = 3;
  guint64 epoch = 1;

  if (argc < 4 || strcmp (argv[2], "enroll") != 0)
    {
      fprintf (stderr, "usage: %s setup.bin enroll live... -- probe live...\n", argv[0]);
      return 2;
    }

  memset (&state, 0, sizeof (state));
  memset (&profile, 0, sizeof (profile));
  goodix_milan_preprocess_reset (&state);
  setup = load_frame (argv[1]);
  global_setup = setup;

  for (; i < argc && strcmp (argv[i], "--") != 0; i++)
    {
      guint16 *live = load_frame (argv[i]);
      GoodixMilanRuntimeOutput *out;
      GoodixMilanEnrollmentResult result = { 0 };
      int status = -1;

      if (goodix_milan_enrollment_transaction_count (tx) >= ENROLL_SAMPLES)
        {
          g_free (live);
          continue;
        }

      out = run (epoch++, GOODIX_MILAN_PURPOSE_ENROLL, &state, &profile,
                 setup_for (argv[i]), live, NULL);
      if (goodix_milan_runtime_enrollment_admitted (out))
        status = goodix_milan_enrollment_transaction_attempt (
          &tx, out->probe_template, &bad_records, &bad_continue, &result);

      printf ("ENROLL %s status=%d quality=%d coverage=%d admitted=%d "
              "admission=%u/%u records=%u attempt=%d count=%u%s%s\n",
              argv[i], out->status, out->quality, out->coverage,
              goodix_milan_runtime_enrollment_admitted (out),
              out->admission_status, out->admission_detail,
              out->probe_record_count, status,
              goodix_milan_enrollment_transaction_count (tx),
              out->error ? " error=" : "", out->error ? out->error->message : "");
      goodix_milan_runtime_output_free (out);
      g_free (live);
    }

  if (goodix_milan_enrollment_transaction_count (tx) < ENROLL_SAMPLES)
    {
      printf ("ENROLL_INCOMPLETE %u\n", goodix_milan_enrollment_transaction_count (tx));
      return 1;
    }

  template = goodix_milan_enrollment_transaction_publish (tx);
  printf ("TEMPLATE %zu bytes\n", template ? g_bytes_get_size (template) : 0);
  if (g_getenv ("ROUNDTRIP"))
    {
      g_autoptr(GError) err = NULL;
      GVariant *v = g_variant_ref_sink (goodix_milan_print_build_data (template, &err));
      g_autoptr(GBytes) ser = g_variant_get_data_as_bytes (v);
      g_autoptr(GVariant) back = g_variant_ref_sink (g_variant_new_from_bytes (g_variant_get_type (v), ser, FALSE));
      GBytes *t2 = NULL;

      if (!goodix_milan_print_parse_data (back, &t2, &err))
        printf ("PARSE FAILED %s\n", err->message);
      printf ("ROUNDTRIP %zu bytes equal=%d\n", g_bytes_get_size (t2), g_bytes_equal (t2, template));
      g_bytes_unref (template);
      template = t2;
    }
  if (!template)
    return 1;

  if (g_getenv ("RESET_STATE") && strstr (g_getenv ("RESET_STATE"), "state"))
    {
      memset (&state, 0, sizeof (state));
      goodix_milan_preprocess_reset (&state);
    }
  if (g_getenv ("RESET_STATE") && strstr (g_getenv ("RESET_STATE"), "profile"))
    memset (&profile, 0, sizeof (profile));

  for (i++; i < argc; i++)
    {
      guint16 *live;
      GoodixMilanRuntimeOutput *out;

      if (strcmp (argv[i], "probe") == 0)
        continue;
      live = load_frame (argv[i]);
      out = run (epoch++, GOODIX_MILAN_PURPOSE_IDENTIFY, &state, &profile,
                 setup_for (argv[i]), live, template);
      printf ("PROBE %s status=%d score=%d quality=%d coverage=%d records=%u%s%s\n",
              argv[i], out->status, out->score, out->quality, out->coverage,
              out->probe_record_count,
              out->error ? " error=" : "", out->error ? out->error->message : "");
      goodix_milan_runtime_output_free (out);
      g_free (live);
    }

  g_bytes_unref (template);
  g_free (setup);
  return 0;
}
