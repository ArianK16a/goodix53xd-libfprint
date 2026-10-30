/*
 * Goodix 53xd (TLS) fingerprint sensor driver for libfprint
 * Glue to the Milan matcher
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

/*
 * Milan was built for the 108x88 Goodix 53x5 sensors, whose empty-sensor
 * ("setup") frame is captured in the same mode as the finger frame. On the
 * 53xd that frame saturates, so a setup frame is synthesised instead: a flat
 * level carrying the sensor's fixed offset pattern, taken from the
 * calibration frame. Milan computes setup minus live, which cancels the
 * pattern and leaves the ridges; uncovered pixels read 4095 and drop below
 * the setup level, so Milan masks them out by itself.
 *
 * The 62x78 usable area is transposed to landscape and resampled to fill
 * Milan's 88x108 geometry.
 */

#define FP_COMPONENT "goodix53xd"

#include "drivers_api.h"
#include "goodix53xd.h"
#include "goodix53xd_milan.h"

#include "milan/print.h"

/* Must stay below Milan's setup admission limit of 3800 */
#define SETUP_LEVEL     3400.0
#define FPN_SCALE       0.98
#define FPN_RADIUS      4
#define MILAN_ROWS      GOODIX_MILAN_SENSOR_ROWS
#define MILAN_COLUMNS   GOODIX_MILAN_SENSOR_COLUMNS

/* Not calibrated for this sensor; only used by the anti-fake stage */
#define MILAN_TCODE     0
#define MILAN_DAC_HIGH  0x97
#define MILAN_DAC_LOW   0xd0

Goodix53xdMilan *
goodix53xd_milan_new (void)
{
  Goodix53xdMilan *milan = g_new0 (Goodix53xdMilan, 1);

  goodix_milan_preprocess_reset (&milan->state);
  return milan;
}

void
goodix53xd_milan_free (Goodix53xdMilan *milan)
{
  g_free (milan);
}

/* The state is stored as raw memory, so the size doubles as a version */
#define STATE_MAGIC "G53XDMS1"

typedef struct
{
  char    magic[8];
  guint32 size;
} StateHeader;

void
goodix53xd_milan_load_state (Goodix53xdMilan *milan, const char *path)
{
  g_autofree gchar *contents = NULL;
  g_autoptr(GError) error = NULL;
  const StateHeader *header;
  gsize len;

  if (!g_file_get_contents (path, &contents, &len, &error))
    {
      fp_dbg ("No matcher state loaded: %s", error->message);
      return;
    }

  header = (const StateHeader *) contents;
  if (len != sizeof (*header) + sizeof (milan->state) ||
      memcmp (header->magic, STATE_MAGIC, sizeof (header->magic)) != 0 ||
      header->size != sizeof (milan->state))
    {
      fp_warn ("Ignoring incompatible matcher state %s", path);
      return;
    }

  memcpy (&milan->state, contents + sizeof (*header), sizeof (milan->state));
  fp_dbg ("Loaded matcher state from %s", path);
}

void
goodix53xd_milan_save_state (Goodix53xdMilan *milan, const char *path)
{
  g_autoptr(GByteArray) contents = g_byte_array_new ();
  g_autoptr(GError) error = NULL;
  StateHeader header = { .size = sizeof (milan->state) };

  memcpy (header.magic, STATE_MAGIC, sizeof (header.magic));
  g_byte_array_append (contents, (const guint8 *) &header, sizeof (header));
  g_byte_array_append (contents, (const guint8 *) &milan->state,
                       sizeof (milan->state));

  if (!g_file_set_contents_full (path, (const gchar *) contents->data,
                                 contents->len,
                                 G_FILE_SET_CONTENTS_CONSISTENT, 0600, &error))
    fp_warn ("Failed to save matcher state: %s", error->message);
}

/* Crop the border and transpose: result is 62 rows of 78 columns */
#define SRC_ROWS    GOODIX53XD_IMG_WIDTH
#define SRC_COLUMNS GOODIX53XD_IMG_HEIGHT

static void
crop_transpose (const double *frame, double *out)
{
  for (gsize r = 0; r < SRC_ROWS; r++)
    for (gsize c = 0; c < SRC_COLUMNS; c++)
      out[r * SRC_COLUMNS + c] =
        frame[(c + GOODIX53XD_BORDER) * GOODIX53XD_FRAME_WIDTH +
              r + GOODIX53XD_BORDER];
}

/* Bilinear resampling with the corner pixels mapped onto each other */
static void
resample (const double *in, guint16 *out)
{
  for (gsize r = 0; r < MILAN_ROWS; r++)
    {
      double y = (double) r * (SRC_ROWS - 1) / (MILAN_ROWS - 1);
      gsize y0 = MIN ((gsize) y, SRC_ROWS - 2);
      double fy = y - y0;

      for (gsize c = 0; c < MILAN_COLUMNS; c++)
        {
          double x = (double) c * (SRC_COLUMNS - 1) / (MILAN_COLUMNS - 1);
          gsize x0 = MIN ((gsize) x, SRC_COLUMNS - 2);
          double fx = x - x0;
          const double *p = in + y0 * SRC_COLUMNS + x0;
          double v = (1 - fy) * ((1 - fx) * p[0] + fx * p[1]) +
                     fy * ((1 - fx) * p[SRC_COLUMNS] + fx * p[SRC_COLUMNS + 1]);

          out[r * MILAN_COLUMNS + c] = (guint16) CLAMP (v + 0.5, 0, 4095);
        }
    }
}

void
goodix53xd_milan_set_frames (Goodix53xdMilan *milan, const guint16 *finger,
                             const guint16 *calibration)
{
  const gsize w = GOODIX53XD_FRAME_WIDTH, h = GOODIX53XD_FRAME_HEIGHT;
  g_autofree double *plane = g_new (double, w * h);
  g_autofree double *cropped = g_new (double, SRC_ROWS * SRC_COLUMNS);

  for (gsize i = 0; i < w * h; i++)
    plane[i] = finger[i];
  crop_transpose (plane, cropped);
  resample (cropped, milan->live);

  /* Setup: flat level plus the high-passed calibration pattern */
  for (gsize y = 0; y < h; y++)
    for (gsize x = 0; x < w; x++)
      {
        double sum = 0;
        int n = 0;

        for (int dy = -FPN_RADIUS; dy <= FPN_RADIUS; dy++)
          for (int dx = -FPN_RADIUS; dx <= FPN_RADIUS; dx++)
            {
              gssize sx = CLAMP ((gssize) x + dx, 0, (gssize) w - 1);
              gssize sy = CLAMP ((gssize) y + dy, 0, (gssize) h - 1);

              sum += calibration[sy * w + sx];
              n++;
            }
        plane[y * w + x] = SETUP_LEVEL +
                           FPN_SCALE * (calibration[y * w + x] - sum / n);
      }
  crop_transpose (plane, cropped);
  resample (cropped, milan->setup);
}

GoodixMilanRuntimeOutput *
goodix53xd_milan_run (Goodix53xdMilan *milan,
                      GoodixMilanPreprocessPurpose purpose,
                      GPtrArray *templates)
{
  g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (
    (GDestroyNotify) goodix_milan_runtime_gallery_input_free);
  GoodixMilanRuntimeInput *input;
  GoodixMilanRuntimeOutput *output;

  for (guint i = 0; templates && i < templates->len; i++)
    g_ptr_array_add (gallery, goodix_milan_runtime_gallery_input_new (
                       i, g_ptr_array_index (templates, i)));

  input = goodix_milan_runtime_input_new (
    ++milan->epoch, 1, purpose, &milan->state, &milan->profile,
    milan->setup, milan->live, MILAN_TCODE, MILAN_DAC_HIGH, MILAN_DAC_LOW,
    GOODIX_MILAN_PRINT_SENSOR_TYPE,
    gallery->len ? (GoodixMilanRuntimeGalleryInput *const *) gallery->pdata : NULL,
    gallery->len);
  output = goodix_milan_runtime_run (input);
  goodix_milan_runtime_input_free (input);

  /* Milan evolves its gain maps from sample to sample */
  if (output->preprocess_state_valid)
    {
      milan->state = output->preprocess_state;
      milan->profile = output->profile_state;
    }
  else if (output->setup_state_valid)
    {
      /* Setup was saved before Milan stopped; keep only its flags */
      milan->profile.setup_initialized = output->profile_state.setup_initialized;
      milan->profile.setup_refresh_pending = output->profile_state.setup_refresh_pending;
      milan->profile.setup_not_ready = output->profile_state.setup_not_ready;
    }

  fp_dbg ("Milan %s: status %d score %d quality %d coverage %d records %u",
          purpose == GOODIX_MILAN_PURPOSE_ENROLL ? "enroll" : "identify",
          output->status, output->score, output->quality, output->coverage,
          output->probe_record_count);

  return output;
}
