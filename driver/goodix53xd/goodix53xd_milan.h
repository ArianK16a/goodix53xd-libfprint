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

#pragma once

#include <glib.h>

#include "milan/runtime.h"

/* Matcher state that persists for as long as the device is open */
typedef struct
{
  GoodixMilanPreprocessState state;
  GoodixMilanProfileState    profile;
  guint64                    epoch;
  guint16                    setup[GOODIX_MILAN_SENSOR_PIXELS];
  guint16                    live[GOODIX_MILAN_SENSOR_PIXELS];
} Goodix53xdMilan;

Goodix53xdMilan *goodix53xd_milan_new (void);
void             goodix53xd_milan_free (Goodix53xdMilan *milan);

/* Milan adapts its gain maps with every sample and only matches reliably
 * with maps that have seen the finger, so they are kept across sessions. */
void             goodix53xd_milan_load_state (Goodix53xdMilan *milan,
                                              const char      *path);
void             goodix53xd_milan_save_state (Goodix53xdMilan *milan,
                                              const char      *path);

/* Convert a sensor frame and the session calibration frame into Milan's
 * sensor geometry. Must be called before each run. */
void             goodix53xd_milan_set_frames (Goodix53xdMilan *milan,
                                              const guint16   *finger,
                                              const guint16   *calibration);

/* Runs one Milan operation on the frames last set. @templates may be NULL
 * for enrollment. The returned output belongs to the caller. */
GoodixMilanRuntimeOutput *goodix53xd_milan_run (Goodix53xdMilan             *milan,
                                                GoodixMilanPreprocessPurpose purpose,
                                                GPtrArray                   *templates);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (Goodix53xdMilan, goodix53xd_milan_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (GoodixMilanRuntimeOutput,
                               goodix_milan_runtime_output_free)
