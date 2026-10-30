# Convert Goodix 532d captures into synthetic 88x108 Milan input frames.
# usage: python milan_frames.py <captures-dir> <out-dir> <scale|pad> [level]
import glob
import os
import sys

import numpy as np
from PIL import Image
from scipy import ndimage

ROWS, COLS = 88, 108
FPN_SCALE = 0.98


def load_pgm16(path):
    with open(path, "rb") as f:
        parts = f.read().split(maxsplit=4)
    w, h = int(parts[1]), int(parts[2])
    return np.frombuffer(parts[4][:w * h * 2], ">u2").reshape(h, w).astype(float)


def to_milan(a, mode, fill):
    a = a[1:-1, 1:-1].T                     # 62 x 78, landscape like Milan
    if mode == "scale":
        return ndimage.zoom(a, (ROWS / a.shape[0], COLS / a.shape[1]), order=1)
    out = np.full((ROWS, COLS), fill, float)
    y, x = (ROWS - a.shape[0]) // 2, (COLS - a.shape[1]) // 2
    out[y:y + a.shape[0], x:x + a.shape[1]] = a
    return out


def save(a, path):
    np.clip(np.round(a), 0, 4095).astype("<u2").tofile(path)


def main(root, out, mode, level=3800.0):
    level = float(level)
    calibs = sorted(glob.glob(os.path.join(root, "*", "*-calibration-raw.pgm")))
    calib = np.mean([load_pgm16(p) for p in calibs], axis=0)
    fpn = calib - ndimage.uniform_filter(calib, 9, mode="nearest")

    os.makedirs(out, exist_ok=True)
    setup = to_milan(level + FPN_SCALE * fpn, mode, level)
    save(setup, os.path.join(out, "setup.bin"))

    for d in ("genuine", "impostor"):
        os.makedirs(os.path.join(out, d), exist_ok=True)
        for p in sorted(glob.glob(os.path.join(root, d, "*-finger-raw.pgm"))):
            live = to_milan(load_pgm16(p), mode, 4095)
            name = os.path.basename(p).replace("-finger-raw.pgm", ".bin")
            save(live, os.path.join(out, d, name))

    diff = setup - to_milan(load_pgm16(p), mode, 4095)
    print(f"{mode}: setup mean {setup.mean():.0f}, example setup-live "
          f"p10/p50/p90 {np.percentile(diff, [10, 50, 90]).round()}")


if __name__ == "__main__":
    main(*sys.argv[1:])
