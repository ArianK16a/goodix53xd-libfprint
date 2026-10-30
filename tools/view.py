import sys, numpy as np
from PIL import Image
d = sys.argv[1]
def load(p):
    t = open(p).read().split()
    assert t[0] == "P2"
    w, h, mx = int(t[1]), int(t[2]), int(t[3])
    return np.array(t[4:4+w*h], dtype=float).reshape(h, w)
def save(a, p):
    lo, hi = np.percentile(a, 1), np.percentile(a, 99)
    a = np.clip((a - lo) / (hi - lo + 1e-9), 0, 1) * 255
    Image.fromarray(a.astype(np.uint8)).resize((a.shape[1]*6, a.shape[0]*6), Image.NEAREST).save(p)
fp, bg = load(f"{d}/fingerprint.pgm"), load(f"{d}/clear-3.pgm")
print("finger min/max/mean", fp.min(), fp.max(), fp.mean().round(1), " bg", bg.min(), bg.max(), bg.mean().round(1))
save(fp, sys.argv[2] + "/fp_raw.png"); save(bg, sys.argv[2] + "/bg.png"); save(bg - fp, sys.argv[2] + "/fp_minus_bg.png")
