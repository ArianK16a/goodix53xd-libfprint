# Capture test for Goodix 27c6:532d. Never flashes: aborts unless firmware and PSK
# already match. Skips finger detection (FDT) and captures on Enter instead, sweeping
# the DAC/offset values that the original script got wrong for the finger frame.
# The session setup is adapted from run_driver() in goodix-fp-dump's
# driver_53xd.py, Copyright (c) 2022 Goodix Fingerprint Linux Development,
# MIT license (see LICENSES/MIT-goodix-fp-dump.txt). Pass the path to a
# goodix-fp-dump checkout as the first argument.
import os
import select
import time
import socket
import struct
import subprocess
import sys

sys.path.insert(0, sys.argv[1])
os.chdir(sys.argv[2])

import goodix
import tool
import driver_53xd as d

# (label, register 0x022c value, 16-bit DAC values) -- 0x128 is what the clear frames used
SWEEP = [
    ("r0a_dac128", b"\x0a\x03", (0x128, 0x122, 0x128, 0x124)),
    ("r0a_dac140", b"\x0a\x03", (0x140, 0x13a, 0x140, 0x13c)),
    ("r0a_dac160", b"\x0a\x03", (0x160, 0x15a, 0x160, 0x15c)),
    ("r0a_dac110", b"\x0a\x03", (0x110, 0x10a, 0x110, 0x10c)),
    ("r05_dac128", b"\x05\x03", (0x128, 0x122, 0x128, 0x124)),
    ("r05_dac0a5", b"\x05\x03", (0x0a5, 0x09f, 0x0a5, 0x0a1)),
]

FDT_IDLE = (b"\x0d\x01\x28\x01\x22\x01\x28\x01\x24\x01" + b"\x00" * 16)


def read_exact(stream, size, timeout):
    fd, data, end = stream.fileno(), b"", time.monotonic() + timeout
    while len(data) < size:
        left = end - time.monotonic()
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            break
        chunk = os.read(fd, size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def capture(device, tls_server, tls_client, reg, dac, flag, name):
    payload = bytes([flag, 0x03]) + struct.pack("<4H", *dac)
    device.write_sensor_register(0x022c, reg)
    tls_client.sendall(
        device.mcu_get_image(
            payload, goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])
    data = read_exact(tls_server.stdout, 7684, 5)
    if len(data) < 7684:
        raise TimeoutError(f"{name}: got only {len(data)}/7684 decrypted bytes")
    image = tool.decode_image(data[:-4])
    device.write_sensor_register(0x022c, reg[:1] + b"\x02")
    tool.write_pgm(image, d.SENSOR_WIDTH, d.SENSOR_HEIGHT, f"{name}.pgm")


device = d.init_device(0x532d)
firmware = device.firmware_version()
if firmware != d.TARGET_FIRMWARE or not d.check_psk(device):
    sys.exit(f"Refusing to run: firmware {firmware!r} / PSK not as expected")


def session(phase, flag):
    tls_server = subprocess.Popen(
        ["openssl", "s_server", "-nocert", "-psk", d.PSK.hex(), "-port",
         "4433", "-quiet"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        time.sleep(0.3)  # let s_server start listening
        if not device.reset(True, False, 20)[0]:
            raise ValueError("Reset failed")
        device.read_sensor_register(0x0000, 4)
        device.read_otp()

        tls_client = socket.socket()
        tls_client.connect(("localhost", 4433))
        try:
            tool.connect_device(device, tls_client)
            if not device.upload_config_mcu(d.DEVICE_CONFIG):
                raise ValueError("Failed to upload config")
            device.mcu_switch_to_fdt_mode(FDT_IDLE + b"\x00", False)
            device.mcu_switch_to_fdt_mode(FDT_IDLE + b"\x01", True)
            for label, reg, dac in SWEEP:
                try:
                    capture(device, tls_server, tls_client, reg, dac, flag,
                            f"{phase}_{label}")
                except TimeoutError as error:
                    print(f"!!! {error} -- skipping rest of this phase")
                    return
        finally:
            tls_client.close()
    finally:
        tls_server.terminate()
        tls_server.wait()


for phase, flag in (("empty", 0x01), ("finger", 0x41)):
    msg = ("Make sure NOTHING touches the sensor" if phase == "empty"
           else "Put your finger flat on the power button and KEEP it there")
    input(f"\n>>> {msg}, then press Enter... ")
    session(phase, flag)
    print(f">>> {phase} captures done")
print("\nAll done, you can lift your finger.")
