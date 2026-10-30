# Hardware finger detection (FDT) experiments for Goodix 27c6:532d. Never
# flashes: aborts unless firmware and PSK already match.
# The session setup is adapted from run_driver() in goodix-fp-dump's
# driver_53xd.py, Copyright (c) 2022 Goodix Fingerprint Linux Development,
# MIT license (see LICENSES/MIT-goodix-fp-dump.txt).
#
# usage: python probe_fdt_532d.py <goodix-fp-dump checkout> <log file>
#
# Reads the FDT areas, derives thresholds from the empty sensor, then runs
# three touch/lift cycles with finger-down and finger-up events.
#
# FDT mode blocks are [op, 0x01, 4x u16 DAC, 8x u16 threshold, reply flag].
# Ops (from the 53x5 driver): 0x0d manual read, 0x0c arm finger down,
# 0x0e arm finger up; bit 7 set means TX off.
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, sys.argv[1])

import usb

import goodix
import tool
import driver_53xd as d

LOG = open(sys.argv[2], "w")

CMD_FDT_DOWN, CMD_FDT_UP, CMD_FDT_MODE = 0x32, 0x34, 0x36
DAC = struct.pack("<4H", 0x128, 0x122, 0x128, 0x124)
DEFAULT_BASE = bytes.fromhex("91918b8b969691919898909092928888")


def log(text):
    print(text)
    LOG.write(text + "\n")
    LOG.flush()


def flat_base(value):
    return bytes([value, value]) * 8


def words(data):
    return [int.from_bytes(data[i:i + 2], "little")
            for i in range(0, len(data) - 1, 2)]


def show(tag, reply, elapsed=None):
    when = f" after {elapsed:.2f}s" if elapsed is not None else ""
    if reply is None:
        log(f"{tag:40s} no reply{when}")
    else:
        log(f"{tag:40s} {reply.hex()}{when}  u16={words(reply)}")


def read_msg(cmd, timeout):
    """Next message for @cmd, or None on timeout. Logs anything else."""
    end = time.monotonic() + timeout
    while True:
        left = end - time.monotonic()
        if left <= 0:
            return None
        try:
            raw = device.protocol.read(timeout=left)
        except usb.core.USBTimeoutError:
            return None
        message = goodix.check_message_pack(raw)
        try:
            payload, command = goodix.decode_message_protocol(message)[:2]
        except ValueError:
            payload, command = goodix.decode_message_protocol(message, False)[:2]
        if command == cmd:
            return payload
        log(f"    (unexpected message 0x{command:02x}: {payload.hex()})")


def wait_any(timeout):
    """First message within @timeout as (cmd, payload, seconds), or None."""
    start = time.monotonic()
    try:
        raw = device.protocol.read(timeout=timeout)
    except usb.core.USBTimeoutError:
        return None
    message = goodix.check_message_pack(raw)
    try:
        payload, command = goodix.decode_message_protocol(message)[:2]
    except ValueError:
        payload, command = goodix.decode_message_protocol(message, False)[:2]
    return command, payload, time.monotonic() - start


def show_any(tag, event):
    if event is None:
        log(f"{tag:40s} nothing")
    else:
        command, payload, elapsed = event
        log(f"{tag:40s} cmd 0x{command:02x} after {elapsed:.2f}s: {payload.hex()}"
            f"  u16={words(payload)}")


def fdt(cmd, op, base, reply, timeout=2.0):
    payload = bytes([op, 0x01]) + DAC + base + bytes([reply])
    device.protocol.write(goodix.encode_message_pack(
        goodix.encode_message_protocol(payload, cmd)))
    goodix.check_ack(goodix.check_message_protocol(
        goodix.check_message_pack(device.protocol.read()),
        goodix.COMMAND_ACK), cmd)
    if not reply or not timeout:
        return None, None
    start = time.monotonic()
    result = read_msg(cmd, timeout)
    return result, time.monotonic() - start


def arm(cmd, op, base):
    # Like goodix-fp-dump: the flag-0 send clears the pending interrupt
    # status, the flag-1 send requests the event message.
    fdt(cmd, op, base, 0)
    fdt(cmd, op, base, 1, 0)


def disarm():
    # Switching back to a manual read cancels a pending down/up wait
    result, _ = fdt(CMD_FDT_MODE, 0x0d, DEFAULT_BASE, 1)
    show("    disarm (manual read)", result)


def prompt(text):
    input(f"\n>>> {text}, then press Enter... ")
    log(f"\n=== {text}")


def derived_base(reply):
    # 53x5 formula: every threshold byte is the reading halved
    return b"".join(bytes([w >> 1 & 0xff, w >> 1 & 0xff]) for w in words(reply[4:20]))


def manual_reads(label):
    last = None
    for name, base in (("zero", flat_base(0)), ("default", DEFAULT_BASE),
                       ("0xff", flat_base(0xff))):
        result, _ = fdt(CMD_FDT_MODE, 0x0d, base, 1)
        show(f"{label} manual tx-on base={name}", result)
        last = result or last
    result, _ = fdt(CMD_FDT_MODE, 0x8d, DEFAULT_BASE, 1)
    show(f"{label} manual tx-off base=default", result)
    return last


# The first command after the sensor has been idle loses its ACK, so wake it
# with a NOP, give it time, drain, and retry on the same connection.
device = d.init_device(0x532d)
for attempt in range(3):
    time.sleep(0.5)
    device.empty_buffer()
    try:
        firmware = device.firmware_version()
        psk_ok = d.check_psk(device)
        break
    except (ValueError, usb.core.USBTimeoutError) as error:
        print(f"setup attempt {attempt + 1} failed ({error}), retrying")
else:
    sys.exit("Device setup failed three times")
if firmware != d.TARGET_FIRMWARE or not psk_ok:
    sys.exit("Refusing to run: firmware / PSK not as expected")

tls_server = subprocess.Popen(
    ["openssl", "s_server", "-nocert", "-psk", d.PSK.hex(), "-port", "4433",
     "-quiet"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    time.sleep(0.3)
    device.reset(True, False, 20)
    device.read_sensor_register(0x0000, 4)
    device.read_otp()
    tls_client = socket.socket()
    tls_client.connect(("localhost", 4433))
    try:
        tool.connect_device(device, tls_client)
        device.upload_config_mcu(d.DEVICE_CONFIG)
        fdt(CMD_FDT_MODE, 0x0d, flat_base(0), 0)
        result, _ = fdt(CMD_FDT_MODE, 0x0d, flat_base(0), 1)
        show("idle mode reply (as the driver sends it)", result)

        prompt("Keep the sensor EMPTY")
        reading = manual_reads("empty")
        empty_base = derived_base(reading)
        log(f"empty base {empty_base.hex()}")

        # Arm right away, in case a pending interrupt makes it fire at once
        arm(CMD_FDT_DOWN, 0x0c, empty_base)
        event = wait_any(3)
        show_any("first down arm, empty, 3 s", event)
        if event is not None:
            arm(CMD_FDT_DOWN, 0x0c, empty_base)
            show_any("re-armed down, empty, 3 s", wait_any(3))

        for cycle in range(3):
            log(f"\n--- cycle {cycle + 1}")
            print("\n>>> TOUCH the sensor now and keep the finger on (10 s)")
            event = wait_any(10)
            show_any("down event", event)
            if event is None:
                disarm()
                break
            finger = event[1]
            reading = manual_reads("finger")
            up_name = "empty" if cycle == 1 else "finger"
            up_base = empty_base if cycle == 1 else derived_base(finger)
            log(f"up base ({up_name}) {up_base.hex()}")
            arm(CMD_FDT_UP, 0x0e, up_base)
            show_any(f"up base={up_name}, finger on, 2 s", wait_any(2))
            print(">>> LIFT your finger now (10 s)")
            event = wait_any(10)
            show_any(f"up base={up_name} event", event)
            if event is None:
                disarm()
            time.sleep(1)
            manual_reads("lifted")
            arm(CMD_FDT_DOWN, 0x0c, empty_base)
            show_any("re-armed down, empty, 3 s", wait_any(3))
    finally:
        tls_client.close()
finally:
    tls_server.terminate()
    tls_server.wait()
log("\nDone.")
