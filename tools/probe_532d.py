# Read-only probe for Goodix 27c6:532d: firmware version and PSK hash. Writes nothing.
# Uses goodix-fp-dump (https://github.com/goodix-fp-linux-dev/goodix-fp-dump);
# pass the path to its checkout as the first argument.
import sys
sys.path.insert(0, sys.argv[1])
import goodix, protocol, driver_53xd as d

dev = goodix.Device(0x532d, protocol.USBProtocol)
dev.nop()
fw = dev.firmware_version()
ok, flags, pmk = dev.preset_psk_read(0xbb020001, len(d.PMK_HASH), 0)
print("\n=== RESULT ===")
print("Firmware:        ", fw)
print("Matches target:  ", fw == d.TARGET_FIRMWARE)
print("PSK read ok:     ", ok, hex(flags) if flags else flags)
print("PMK hash:        ", pmk.hex() if pmk else None)
print("PSK is known one:", pmk == d.PMK_HASH)
