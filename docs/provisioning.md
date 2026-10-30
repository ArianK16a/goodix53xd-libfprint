# Provisioning

The sensor only talks to a host that knows its TLS pre-shared key (PSK).
The factory key is set by the Windows driver. With the application firmware
running, the sensor returns only the key's hash: `tools/probe_psk_532d.py`
tried the other record types and all were refused.

Re-provisioning with
[goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump):

- erases the firmware,
- writes the all-zero PSK, and
- flashes `GF5298_GM168SEC_APP_13016`.

This is done once. Afterwards the sensor no longer works with the Windows
driver.

```sh
git clone https://github.com/goodix-fp-linux-dev/goodix-fp-dump.git
cd goodix-fp-dump
git submodule update --init
python3 -m venv venv && venv/bin/pip install pyusb crcmod pycryptodome crccheck

sudo venv/bin/python <this repo>/tools/probe_532d.py "$PWD"   # read-only check
sudo venv/bin/python run_532d.py                               # provision
sudo venv/bin/python <this repo>/tools/probe_532d.py "$PWD"
```

After provisioning, the probe must report `Matches target: True` and
`PSK is known one: True`.

The reader must be enabled in the BIOS to show up on USB.
