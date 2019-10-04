#!/usr/bin/env python3

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
    if len(sys.argv) != 3:
        print('Usage: {} <input_apk> <output_dex>'.format(__file__))
        return

    _, input_apk, output_dex = sys.argv

    with open(input_apk, 'rb') as f:
        apk_data = bytearray(f.read())

    pos = apk_data.find(b'\x50\x4b\x03\x04')

    output_data = apk_data[:pos]

    update_checksum(output_data)

    with open(output_dex, 'wb') as f:
        f.write(output_data)


if __name__ == '__main__':
    main()
