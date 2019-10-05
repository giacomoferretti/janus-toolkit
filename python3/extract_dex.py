#!/usr/bin/env python3

# -*- coding: utf-8 -*-

#  Copyright 2019 Giacomo Ferretti
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

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
