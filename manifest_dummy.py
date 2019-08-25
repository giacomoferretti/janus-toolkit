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

import xml.etree.ElementTree as ET
import sys
import os
import string
import random


def random_string(length=10):
    dictionary = string.ascii_lowercase
    return ''.join(random.choice(dictionary) for i in range(length))


def main():
    # Check arguments
    if len(sys.argv) != 3:
        print('Usage: {} <manifest_xml> <output_dir>'.format(__file__))
        exit(1)

    # Load arguments
    _, manifest, output = sys.argv

    # Load templates
    with open(os.path.join('templates', 'application_template')) as f:
        application_template = f.read()

    with open(os.path.join('templates', 'provider_template')) as f:
        provider_template = f.read()

    with open(os.path.join('templates', 'service_template')) as f:
        service_template = f.read()

    manifest_tags = ''
    application_tag = 'application android:name="%s">\n'
    provider_tag = '<provider android:name="%s" android:authorities="%s"/>\n'
    service_tag = '<service android:name="%s"/>\n'

    # Load XML
    root = ET.parse(manifest).getroot()

    # Parse application
    manifest_tags += application_tag % (
        root.find('application').get('{http://schemas.android.com/apk/res/android}name'))

    # Parse providers
    for providers in root.findall('application/provider'):
        name = providers.get('{http://schemas.android.com/apk/res/android}name')

        folder = os.path.join(output, '/'.join(name.split('.')[:-1]))
        class_name = name.split('.')[-1]

        manifest_tags += provider_tag % (name, random_string(3) + '.' + random_string(5))

        out = provider_template % ('.'.join(name.split('.')[:-1]), class_name)

        try:
            os.makedirs(folder)
        except:
            pass

        with open(os.path.join(folder, class_name + '.java'), 'w') as f:
            f.write(out)

        print('Found provider: {}'.format(name))

    for providers in root.findall('application/service'):
        name = providers.get('{http://schemas.android.com/apk/res/android}name')

        folder = os.path.join(output, '/'.join(name.split('.')[:-1]))
        class_name = name.split('.')[-1]

        out = service_template % ('.'.join(name.split('.')[:-1]), class_name)

        manifest_tags += service_tag % name

        try:
            os.makedirs(folder)
        except:
            pass

        with open(os.path.join(folder, class_name + '.java'), 'w') as f:
            f.write(out)

        print('Found service: {}'.format(name))

    with open(os.path.join(output, 'manifest.xml'), 'w') as f:
        f.write(manifest_tags)

    print('Created necessary dummy classes in "{}".'.format(output))
    print('Exported necessary manifest tags in "{}/manifest.xml".'.format(output))


if __name__ == '__main__':
    main()
