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

templates_folder = 'templates'


def random_string(length=10):
    dictionary = string.ascii_lowercase
    return ''.join(random.choice(dictionary) for i in range(length))


def load_template(file):
    with open(os.path.join(templates_folder, file)) as f:
        return f.read()


def generate_file(output_folder, name, tag, template, authority=False):
    folder = os.path.join(output_folder, '/'.join(name.split('.')[:-1]))
    class_name = name.split('.')[-1]

    out = tag % ('.'.join(name.split('.')[:-1]), class_name)

    try:
        os.makedirs(folder)
    except FileExistsError:
        pass

    with open(os.path.join(folder, class_name + '.java'), 'w') as f:
        f.write(out)

    if authority:
        return template % (name, random_string(3) + '.' + random_string(5))

    return template % name


def main():
    # Check arguments
    if len(sys.argv) != 3:
        print('Usage: {} <manifest_xml> <output_dir>'.format(__file__))
        exit(1)

    # Load arguments
    _, manifest, output = sys.argv

    # Load templates
    application_template = load_template('application')
    provider_template = load_template('provider')
    service_template = load_template('service')
    receiver_template = load_template('receiver')

    # Initialize tags
    manifest_tags = ''
    application_tag = '<application android:name="%s">\n'
    provider_tag = '\t<provider android:name="%s" android:authorities="%s"/>\n'
    service_tag = '\t<service android:name="%s"/>\n'
    receiver_tag = '\t<receiver android:name="%s"/>\n'

    # Load XML
    root = ET.parse(manifest).getroot()

    # Parse application
    application_name = root.find('application').get('{http://schemas.android.com/apk/res/android}name')
    manifest_tags += generate_file(output, application_name, application_tag, application_template)

    # Parse providers
    for x in root.findall('application/provider'):
        name = x.get('{http://schemas.android.com/apk/res/android}name')
        manifest_tags += generate_file(output, name, provider_tag, provider_template, authority=True)
        print('Found provider: {}'.format(name))

    for x in root.findall('application/service'):
        name = x.get('{http://schemas.android.com/apk/res/android}name')
        manifest_tags += generate_file(output, name, service_tag, service_template)
        print('Found service: {}'.format(name))

    for x in root.findall('application/receiver'):
        name = x.get('{http://schemas.android.com/apk/res/android}name')
        manifest_tags += generate_file(output, name, receiver_tag, receiver_template)
        print('Found receiver: {}'.format(name))

    with open(os.path.join(output, 'manifest.xml'), 'w') as f:
        manifest_tags += '</application>'
        f.write(manifest_tags)

    print('Created necessary dummy classes in "{}".'.format(output))
    print('Exported necessary manifest tags in "{}/manifest.xml".'.format(output))


if __name__ == '__main__':
    main()
