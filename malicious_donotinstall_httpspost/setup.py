#!/usr/bin/env python3

import os.path
from setuptools import setup

setup(
    name='malicious_donotinstall_httpspost',
    version='0.0.3',
    packages=['malicious_donotinstall_httpspost'],
    install_requires=['requests>=2.28.1'],
    author='Ben Wiederhake',
    author_email='BenWiederhake.GitHub@gmx.de',
    description='Malicious package (HTTPS post), do not install',
    long_description='Malicious package (HTTPS post), do not install',
    long_description_content_type='text/markdown',
    platforms='Any',
    license='MIT',
    keywords='malicious donotinstall',
    url='https://github.com/invalid/nonexistent',
    classifiers=[
        'License :: OSI Approved :: The Unlicense (Unlicense)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
)
