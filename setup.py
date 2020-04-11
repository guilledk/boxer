#!/usr/bin/env python3

from setuptools import setup, find_packages


setup(
    name="boxer",
    packages=find_packages(),
    version="0.1.0",
    description="UDP Hole punching server for BOXER protocol.",
    install_requires=[
        "trio",
        "pynacl",
        "aplutils"
    ]
)
