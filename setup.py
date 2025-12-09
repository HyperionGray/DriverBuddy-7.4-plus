#!/usr/bin/env python3
"""
DriverBuddy Setup Script

    ☠ ☠ ☠ INSTALLATION SETUP ☠ ☠ ☠

Setup script for installing DriverBuddy as a Python package.
"""

from setuptools import setup, find_packages
import os

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read version from __init__.py
def get_version():
    with open("DriverBuddy/__init__.py", "r") as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split('"')[1]
    return "2.0.0"

setup(
    name="driverbuddy",
    version=get_version(),
    author="NCC Group (Original), Modernized",
    author_email="",
    description="☠ Modern Multi-Platform Windows Driver Analysis Tool ☠",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nccgroup/driverbuddy",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        # Core dependencies
    ],
    extras_require={
        "radare2": ["r2pipe"],
        "dev": ["pytest", "black", "flake8"],
    },
    entry_points={
        "console_scripts": [
            "driverbuddy=DriverBuddy:main",
        ],
    },
    include_package_data=True,
    package_data={
        "DriverBuddy": ["*.py"],
        "scripts": ["*.py"],
        "examples": ["*.py"],
    },
    keywords="reverse-engineering, windows, drivers, security, ida, ghidra, binary-ninja, radare2",
    project_urls={
        "Bug Reports": "https://github.com/nccgroup/driverbuddy/issues",
        "Source": "https://github.com/nccgroup/driverbuddy",
        "Documentation": "https://github.com/nccgroup/driverbuddy/blob/main/README.md",
    },
)