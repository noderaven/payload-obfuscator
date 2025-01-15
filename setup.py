"""
Setup configuration for payload_obfuscator package.
"""

from setuptools import setup, find_packages

setup(
    name="payload_obfuscator",
    version="1.0.0",
    description="Windows PE binary obfuscation tool for OSEP exam preparation",
    author="rileymxyz",
    author_email="noderaven@proton.me",
    packages=find_packages(),
    install_requires=[
        "pefile>=2023.2.7",
        "rich>=13.3.1",
        "loguru>=0.7.0",
        "pycryptodomex>=3.19.0",
        "psutil>=5.9.5",
        "wmi>=1.5.1",
        "netifaces>=0.11.0"
    ],
    entry_points={
        "console_scripts": [
            "payload-obfuscator=src.obfuscator:main"
        ]
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: Education"
    ]
) 