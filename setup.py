from setuptools import setup

setup(
    name="SleepProxyServer",
    description="An implementation of a sleep proxy server, "
        "which aims to be compatible with Apple's wake on demand",
    version="0.2",
    author="Dennis Schafroth",
    author_email="dennis@schafroth.com",
    url="https://github.com/schafdog/SleepProxyServer",
    packages=["sleepproxy"],
    scripts=["scripts/sleepproxyd"],
    python_requires=">=3.8",
    install_requires=[
        # "dbus-python",  # Unfortunately not distributed with a setup.py
        "dnspython",
        "dnslib",
        "netifaces",
        "scapy",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
#        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
    ],
)
