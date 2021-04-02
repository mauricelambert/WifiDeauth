from setuptools import setup, find_packages

setup(
    name = 'WifiDeauth',
 
    version = "0.0.2",
    packages = find_packages(include=["WifiDeauth"]),
    install_requires = ['scapy'],

    author = "Maurice Lambert", 
    author_email = "mauricelambert434@gmail.com",
 
    description = "This package implement a Dos attack on Wifi named Deauth.",
    long_description = open('README.md').read(),
    long_description_content_type="text/markdown",
 
    include_package_data = True,

    url = 'https://github.com/mauricelambert/WifiDeauth',
 
    classifiers = [
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.9",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
        "Topic :: Security",
    ],
 
    entry_points = {
        'console_scripts': [
            'WifiDeauth = WifiDeauth:deauth'
        ],
    },
    python_requires='>=3.9',
)