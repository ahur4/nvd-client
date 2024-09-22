from setuptools import setup, find_packages

long_description = open('README.md', 'r').read()

setup(
    name="nvd-client",
    version="0.1.3.1",
    description="A Python client for interacting with the National Vulnerability Database (NVD) API to fetch CVE data.",
    author="Ahur4",
    author_email="ahur4.rahmani@gmail.com",
    url="https://github.com/ahur4/nvd-client",
    packages=find_packages(include=['nvd_client', 'nvd_client.*']),
    install_requires=[
        "certifi==2024.6.2",
        "charset-normalizer==3.3.2",
        "idna==3.7",
        "requests[socks]==2.32.3",
        "urllib3==2.2.1"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    keywords=[
        "vulnerability", "nvd", "national vulnerability database", "nvd_client", "nvd_client-api",
        "ahur4", "ahura rahmani", "redteam", "soc", "vulnerability assessment", "penetration testing"
    ],
    long_description=long_description,
    long_description_content_type='text/markdown',
)
