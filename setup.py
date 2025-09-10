"""
Setup script for basicsec package
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="basicsec",
    version="1.1.1",
    author="Vlatko Kosturjak",
    author_email="vlatko.kosturjak@marlink.com",
    description="A Python library for basic and mostly passive security scanning like DNS and e-mail",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/marlinkcyber/basicsec",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Communications :: Email",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "dnspython>=2.3.0",
        "email-validator>=2.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "basicsec=basicsec.cli:main",
        ],
    },
    keywords="security dns email spf dmarc dnssec scanner",
    project_urls={
        "Bug Reports": "https://github.com/marlinkcyber/basicsec/issues",
        "Source": "https://github.com/marlinkcyber/basicsec",
        "Documentation": "https://basicsec.readthedocs.io/",
    },
)
