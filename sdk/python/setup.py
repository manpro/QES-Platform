#!/usr/bin/env python3
"""
QES Platform Python SDK Setup
"""

from setuptools import setup, find_packages
import os

# Read version from file
def read_version():
    version_file = os.path.join(os.path.dirname(__file__), 'qes_platform', '_version.py')
    with open(version_file, 'r') as f:
        exec(f.read())
    return locals()['__version__']

# Read README for long description
def read_readme():
    readme_file = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_file):
        with open(readme_file, 'r', encoding='utf-8') as f:
            return f.read()
    return "QES Platform Python SDK for qualified electronic signatures"

setup(
    name="qes-platform-sdk",
    version=read_version(),
    description="QES Platform Python SDK for qualified electronic signatures",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="QES Platform Team",
    author_email="support@qes-platform.com",
    url="https://github.com/qes-platform/qes-platform",
    project_urls={
        "Documentation": "https://docs.qes-platform.com/sdk/python",
        "Source": "https://github.com/qes-platform/qes-platform",
        "Tracker": "https://github.com/qes-platform/qes-platform/issues",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Office/Business",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "pydantic>=2.0.0",
        "cryptography>=41.0.0",
        "python-dateutil>=2.8.0",
        "urllib3>=1.26.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "sphinx-autodoc-typehints>=1.19.0",
        ],
        "async": [
            "aiohttp>=3.8.0",
            "aiofiles>=23.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "qes-cli=qes_platform.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "qes_platform": ["py.typed"],
    },
    keywords=[
        "eidas", "digital-signatures", "qualified-electronic-signatures",
        "qes", "crypto", "signing", "certificates", "pki"
    ],
    zip_safe=False,
)