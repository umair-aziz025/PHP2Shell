"""
PHP2Shell Research Toolkit — Package Setup
"""

from pathlib import Path
from setuptools import setup, find_packages

HERE = Path(__file__).resolve().parent

setup(
    name="php2shell-scanner",
    version="2.2.1",
    description=(
        "Full-pipeline PHP vulnerability assessment & exploitation suite for "
        "CVE-2026-109618 and CVE-2026-109619."
    ),
    long_description=(HERE / "README.md").read_text(encoding="utf-8")
    if (HERE / "README.md").exists()
    else "",
    long_description_content_type="text/markdown",
    author="PHP2Shell Research Team",
    license="MIT",
    python_requires=">=3.9",
    packages=find_packages(),
    py_modules=["php2shell"],
    install_requires=[
        "requests>=2.28.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "php2shell=php2shell:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    keywords="php security scanner vulnerability cve defensive",
)
