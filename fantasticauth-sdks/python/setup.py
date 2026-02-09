"""
Vault Auth Python SDK
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vault-auth",
    version="1.0.0",
    author="Vault Team",
    author_email="support@vault.dev",
    description="Official Python SDK for Vault authentication and user management",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vault/auth-sdk-python",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "cryptography>=3.4.0",
    ],
    extras_require={
        "flask": ["Flask>=2.0.0"],
        "django": ["Django>=3.2"],
        "fastapi": ["fastapi>=0.95.0", "starlette>=0.20.0"],
        "drf": ["djangorestframework>=3.12"],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "responses>=0.23.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
        ],
    },
    entry_points={
        "console_scripts": [],
    },
)
