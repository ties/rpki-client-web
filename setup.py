""" Set up script """
import os

from setuptools import find_packages, setup

here = os.path.abspath(os.path.dirname(__file__))


with open(os.path.join(here, "README.md"), "rb") as f:
    long_descr = f.read().decode("utf-8")


setup(
    name="rpkiclientweb",
    version="0.2.1",
    author="Ties de Kock",
    author_email="ties@tiesdekock.nl",
    description="A web api for RPKI-client",
    long_description_content_type="text/markdown",
    long_description=long_descr,
    url="https://github.com/ties/rpki-client-web",
    entry_points={"console_scripts": ["rpki-client-web = rpkiclientweb.__main__:main"]},
    install_requires=["aiohttp", "pyyaml", "prometheus-async"],
    include_package_data=True,
    python_requires=">=3.8",
    license="MIT",
    keywords="rpki rpki-client validator",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: Software Development :: Libraries",
        "License :: OSI Approved :: MIT License",
    ],
)
