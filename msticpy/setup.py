# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
"""Setup script for msticpy."""

import setuptools

from ._version import VERSION as __version__

# pylint: disable=locally-disabled, C0103
with open("README.md", "r") as fh:
    long_description = fh.read()
# pylint: enable=locally-disabled, C0103

setuptools.setup(
    name="msticpy",
    version=__version__,
    author="Ian Hellen",
    author_email="ianhelle@microsoft.com",
    description="MSTIC Security Tools",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://https://github.com/ianhelle/msyticpy",
    python_requires='>=3.6',
    packages=setuptools.find_packages(exclude=['notebookext', 'notebooks', 'miscnotebooks']),
    classifiers=[
        "Programming Language :: Python :: 3.6",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    extras_require={"pandas": ["pandas>=0.15.0"]}
)
