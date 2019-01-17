import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="msticpy",
    version="0.0.413",
    author="Ian Hellen",
    author_email="ianhelle@microsoft.com",
    description="MSTIC Security Tools",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://https://github.com/ianhelle/msyticpy",
    packages=setuptools.find_packages(exclude=['notebookext', 'notebooks', 'miscnotebooks']),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)