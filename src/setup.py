import setuptools

with open("../README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ddos_dissector",
    version="0.0.1",
    author="Jair Santanna",
    author_email="jairsantanna@gmail.com",
    description="Package to enable dissection of DDoS attacks from various network capture formats",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jjsantanna/ddosdb",
    packages=setuptools.find_packages(),
    install_requires=["pandas","numpy","dpkt","matplotlib","requests"],
    classifiers=[
        "Programming Language :: Python :: 3",
        # "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    scripts=["ddos_dissector_cli.py"]
)