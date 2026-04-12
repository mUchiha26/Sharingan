from setuptools import setup, find_packages

setup(
    name="sharingan",
    version="1.0.0",
    author="mUchiha26",
    packages=find_packages(),
    py_modules=["main"],
    install_requires=["requests"],
    entry_points={
        "console_scripts": [
            "sharingan=main:main",
        ],
    },
    python_requires=">=3.10",
)
