from setuptools import setup


setup(
    name="webvulnscan",
    version="0.2.0",
    description="Defensive Nmap-based web vulnerability scanning CLI",
    py_modules=["analisis_vulnerabilidades"],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "webvulnscan=analisis_vulnerabilidades:main",
        ],
    },
)
