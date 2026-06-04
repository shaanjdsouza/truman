from pathlib import Path

from setuptools import setup


ROOT = Path(__file__).parent


def read_requirements():
    requirements_path = ROOT / "requirements.txt"
    return [
        line.strip()
        for line in requirements_path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


setup(
    name="truman",
    version="0.1.0",
    description="Network scanning and packet tracing CLI toolkit",
    py_modules=["truman", "lan_scanner", "packet_sniffer"],
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "truman=truman:main",
        ],
    },
)
