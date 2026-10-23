#!/usr/bin/env python3
"""Cross-platform script runner for dev, test, and lint."""

import os
import socket
import subprocess
import sys


def is_port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0


def load_env(path: str = ".env") -> None:
    """Manually parse .env file to guarantee environment variables are loaded."""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    if k.strip() not in os.environ:
                        os.environ[k.strip()] = v.strip().strip("\"'")


def main():
    load_env()
    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else "dev"
    if cmd == "dev":
        port = int(os.environ.get("PORT", "8000"))
        host = os.environ.get("HOST", "127.0.0.1")
        if is_port_in_use(host, port):
            print(f"\n[!] Error: Port {port} is already in use by another process on {host}.")
            print("    Please close the existing process or set a different port:")
            print(f'    $env:PORT="{port + 1}"; python scripts/run.py\n')
            sys.exit(1)

        subprocess.run(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "auralert.app:app",
                "--host",
                host,
                "--port",
                str(port),
                "--reload",
                "--env-file",
                ".env",
            ],
            check=True,
        )
    elif cmd == "test":
        subprocess.run([sys.executable, "-m", "pytest", "tests", "-v"], check=True)
    elif cmd == "lint":
        print("Running ruff check...")
        subprocess.run([sys.executable, "-m", "ruff", "check", "."], check=True)
        print("Running ruff format check...")
        subprocess.run([sys.executable, "-m", "ruff", "format", "--check", "."], check=True)
    elif cmd == "install":
        subprocess.run([sys.executable, "-m", "pip", "install", "-e", ".[dev]"], check=True)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
