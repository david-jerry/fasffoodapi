#!/usr/bin/env python

import subprocess

def run_uvicorn():
    uvicorn_command = [
        "uvicorn",
        "config.asgi:application",
        "--host", "0.0.0.0",
        "--reload",
        "--reload-include", "'*.html'",
    ]

    try:
        subprocess.run(uvicorn_command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running uvicorn: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    run_uvicorn()
