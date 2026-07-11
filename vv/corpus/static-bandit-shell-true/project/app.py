import subprocess


def run_command(command: str) -> None:
    subprocess.run(command, shell=True, check=True)
