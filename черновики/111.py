import subprocess

try:
    result = subprocess.run(
        ["tshark", "-v"],
        capture_output=True,
        text=True
    )
    print(result.stdout)
except FileNotFoundError:
    print("tshark НЕ найден. Он не установлен или не добавлен в PATH.")