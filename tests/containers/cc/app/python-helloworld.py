import requests

print("Hello world!")

response = requests.get("https://www.microsoft.com/", timeout=5)
response.raise_for_status()
print("Network test successful!")
