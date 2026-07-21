import requests


def main():
    response = requests.get("https://example.com", timeout=5)
    print(response.status_code)


if __name__ == "__main__":
    main()
