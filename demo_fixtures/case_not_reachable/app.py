import json


def main():
    # pyyaml is declared in requirements.txt but never imported or called
    print(json.dumps({"status": "ok"}))


if __name__ == "__main__":
    main()
