import sys
import yaml


def load_config(text):
    return yaml.load(text)  # no Loader: unsafe default in PyYAML < 5.1


def main(text):
    return load_config(text)


if __name__ == "__main__":
    print(main(sys.argv[1] if len(sys.argv) > 1 else "a: 1"))
