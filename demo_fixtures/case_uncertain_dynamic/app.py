import importlib
import sys


def run(module_name, func_name, data):
    mod = importlib.import_module(module_name)  # dynamic import
    return getattr(mod, func_name)(data)        # dynamic getattr


if __name__ == "__main__":
    print(run(sys.argv[1], sys.argv[2], sys.argv[3]))
