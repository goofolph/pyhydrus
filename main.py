"""
This is the main entrypoint for the module.
"""

import sys
from rich import print
import yaml
from hydrus import Hydrus


def main():
    """
    Main function, called when not imported
    """
    with open("config.yml", mode="r", encoding="utf8") as f:
        try:
            config = yaml.safe_load(f)
            print("config:", config)
            url = config["url"]
            api_key = config["api_key"]
        except yaml.YAMLError as e:
            print(e)
            sys.exit(1)

    hydrus = Hydrus(url, api_key)

    print(hydrus)


if __name__ == "__main__":
    main()
