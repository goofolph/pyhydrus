"""
This is the test entrypoint for the module.
"""

import sys
import unittest
import yaml
from hydrus import Hydrus


class TestHydrusMethods(unittest.TestCase):
    """
    Test the methods of the Hydrus class
    """

    def setUp(self):
        """
        Setup Hydrus class and import config options
        """
        with open("config.yml", mode="r", encoding="utf8") as f:
            try:
                config = yaml.safe_load(f)
                url = config["url"]
                api_key = config["api_key"]
            except yaml.YAMLError as e:
                print(e)
                sys.exit(1)

        self.hydrus = Hydrus(url, api_key)

    def test_version(self):
        """
        Test the version method of Hydrus class
        """
        version = self.hydrus.get_version()
        self.assertEqual(type(version), str)
        self.assertGreaterEqual(version, "599.75")

    def test_request_new_permissions(self):
        """
        Test the request new permissions method of Hydrus class
        """

        apikey = self.hydrus.get_request_new_permissions(
            "Testing",
            False,
            [0, 1],
        )
        self.assertGreater(len(apikey), 0)
