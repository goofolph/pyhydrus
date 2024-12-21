"""
This is the test entrypoint for the module.
"""

import sys
import unittest
import yaml
from rich import print
from curl_cffi.requests.exceptions import HTTPError
import hydrus


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

        self.hydrus = hydrus.Hydrus(url, api_key)
        self.hydrus.get_session_key()

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

        try:
            apikey = self.hydrus.get_request_new_permissions(
                "Testing",
                False,
                [0, 1],
            )
            self.assertEqual(len(apikey), 64)
        except HTTPError as err:
            print("Warning: Request New Permissions Window Not Open")

    def test_session_key(self):
        """
        Test the session key method of Hydrus class
        """

        sessionkey = self.hydrus.get_session_key()
        self.assertEqual(len(sessionkey), 64)
        self.assertEqual(sessionkey, self.hydrus.__session_key__)

    def test_verify_access_key(self):
        """
        Test verifying the access key
        """

        verify = self.hydrus.get_verify_access_key()
        self.assertEqual(verify.name, "Testing")

    def test_get_service(self):
        """
        Test getting a service
        """

        service = self.hydrus.get_service("my tags")
        self.assertTrue(isinstance(service.name, str))
        self.assertEqual(service.name, "my tags")
        self.assertTrue(isinstance(service.service_type, hydrus.HydrusServiceType))
        self.assertTrue(isinstance(service.type_pretty, str))

    def test_get_services(self):
        """
        Test getting services
        """

        services = self.hydrus.get_services()
        self.assertNotEqual(services, None)
        self.assertTrue(isinstance(services, list))
        self.assertTrue(isinstance(services[0], hydrus.HydrusService))
