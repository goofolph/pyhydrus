"""
This module contains the main class for the hydrus API.
"""

import json
from pydantic import BaseModel
from rich import print
from curl_cffi import requests


class Hydrus:
    """
    The main class for the hydrus API.
    """

    def __init__(self, url: str = "http://127.0.0.1:45869", apikey: str = "") -> None:
        """
        Construct a new Hydrus object

        :param url: The base URL for the hydrus API including protocol and port number, ex. http://127.0.0.1:45869.
        :param apikey: The API key to use with the hydrus API.
        :return: returns nothing
        """
        self._apikey = apikey
        self._base_url = url
        if not self._base_url or len(self._base_url.strip()) == 0:
            self._base_url = 'http://127.0.0.1:45869'

        self._session = requests.Session(impersonate="chrome")

        print("Initiated Hydrus API at", self._base_url,
              "with api key", self._apikey)

    def get_version(self) -> str:
        """
        Get the version of hydrus.

        :return: The version string for hydrus.
        """

        url = f"{self._base_url}/api_version"
        resp = self._session.get(url)
        resp.raise_for_status()
        j = resp.json()
        return f"{j['hydrus_version']}.{j['version']}"
