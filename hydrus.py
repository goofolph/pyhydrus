"""
This module contains the main class for the hydrus API.
"""

import json
from typing import List
from urllib.parse import quote
from pydantic import BaseModel
from rich import print
from curl_cffi import requests


class _HydrusApiVersion(BaseModel):
    """
    The type definition of get api version response
    """

    version: int
    hydrus_version: int


class _HydrusRequestNewPermission(BaseModel):
    """
    The type definition of new permission request
    """

    access_key: str


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
        self._sessionkey = None
        self._base_url = url
        if not self._base_url or len(self._base_url.strip()) == 0:
            self._base_url = "http://127.0.0.1:45869"

        self._session = requests.Session(impersonate="chrome")

    def _get(self, url, params=None, headers=None) -> requests.Response:
        """
        Make a request to the Hydrus client using specified keys, parameters, and headers.

        :param url: The URL to API endpoint.
        :param params: Parameters to be sent in the request URL.
        :param headers: Headers for the request.
        """

        if not headers:
            if self._sessionkey:
                headers = {"Hydrus-Client-API-Session-Key": self._sessionkey}
            if self._apikey:
                headers = {"Hydrus-Client-API-Access-Key": self._apikey}
        else:
            if self._sessionkey:
                headers["Hydrus-Client-API-Session-Key"] = self._sessionkey
            if self._apikey:
                headers["Hydrus-Client-API-Access-Key"] = self._apikey

        resp = self._session.get(url, params=params, headers=headers)
        resp.raise_for_status()
        return resp

    def get_version(self) -> str:
        """
        Get the version of hydrus.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#api_version

        :return: The version string for hydrus.
        """

        url = f"{self._base_url}/api_version"
        resp = self._get(url)
        version = _HydrusApiVersion(**resp.json())
        return f"{version.hydrus_version}.{version.version}"

