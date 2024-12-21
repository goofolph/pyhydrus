"""
This module contains the main class for the hydrus API.
"""

import json
from typing import List, Optional
from urllib.parse import quote
from enum import Enum, IntEnum
from pydantic import BaseModel, Field
from rich import print
from curl_cffi import requests


class HydrusApiVersion(BaseModel):
    """
    The type definition of get api version response
    """

    version: int
    hydrus_version: int


class HydrusRequestNewPermission(BaseModel):
    """
    The type definition of new permission request
    """

    access_key: str


class HydrusSessionKey(BaseModel):
    """
    The type definition of session key response
    """

    session_key: str


class HydrusBasicPermission(IntEnum):
    """
    The type definition of basic permissions

    https://hydrusnetwork.github.io/hydrus/developer_api.html#request_new_permissions
    """

    import_and_edit_urls = 0
    import_and_delete_files = 1
    edit_file_tags = 2
    search_for_and_fetch_files = 3
    manage_pages = 4
    manage_cookies_and_headers = 5
    manage_database = 6
    edit_file_notes = 7
    edit_file_relationships = 8
    edit_file_ratings = 9
    manage_popups = 10
    edit_file_times = 11
    commit_pending = 12
    see_local_paths = 13


class HydrusVerifyAccessKey(BaseModel):
    """
    The type definition of verify access key response
    """

    name: str
    permits_everything: bool
    basic_permissions: List[HydrusBasicPermission]
    human_description: str


class HydrusServiceType(IntEnum):
    """
    The type definition of service types

    https://hydrusnetwork.github.io/hydrus/developer_api.html#services_object
    """

    tag_repository = 0
    file_repository = 1
    local_file_domain = 2
    local_tag_domain = 5
    numerical_rating_service = 6
    like_rating_service = 7
    all_known_tags = 10
    all_known_files = 11
    the_local_booru = 12
    IPFS = 13
    trash = 14
    all_local_files = 15
    file_notes = 17
    Client_API = 18
    deleted_from_anywhere = 19
    local_updates = 20
    all_my_files = 21
    inc_dec_rating_service = 22
    server_administration = 99


class HydrusService(BaseModel):
    """
    The type definition of service
    """

    name: str
    service_key: str
    service_type: HydrusServiceType = Field(alias="type")
    type_pretty: str


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
        self._api_key = apikey
        self._session_key = None
        self._base_url = url
        if not self._base_url or len(self._base_url.strip()) == 0:
            self._base_url = "http://127.0.0.1:45869"

        self._session = requests.Session(impersonate="chrome")

    def __get__(self, url, params=None, headers=None) -> requests.Response:
        """
        Make a request to the Hydrus client using specified keys, parameters, and headers.

        :param url: The URL to API endpoint.
        :param params: Parameters to be sent in the request URL.
        :param headers: Headers for the request.
        """

        if not headers:
            if self._session_key:
                headers = {"Hydrus-Client-API-Session-Key": self._session_key}
            if self._api_key:
                headers = {"Hydrus-Client-API-Access-Key": self._api_key}
        else:
            if self._session_key:
                headers["Hydrus-Client-API-Session-Key"] = self._session_key
            if self._api_key:
                headers["Hydrus-Client-API-Access-Key"] = self._api_key

        if params:
            for key, value in params.items():
                if isinstance(value, str):
                    params[key] = quote(value)
                else:
                    params[key] = quote(json.dumps(value))

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
        resp = self.__get__(url)
        version = _HydrusApiVersion(**resp.json())
        return f"{version.hydrus_version}.{version.version}"

    def get_request_new_permissions(
        self, name: str, permits_everything: bool, basic_permissions: List[int]
    ) -> str:
        """
        Request new API key with specified permissions.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#request_new_permissions

        :param name: The descriptive name of your access.
        :param permits_everything: Whether to permit all tasks now and in future.
        :param basic_permissions: A list of numerical permission identifiers you want to request.
        :return: The new API for requested permissions
        """

        url = f"{self._base_url}/request_new_permissions"

        arguments = {"name": name}
        if permits_everything:
            arguments["permits_everything"] = True
        if basic_permissions:
            # arguments["basic_permissions"] = quote(json.dumps(basic_permissions))
            arguments["basic_permissions"] = basic_permissions

        resp = self.__get__(url, params=arguments)
        return _HydrusRequestNewPermission(**resp.json()).access_key

    def get_session_key(self) -> str:
        """
        Get the session key for hydrus.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#session_key

        :return: The session key string for hydrus.
        """

        url = f"{self._base_url}/session_key"
        resp = self.__get__(url)
        self._session_key = _HydrusSessionKey(**resp.json()).session_key
        return self._session_key

    def get_verify_access_key(self) -> _HydrusVerifyAccessKey:
        """
        Verify the access key name and permissions.

        :return: The verify access key response
        """

        url = f"{self._base_url}/verify_access_key"
        resp = self.__get__(url)
        return _HydrusVerifyAccessKey(**resp.json())

    def get_service(
        self,
        name: Optional[str] = None,
        key: Optional[str] = None,
    ) -> HydrusService:
        """
        Ask the client about a specific service.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#get_service

        :param name: Name of the service
        :param key: hxe string key of the service

        """

        assert name is None or isinstance(name, str)
        assert key is None or isinstance(key, str)
        assert name is not None and key is None or name is None and key is not None

        if name:
            params = {"service_name": name}
        if key:
            params = {"service_key": key}

        url = f"{self._base_url}/get_service"
        resp = self.__get__(url, params=params)
        return HydrusService(**resp.json()["service"])
