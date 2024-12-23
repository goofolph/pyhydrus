"""
This module contains the main class for the hydrus API.
"""

import json
import os
from enum import Enum, IntEnum
from typing import List, Optional
from urllib.parse import quote

from curl_cffi import requests
from pydantic import BaseModel, Field


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


class HydrusServiceStarShape(str, Enum):
    circle = "circle"
    square = "square"
    fat = "fat star"
    pentagram = "pentagram star"


class HydrusService(BaseModel):
    """
    The type definition of service
    """

    name: str
    service_key: str
    service_type: HydrusServiceType = Field(alias="type")
    type_pretty: str
    star_shape: Optional[HydrusServiceStarShape] = None
    min_stars: Optional[int] = None
    max_stars: Optional[int] = None


class HydrusServices(BaseModel):
    """
    The type definition of the services object

    https://hydrusnetwork.github.io/hydrus/developer_api.html#services_object
    """

    local_tags: List[HydrusService]
    tag_repositories: List[HydrusService]
    local_files: List[HydrusService]
    local_updates: List[HydrusService]
    file_repositories: List[HydrusService]
    all_local_files: List[HydrusService]
    all_local_media: List[HydrusService]
    all_known_files: List[HydrusService]
    all_known_tags: List[HydrusService]
    trash: List[HydrusService]
    services: dict


class HydrusAddFileStatus(IntEnum):
    successfully_imported = 1
    already_in_databarse = 2
    previously_deleted = 3
    failed_import = 4
    vetoed = 7


class HydrusAddFileResponse(BaseModel):
    """
    The type definition for the add_file response
    """

    status: HydrusAddFileStatus
    filehash: str = Field(alias="hash")
    note: str


class Hydrus:
    """
    The main class for the hydrus API.
    """

    def __init__(
        self, url: str = "http://127.0.0.1:45869", apikey: Optional[str] = None
    ) -> None:
        """
        Construct a new Hydrus object

        :param url: The base URL for the hydrus API including protocol and port number, ex. http://127.0.0.1:45869.
        :param apikey: The API key to use with the hydrus API.
        :return: returns nothing
        """
        self.__api_key__ = apikey
        self.__session_key__ = None
        self.__verify_access_key__ = None
        self.base_url = url
        if not self.base_url or len(self.base_url.strip()) == 0:
            self.base_url = "http://127.0.0.1:45869"

        self.__session__ = requests.Session(impersonate="chrome")

    def __get__(self, url, headers=None, params=None) -> requests.Response:
        """
        Make a request to the Hydrus client using available keys, parameters, and headers.

        :param url: The URL to API endpoint.
        :param headers: Headers for the request.
        :param params: Parameters to be sent in the request URL.
        """

        if headers is None:
            headers = {}
        if self.__session_key__:
            headers["Hydrus-Client-API-Session-Key"] = self.__session_key__
        elif self.__api_key__:
            headers["Hydrus-Client-API-Access-Key"] = self.__api_key__
        if "Accept" not in headers:
            headers["Accept"] = "application/json"

        if params:
            for key, value in params.items():
                if isinstance(value, str):
                    params[key] = quote(value)
                else:
                    params[key] = quote(json.dumps(value))

        resp = self.__session__.get(url, params=params, headers=headers)
        resp.raise_for_status()
        return resp

    def __post__(
        self, url, headers=None, params=None, data=None, json=None
    ) -> requests.Response:
        """
        Make a post request to the Hydrus client using available keys, parameters, and headers.

        :param url: The URL to API endpoint
        :param headers: Headers for the request
        :param params: Parameters to be sent in the request URL
        :param data: Data to be send in POST body
        :param json: JSON data to be send in POST body
        """

        if headers is None:
            headers = {}
        if self.__session_key__:
            headers["Hydrus-Client-API-Session-Key"] = self.__session_key__
        elif self.__api_key__:
            headers["Hydrus-Client-API-Access-Key"] = self.__api_key__
        if "Accept" not in headers:
            headers["Accept"] = "application/json"

        if params:
            for key, value in params.items():
                if isinstance(value, str):
                    params[key] = quote(value)
                else:
                    params[key] = quote(json.dumps(value))

        resp = self.__session__.post(
            url, headers=headers, params=params, data=data, json=json
        )
        resp.raise_for_status()
        return resp

    def get_version(self) -> str:
        """
        Get the version of hydrus.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#api_version

        :return: The version string for hydrus.
        """

        url = f"{self.base_url}/api_version"
        resp = self.__get__(url)
        version = HydrusApiVersion(**resp.json())
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

        url = f"{self.base_url}/request_new_permissions"

        arguments = {"name": name}
        if permits_everything:
            arguments["permits_everything"] = True
        if basic_permissions:
            # arguments["basic_permissions"] = quote(json.dumps(basic_permissions))
            arguments["basic_permissions"] = basic_permissions

        resp = self.__get__(url, params=arguments)
        return HydrusRequestNewPermission(**resp.json()).access_key

    def get_session_key(self) -> str:
        """
        Get the session key for hydrus.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#session_key

        :return: The session key string for hydrus.
        """

        url = f"{self.base_url}/session_key"
        resp = self.__get__(url)
        self.__session_key__ = HydrusSessionKey(**resp.json()).session_key
        return self.__session_key__

    def get_verify_access_key(self) -> HydrusVerifyAccessKey:
        """
        Verify the access key name and permissions.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#verify_access_key

        :return: The verify access key response
        """

        url = f"{self.base_url}/verify_access_key"
        resp = self.__get__(url)
        self.__verify_access_key__ = HydrusVerifyAccessKey(**resp.json())
        return self.__verify_access_key__

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

        :return: HydrusService
        """

        assert name is None or isinstance(name, str)
        assert key is None or isinstance(key, str)
        assert (
            name is not None and key is None or name is None and key is not None
        )

        if self.__verify_access_key__ is None:
            self.get_verify_access_key()
        assert self.__verify_access_key__.permits_everything or any(
            map(
                lambda e: e in self.__verify_access_key__.basic_permissions,
                [
                    HydrusBasicPermission.import_and_delete_files,
                    HydrusBasicPermission.edit_file_tags,
                    HydrusBasicPermission.manage_pages,
                    HydrusBasicPermission.search_for_and_fetch_files,
                ],
            )
        )

        if name:
            params = {"service_name": name}
        if key:
            params = {"service_key": key}

        url = f"{self.base_url}/get_service"
        resp = self.__get__(url, params=params)
        return HydrusService(**resp.json()["service"])

    def get_services(self) -> List[HydrusService]:
        """
        Ask the client about its services.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#get_services

        :return: HydrusServices
        """

        if self.__verify_access_key__ is None:
            self.get_verify_access_key()
        assert self.__verify_access_key__.permits_everything or any(
            map(
                lambda e: e in self.__verify_access_key__.basic_permissions,
                [
                    HydrusBasicPermission.import_and_delete_files,
                    HydrusBasicPermission.edit_file_tags,
                    HydrusBasicPermission.manage_pages,
                    HydrusBasicPermission.search_for_and_fetch_files,
                ],
            )
        )

        url = f"{self.base_url}/get_services"
        all_services = []
        all_service_keys = []
        resp = self.__get__(url)
        services = resp.json()

        for key in [
            key
            for key in services.keys()
            if key not in ["services", "version", "hydrus_version"]
        ]:
            for serv in services[key]:
                if serv["service_key"] not in all_service_keys:
                    all_service_keys.append(serv["service_key"])
                    all_services.append(HydrusService(**serv))

        # Need to parse these differently, service_key isn't inside the object but is the key. Can contain duplicates and contains the rating services not included elsewhere
        for key, value in services["services"].items():
            value["service_key"] = key
            if key not in all_service_keys:
                all_service_keys.append(key)
                all_services.append(HydrusService(**value))

        return all_services

    def add_file(
        self,
        filepath: str,
        asStream: bool = False,
        delete: bool = False,
        file_domain_key: str = None,
    ) -> HydrusAddFileResponse:
        """
        Tell the client to import a file.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#add_files_add_file

        :param filepath: path to the file
        :param asStream: send image as data stream, otherwise send path to Hydrus client
        :param delete: Tells the client to delete the file after import. Only works when sending file path not stream
        :param file_domain_key: Tells the client which file domain to import to, not available when sending as stream

        :return: HydrusAddFileResponse
        """

        assert isinstance(filepath, str)
        assert len(filepath.strip()) > 0
        assert os.path.exists(filepath)
        assert isinstance(asStream, bool)
        if file_domain_key is not None:
            assert isinstance(file_domain_key, str)
            assert len(file_domain_key.strip()) > 0

        if self.__verify_access_key__ is None:
            self.get_verify_access_key()
        assert self.__verify_access_key__.permits_everything or any(
            map(
                lambda e: e in self.__verify_access_key__.basic_permissions,
                [HydrusBasicPermission.import_and_delete_files],
            )
        )

        url = f"{self.base_url}/add_files/add_file"
        filepath = os.path.abspath(filepath)
        if asStream:
            headers = {"Content-Type": "application/octet-stream"}
            with open(filepath, "rb") as f:
                resp = self.__post__(url, headers=headers, data=f.read())
        else:
            headers = {"Content-Type": "application/json"}
            data = {"path": filepath}
            if delete:
                data["delete_after_successful_import"] = delete
            if file_domain_key is not None:
                data["file_service_key"] = file_domain_key
            resp = self.__post__(url, headers=headers, json=data)

        return HydrusAddFileResponse(**resp.json())

    def delete_files(
        self,
        file_id: Optional[int] = None,
        file_ids: Optional[List[int]] = None,
        file_hash: Optional[str] = None,
        file_hashes: Optional[List[str]] = None,
        file_domain_key: Optional[str] = None,
        file_domain_keys: Optional[List[str]] = None,
        reason: Optional[str] = None,
    ):
        """
        Tell the client to send files to the trash.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#add_files_delete_files

        :param file_id: id of file to be deleted
        :param file_ids: ids of files to be deleted
        :param file_hash: SHA256 of file to be deleted
        :param file_hashes: SHA256s of files to be deleted
        :param file_domain_key: file domain service key from which the file(s) are to be deleted
        :param reason: reason to be attached to delete operation
        """

        if file_id is not None:
            assert isinstance(file_id, int)
        if file_ids is not None:
            assert isinstance(file_ids, list)
            for i in file_ids:
                assert isinstance(i, int)
        if file_hash is not None:
            assert isinstance(file_hash, str)
        if file_hashes is not None:
            assert isinstance(file_hashes, list)
            for h in file_hashes:
                assert isinstance(h, str)
        if file_domain_key is not None:
            assert isinstance(file_domain_key, str)
        if file_domain_keys is not None:
            assert isinstance(file_domain_keys, list)
            for k in file_domain_key:
                assert isinstance(k, str)
        if reason is not None:
            assert isinstance(reason, str)

        if self.__verify_access_key__ is None:
            self.get_verify_access_key()
        assert self.__verify_access_key__.permits_everything or any(
            map(
                lambda e: e in self.__verify_access_key__.basic_permissions,
                [HydrusBasicPermission.import_and_delete_files],
            )
        )

        data = {}
        if file_id:
            data["file_id"] = file_id
        if file_ids:
            data["file_ids"] = file_ids
        if file_hash:
            data["hash"] = file_hash
        if file_hashes:
            data["hashes"] = file_hashes
        if file_domain_key:
            data["file_service_key"] = file_domain_key
        if reason:
            data["reason"] = reason

        url = f"{self.base_url}/add_files/delete_files"
        self.__post__(url, json=data)

    def undelete_files(
        self,
        file_id: Optional[int] = None,
        file_ids: Optional[List[int]] = None,
        file_hash: Optional[str] = None,
        file_hashes: Optional[List[str]] = None,
        file_domain_key: Optional[str] = None,
        file_domain_keys: Optional[List[str]] = None,
    ):
        """
        Tell the client to remove files to the trash.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#add_files_undelete_files

        :param file_id: id of file to be undeleted
        :param file_ids: ids of files to be undeleted
        :param file_hash: SHA256 of file to be undeleted
        :param file_hashes: SHA256s of files to be undeleted
        :param file_domain_key: file domain service key from which the file(s) are to be undeleted
        """

        if file_id is not None:
            assert isinstance(file_id, int)
        if file_ids is not None:
            assert isinstance(file_ids, list)
            for i in file_ids:
                assert isinstance(i, int)
        if file_hash is not None:
            assert isinstance(file_hash, str)
        if file_hashes is not None:
            assert isinstance(file_hashes, list)
            for h in file_hashes:
                assert isinstance(h, str)
        if file_domain_key is not None:
            assert isinstance(file_domain_key, str)
        if file_domain_keys is not None:
            assert isinstance(file_domain_keys, list)
            for k in file_domain_key:
                assert isinstance(k, str)

        if self.__verify_access_key__ is None:
            self.get_verify_access_key()
        assert self.__verify_access_key__.permits_everything or any(
            map(
                lambda e: e in self.__verify_access_key__.basic_permissions,
                [HydrusBasicPermission.import_and_delete_files],
            )
        )

        data = {}
        if file_id:
            data["file_id"] = file_id
        if file_ids:
            data["file_ids"] = file_ids
        if file_hash:
            data["hash"] = file_hash
        if file_hashes:
            data["hashes"] = file_hashes
        if file_domain_key:
            data["file_service_key"] = file_domain_key

        url = f"{self.base_url}/add_files/undelete_files"
        self.__post__(url, json=data)

    def clear_file_deletion_record(
        self,
        file_id: Optional[int] = None,
        file_ids: Optional[List[int]] = None,
        file_hash: Optional[str] = None,
        file_hashes: Optional[List[str]] = None,
    ):
        """
        Tell the client to forget that it once deleted files.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#add_files_clear_file_deletion_record

        :param file_id: The file id for which record to be deleted
        :param file_ids: The file ids for which records to be deleted
        :param file_hash: The file hash for which record to be deleted
        :param file_hashes: The file hashes for which records to be deleted
        """

        if file_id is not None:
            assert isinstance(file_id, int)
        if file_ids is not None:
            assert isinstance(file_ids, list)
            for i in file_ids:
                assert isinstance(i, int)
        if file_hash is not None:
            assert isinstance(file_hash, str)
        if file_hashes is not None:
            assert isinstance(file_hashes, list)
            for h in file_hashes:
                assert isinstance(h, str)

        if self.__verify_access_key__ is None:
            self.get_verify_access_key()
        assert self.__verify_access_key__.permits_everything or any(
            map(
                lambda e: e in self.__verify_access_key__.basic_permissions,
                [HydrusBasicPermission.import_and_delete_files],
            )
        )

        data = {}
        if file_id:
            data["file_id"] = file_id
        if file_ids:
            data["file_ids"] = file_ids
        if file_hash:
            data["hash"] = file_hash
        if file_hashes:
            data["hashes"] = file_hashes

        url = f"{self.base_url}/add_files/clear_file_deletion_record"
        self.__post__(url, json=data)

    def migrate_files(
        self,
        file_id: Optional[int] = None,
        file_ids: Optional[List[int]] = None,
        file_hash: Optional[str] = None,
        file_hashes: Optional[List[str]] = None,
        file_domain_key: Optional[str] = None,
        file_domain_keys: Optional[List[str]] = None,
    ):
        """
        Copy files from one local file domain to another.

        https://hydrusnetwork.github.io/hydrus/developer_api.html#add_files_migrate_files

        :param file_id: id of file to be migrated
        :param file_ids: ids of files to be migrated
        :param file_hash: SHA256 of file to be migrated
        :param file_hashes: SHA256s of files to be migrated
        :param file_domain_key: file domain service key from which the file(s) are to be migrated to
        """

        if file_id is not None:
            assert isinstance(file_id, int)
        if file_ids is not None:
            assert isinstance(file_ids, list)
            for i in file_ids:
                assert isinstance(i, int)
        if file_hash is not None:
            assert isinstance(file_hash, str)
        if file_hashes is not None:
            assert isinstance(file_hashes, list)
            for h in file_hashes:
                assert isinstance(h, str)
        if file_domain_key is not None:
            assert isinstance(file_domain_key, str)
        if file_domain_keys is not None:
            assert isinstance(file_domain_keys, list)
            for k in file_domain_key:
                assert isinstance(k, str)

        data = {}
        if file_id:
            data["file_id"] = file_id
        if file_ids:
            data["file_ids"] = file_ids
        if file_hash:
            data["hash"] = file_hash
        if file_hashes:
            data["hashes"] = file_hashes
        if file_domain_key:
            data["file_service_key"] = file_domain_key

        url = f"{self.base_url}/add_files/migrate_files"
        self.__post__(url, json=data)
