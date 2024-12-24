"""
This is the test entrypoint for the module.
"""

import hashlib
import os
import sys
import unittest

import numpy
import yaml
from curl_cffi.requests.exceptions import HTTPError
from PIL import Image
from rich import print

import hydrus


def generate_random_image(
    filepath: str = "image.jpg", width: int = 20, height: int = 20
) -> str:
    """
    Generates a random image of noise. Used to avoid image hash checksums when imported into Hydrus during testing.

    https://stackoverflow.com/questions/10901049/create-set-of-random-jpgs
    """

    filepath = os.path.abspath(filepath)
    a = numpy.random.rand(width, height, 3) * 255
    im_out = Image.fromarray(a.astype("uint8")).convert("RGB")
    im_out.save(filepath)
    return filepath


def get_sha256(filepath: str):
    """
    Generates the SHA256 checksum of a file.

    :param filepath: path to file to be hashed

    :return: sha256 hash in hex
    """

    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        sha256.update(f.read())
    return sha256.hexdigest()


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
        except HTTPError:
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
        self.assertTrue(
            isinstance(service.service_type, hydrus.HydrusServiceType)
        )
        self.assertTrue(isinstance(service.type_pretty, str))

    def test_get_services(self):
        """
        Test getting services
        """

        services = self.hydrus.get_services()
        self.assertNotEqual(services, None)
        self.assertTrue(isinstance(services, list))
        self.assertTrue(isinstance(services[0], hydrus.HydrusService))

    def test_add_file_path(self):
        """
        Test adding file by file path
        """

        image_path = generate_random_image("image.jpg")
        image_hash = get_sha256(image_path)

        added = self.hydrus.add_file(image_path)
        self.assertTrue(
            added.status
            in [
                hydrus.HydrusAddFileStatus.successfully_imported,
                hydrus.HydrusAddFileStatus.already_in_databarse,
            ]
        )
        self.assertEqual(added.filehash, image_hash)
        self.hydrus.delete_files(file_hash=image_hash)

    def test_add_file_stream(self):
        """
        Test adding file by byte stream
        """

        image_path = generate_random_image("image.jpg")
        image_hash = get_sha256(image_path)

        added = self.hydrus.add_file(image_path, asStream=True)
        self.assertTrue(
            added.status
            in [
                hydrus.HydrusAddFileStatus.successfully_imported,
                hydrus.HydrusAddFileStatus.already_in_databarse,
            ]
        )
        self.assertEqual(added.filehash, image_hash)
        self.hydrus.delete_files(file_hash=image_hash)

    def test_delete_files(self):
        """
        Test deleting files
        """

        image_path = generate_random_image("image.jpg")
        image_hash = get_sha256(image_path)

        self.hydrus.add_file(image_path)

        self.hydrus.delete_files(file_hash=image_hash)

    def test_undelete_files(self):
        """
        Test undeleting files
        """

        image_path = generate_random_image("image.jpg")
        image_hash = get_sha256(image_path)

        self.hydrus.add_file(image_path)

        self.hydrus.delete_files(file_hash=image_hash)
        self.hydrus.undelete_files(file_hash=image_hash)
        self.hydrus.delete_files(file_hash=image_hash)

    def test_clear_file_deletion_record(self):
        """
        Test clearing file deletion record
        """

        image_path = generate_random_image("image.jpg")
        image_hash = get_sha256(image_path)

        added = self.hydrus.add_file(image_path)
        self.assertEqual(
            added.status,
            hydrus.HydrusAddFileStatus.successfully_imported,
        )

        self.hydrus.delete_files(file_hash=image_hash)
        added = self.hydrus.add_file(image_path)
        self.assertEqual(
            added.status,
            hydrus.HydrusAddFileStatus.previously_deleted,
        )

        self.hydrus.delete_files(
            file_hash=image_hash,
            file_domain_key="616c6c206c6f63616c2066696c6573",
        )
        self.hydrus.clear_file_deletion_record(file_hash=image_hash)
        added = self.hydrus.add_file(image_path)
        self.assertEqual(
            added.status,
            hydrus.HydrusAddFileStatus.successfully_imported,
        )
        self.hydrus.delete_files(file_hash=image_hash)

    def test_migrate_files(self):
        # TODO add testing after another local file domain can be added
        pass

    def test_achive_files(self):
        image_path = generate_random_image("image.jpg")
        image_hash = get_sha256(image_path)
        self.hydrus.add_file(image_path, asStream=True)
        self.hydrus.archive_files(file_hash=image_hash)
        # TODO add search here to verify
        self.hydrus.delete_files(file_hash=image_hash)
