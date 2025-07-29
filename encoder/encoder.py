import os
import base64
import cryptography.fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import List, Set, Tuple, Union
import secrets

FilesToEncodeType = Union[List[str], Set[str], Tuple[str]]


class FileManager:
    @staticmethod
    def read_file(file_name, mode: str = 'rb') -> bytes:
        if file_name is None:
            raise RuntimeError("File wasn't found: path is None")
        try:
            with open(file_name, mode=mode) as file:
                file_data = file.read()
            return file_data
        except FileNotFoundError:
            raise RuntimeError(f"File wasn't found by: {os.path.abspath(file_name)}")

    @staticmethod
    def delete_file(file_name: str):
        if os.path.isfile(file_name):
            os.remove(file_name)
        else:
            raise FileNotFoundError(file_name)

    @staticmethod
    def write_file(file_name: str, data: bytes | str, mode=None):
        if isinstance(data, str):
            mode = mode or 'w'
        else:
            mode = mode or 'wb'
        with open(file_name, mode) as f:
            f.write(data)


class Contracts:
    @staticmethod
    def retrieve_master_key(master_key_path):
        try:
            master_key = FileManager.read_file(master_key_path)
        except Exception:
            master_key = bytes(input("Enter a secret key to encode/decode files: "), 'utf-8')
        return master_key

    @staticmethod
    def retrieve_files_to_encode(files_to_encode):
        if not isinstance(files_to_encode, (list, set, tuple)):
            raise TypeError("files_to_encode must be a list, set, or tuple of strings")
        return files_to_encode

    @staticmethod
    def initialize_salt(salt_path):
        if salt_path is None or not os.path.exists(salt_path):
            response = input(f"Salt file not found at '{salt_path}'. Generate new one? [y/N]: ").strip().lower()
            if response == "y":
                salt = secrets.token_bytes(16)  # or 32 if your KDF needs it
                with open(salt_path, "wb") as f:
                    f.write(salt)
                print(f"New salt saved to: {salt_path}")
                return salt
            else:
                raise FileNotFoundError("Salt file is required.")
        else:
            with open(salt_path, "rb") as f:
                return f.read()


class FileEncoder:
    """
    A class to encode and decode files using a master key and optional salt.

    Attributes:
    - master_key_path (str): Path to the master key file containing text or binary data. If the file does not exist, it will prompt for a key input.
    - files_to_encode (FilesToEncodeType): A list, set, or tuple of file names to encode or decode.
    - use_salt (bool):
        - If True, it will look for a salt file named 'salt'. If the salt file does not exist, it will generate a new salt with `os.urandom(16)` and save it as 'salt' file.
        - If False, it will use an empty binary string as salt. (Not recommended. Easily breakable)
    """

    def __init__(
        self,
        files_to_encode: FilesToEncodeType,
        use_salt: bool = True,
        master_key_path: str = None,
        salt_path: str = None
    ):

        self.files_to_encode = Contracts.retrieve_files_to_encode(files_to_encode)
        _master_key = Contracts.retrieve_master_key(master_key_path)

        if use_salt:
            _salt = Contracts.initialize_salt(salt_path=salt_path)
        else:
            _salt = b''

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=_salt,
            iterations=480000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(_master_key))
        self._fernet = Fernet(key)

    def encode(self):
        for file_name in self.files_to_encode:
            if os.path.exists(file_name):
                file_data: bytes = FileManager.read_file(file_name)
                encrypted_data: bytes = self._fernet.encrypt(file_data)
                FileManager.write_file(file_name=f"{file_name}.enc", data=encrypted_data)
                FileManager.delete_file(file_name)

    def decode(self):
        for file_name in self.files_to_encode:
            file_name_enc = file_name + ".enc"
            encrypted_data: bytes = FileManager.read_file(file_name_enc)

            try:
                data = self._fernet.decrypt(encrypted_data)
            except cryptography.fernet.InvalidToken:
                raise ValueError("Key does not match or file is corrupted")
            else:
                FileManager.write_file(file_name=file_name, data=data, mode='wb')
                FileManager.delete_file(file_name_enc)
