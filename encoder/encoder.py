import os
import base64
import cryptography.fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import List, Set, Tuple, Union

FilesToEncodeType = Union[List[str], Set[str], Tuple[str]]


class FileManager:
    @staticmethod
    def read_file(file_name, mode: str = 'rb') -> bytes:
        try:
            with open(file_name, mode=mode) as file:
                file_data = file.read()
            return file_data
        except FileNotFoundError:
            raise FileNotFoundError(f"File wasn't found by: {os.path.abspath(file_name)}")

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
        master_key_path: str,
        files_to_encode: FilesToEncodeType,
        use_salt: bool = True
    ):
        if not isinstance(files_to_encode, (list, set, tuple)):
            raise TypeError("files_to_encode must be a list, set, or tuple of strings")

        self.files_to_encode = files_to_encode
        _master_key = self._initialize_master_key(master_key_path)

        if use_salt:
            _salt = self._initialize_salt()

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=_salt,
                iterations=480000,
            )
        else:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'',
                iterations=480000,
            )

        key = base64.urlsafe_b64encode(kdf.derive(_master_key))
        self._fernet = Fernet(key)

    @staticmethod
    def _initialize_master_key(master_key_path: str):
        if not (master_key := FileManager.read_file(master_key_path)):
            return bytes(input("Enter a secret key to encode files: "), 'utf-8')
        else:
            return master_key

    @staticmethod
    def _initialize_salt():
        try:
            salt = FileManager.read_file('salt')
        except FileNotFoundError:
            salt: bytes = os.urandom(16)
        else:
            if not salt:
                salt = os.urandom(16)

        FileManager.write_file(mode='wb', file_name='salt', data=salt)
        return salt

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
