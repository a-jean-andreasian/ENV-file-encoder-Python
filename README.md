# File Encryptor for Python

---

## Intro

This script encrypts your files using **Fernet** with a custom `master.key`, and generates new `.enc` versions without
deleting the originals.

* It's useful for encrypting sensitive data like secrets, credentials, configs, or anything you want to commit,
  transfer, or back up securely.
* This allows you to share or store encrypted versions of your files, while preserving local access to the original
  data.

### Bonus:

In my similar project [File Encryptor for Ruby](https://github.com/Armen-Jean-Andreasian/File-Encryptor-for-Ruby), *
*AES-256-CBC** was used. Here, we use **Fernet**.

Yes, `AES-256-CBC` is more powerful and lower-level, but `Fernet` is easier to implement, provides authenticated
encryption (AES-128-CBC + HMAC), and is good enough for most practical use cases.

---

## Important Security Note

If you lose your `master.key` or the `salt` file, **you won't be able to decrypt your `.enc` files**.
Keep both in a safe location. This script is framework-independent and fully isolated.

---

## Usage Example

```python
from encoder import FileEncoder, FilesToEncodeType

if __name__ == "__main__":
    MASTER_KEY_PATH = "master.key"  # path to your key file
    FILES_TO_ENCODE: FilesToEncodeType = (
        "./file1.txt",
        "./config/secrets.json",
    )

    file_encoder = FileEncoder(
        master_key_path=MASTER_KEY_PATH,
        files_to_encode=FILES_TO_ENCODE
    )

    file_encoder.encode()  # produces file1.txt.enc and secrets.json.enc
    file_encoder.decode()  # restores original files from .enc (if deleted)
```

---
