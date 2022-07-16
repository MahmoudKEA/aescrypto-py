from .header import *


def is_supported(path: str) -> bool:
    """Check a file is encrypted by aes crypto"""

    valid = False
    with open(path, 'rb') as file:
        file.read(struct.calcsize('Q'))
        signature = file.read(len(Output.signature))

        if signature == Output.signature:
            valid = True

    return valid


def checksum(path: str, algorithm: typing.Callable = hashlib.sha256) -> str:
    """Get file hash string"""

    algorithm = algorithm()
    with open(path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            algorithm.update(chunk)

    return algorithm.hexdigest()


def get_hash_string(
        text: typing.Union[str, bytes], algorithm: typing.Callable = hashlib.sha256
) -> str:
    """Get hash string"""

    if isinstance(text, str):
        text = text.encode()

    return algorithm(text).hexdigest()


def get_hash_digest(
        text: typing.Union[str, bytes], algorithm: typing.Callable = hashlib.sha256
) -> bytes:
    """Get hash digest"""

    if isinstance(text, str):
        text = text.encode()

    return algorithm(text).digest()


def create_key(key: typing.Union[str, bytes]) -> bytes:
    """Key encapsulation for more security"""

    key_512 = get_hash_string(text=key, algorithm=hashlib.sha512)
    return get_hash_digest(text=key_512, algorithm=hashlib.sha256)


def add_extension(path: str) -> str:
    """Add extension to file path"""

    return '%s.%s' % (path, Output.fileExtension)


def remove_extension(path: str) -> str:
    """Remove extension from file path"""

    return path.rsplit('.', 1)[0]


def add_padding(text: typing.Union[str, bytes]) -> bytes:
    """Add padding to text"""

    if isinstance(text, str):
        text = text.encode()

    size = AES.block_size - len(text) % AES.block_size
    text += chr(size).encode() * size

    return text


def remove_padding(text: bytes) -> bytes:
    """Remove padding of text"""

    char = text[-1:]
    size = ord(char)

    if size <= AES.block_size and text.endswith(char * size):
        original = text[:-size]
        if original[-1:] != char:
            text = original

    # return text[:-ord(text[len(text)-1:])]
    return text


def output_path_handler(path: str, directory: str = None) -> str:
    """Destination path detection and extension handling"""

    if directory:
        os.makedirs(directory, exist_ok=True)
        output_path = os.path.join(directory, os.path.basename(path))
    else:
        output_path = path

    if path.endswith(Output.fileExtension):
        output_path = remove_extension(output_path)
    else:
        output_path = add_extension(output_path)

    return output_path
