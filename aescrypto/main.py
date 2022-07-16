from .header import *
from . import utility, error


class AESCrypto(object):
    def __init__(self, key: str, mode: int = AES.MODE_CBC):
        self.__key = utility.create_key(key)
        self.__mode = mode
        self.__isKilled = False
        self.__totalProgress = 0
        self.__progressValue = 0

        if not any(mode in modes for modes in (ivModes, nonceModes)):
            raise error.UnsupportedModeError("This mode is not supported")

    def encrypt(
            self, text: typing.Union[str, bytes], add_signature: bool = False, add_key: bool = False
    ) -> bytes:
        """Encrypt plain text to cipher text"""

        cipher, tag = self.__cipher()
        result = b''

        if add_signature:
            result += Output.signature

        if add_key:
            result += utility.create_key(self.__key)

        result += tag
        result += cipher.encrypt(
            utility.add_padding(text)
        )

        return result

    def decrypt(
            self, cipher_text: bytes, check_signature: bool = False, check_key: bool = False
    ) -> bytes:
        """
        Decrypt cipher text to original text
        :exception error.SignatureNotFoundError
        :exception error.WrongKeyError
        """

        if check_signature:
            signature_length = len(Output.signature)
            signature = cipher_text[:signature_length]
            cipher_text = cipher_text[signature_length:]
            if signature != Output.signature:
                raise error.SignatureNotFoundError("Signature not found")

        if check_key:
            key = cipher_text[:keyLength]
            cipher_text = cipher_text[keyLength:]
            if key != utility.create_key(self.__key):
                raise error.WrongKeyError("The key is wrong")

        tag_length = self.__tag_length()
        tag = cipher_text[:tag_length]
        cipher_text = cipher_text[tag_length:]

        cipher, _ = self.__cipher(tag)
        result = cipher.decrypt(cipher_text)

        return utility.remove_padding(result)

    def encrypt_file(
            self, path: str, directory: str = None, add_key: bool = True, ignore_file_exists: bool = False,
            remove_after_complete: bool = False, progress_event: typing.Callable = None
    ) -> typing.Tuple[bool, str]:
        """
        Encrypt a file
        :exception FileExistsError
        """

        output_path = utility.output_path_handler(path=path, directory=directory)

        if not ignore_file_exists and os.path.exists(output_path):
            raise FileExistsError("File already exists")

        with open(path, 'rb') as src_file:
            with open(output_path, 'wb') as output_file:
                completed = self.__encrypt_file(
                    src_file=src_file, output_file=output_file,
                    add_key=add_key, progress_event=progress_event
                )

        if completed and remove_after_complete:
            os.remove(path)

        return completed, output_path

    def decrypt_file(
            self, path: str, directory: str = None, check_key: bool = True, ignore_file_exists: bool = False,
            remove_after_complete: bool = False, progress_event: typing.Callable = None
    ) -> typing.Tuple[bool, str]:
        """
        Decrypt a file
        :exception FileExistsError
        :exception error.SignatureNotFoundError
        :exception error.WrongKeyError
        """

        output_path = utility.output_path_handler(path=path, directory=directory)

        if not ignore_file_exists and os.path.exists(output_path):
            raise FileExistsError("File already exists")

        with open(path, 'rb') as src_file:
            with open(output_path, 'wb') as output_file:
                completed = self.__decrypt_file(
                    src_file=src_file, output_file=output_file,
                    check_key=check_key, progress_event=progress_event
                )

        if completed and remove_after_complete:
            os.remove(path)

        return completed, output_path

    def dump(
            self, data: bytes, path: str, add_key: bool = True, ignore_file_exists: bool = False,
            progress_event: typing.Callable = None
    ) -> typing.Tuple[bool, str]:
        """
        Encrypt data from memory to storage
        :exception FileExistsError
        """

        output_path = utility.output_path_handler(path=path)

        if not ignore_file_exists and os.path.exists(output_path):
            raise FileExistsError("File already exists")

        with io.BytesIO(data) as src_file:
            with open(output_path, 'wb') as output_file:
                completed = self.__encrypt_file(
                    src_file=src_file, output_file=output_file,
                    add_key=add_key, progress_event=progress_event
                )

        return completed, output_path

    def load(
            self, path: str, check_key: bool = True, progress_event: typing.Callable = None
    ) -> typing.Tuple[bool, bytes]:
        """
        Decrypt a file from storage to memory
        :exception error.SignatureNotFoundError
        :exception error.WrongKeyError
        """

        with open(path, 'rb') as src_file:
            with io.BytesIO() as output_file:
                completed = self.__decrypt_file(
                    src_file=src_file, output_file=output_file,
                    check_key=check_key, progress_event=progress_event
                )

                return completed, output_file.getvalue()

    def kill(self):
        """kill current operation"""

        self.__isKilled = True

    def __kill(self, file: typing.BinaryIO):
        self.__isKilled = False
        file.close()

        try:
            os.remove(file.name)
        except AttributeError:
            pass

    def __progress_update(self, size: int, chunk_size: int, progress_event: typing.Callable):
        self.__totalProgress += chunk_size
        value = min(
            int((100.0 * self.__totalProgress) / size), 100
        )

        if value != self.__progressValue:
            self.__progressValue = value

            if progress_event:
                progress_event(value)

    def __reset(self):
        self.__isKilled = False
        self.__totalProgress = 0
        self.__progressValue = 0

    def __tag_length(self) -> int:
        result = 16

        if self.__mode in nonceModes:
            result = 8

        return result

    def __cipher(self, tag: bytes = None) -> tuple:
        cipher = None

        if self.__mode in ivModes:
            if not tag:
                tag = Random.new().read(AES.block_size)
            cipher = AES.new(self.__key, self.__mode, iv=tag)

        elif self.__mode in nonceModes:
            cipher = AES.new(self.__key, self.__mode, nonce=tag)
            tag = cipher.nonce

        return cipher, tag

    def __encrypt_file(
            self, src_file: typing.BinaryIO, output_file: typing.BinaryIO,
            add_key: bool = True, progress_event: typing.Callable = None
    ) -> bool:
        """Encrypt data from somewhere to save it somewhere"""

        self.__reset()

        size = src_file.seek(0, io.SEEK_END)
        src_file.seek(0)
        cipher, tag = self.__cipher()

        output_file.write(struct.pack('<Q', size))
        output_file.write(Output.signature)
        if add_key:
            output_file.write(utility.create_key(self.__key))
        output_file.write(tag)

        while True:
            chunk = src_file.read(chunkSize)
            chunk_size = len(chunk)
            if chunk_size == 0 or self.__isKilled:
                if self.__isKilled:
                    self.__kill(output_file)
                break
            elif chunk_size % AES.block_size != 0:
                chunk = utility.add_padding(chunk)

            output_file.write(cipher.encrypt(chunk))

            self.__progress_update(size, chunk_size, progress_event)

        return self.__progressValue == 100

    def __decrypt_file(
            self, src_file: typing.BinaryIO, output_file: typing.BinaryIO,
            check_key: bool = True, progress_event: typing.Callable = None
    ) -> bool:
        """
        Decrypt data from somewhere to read it somewhere
        :exception error.SignatureNotFoundError
        :exception error.WrongKeyError
        """

        self.__reset()

        size = struct.unpack('<Q', src_file.read(struct.calcsize('Q')))[0]

        signature = src_file.read(len(Output.signature))
        if signature != Output.signature:
            raise error.SignatureNotFoundError("Signature not found")

        if check_key:
            key = src_file.read(keyLength)
            if key != utility.create_key(self.__key):
                raise error.WrongKeyError("The key is wrong")

        tag = src_file.read(self.__tag_length())
        cipher, tag = self.__cipher(tag)

        while True:
            chunk = src_file.read(chunkSize)
            chunk_size = len(chunk)
            if chunk_size == 0 or self.__isKilled:
                if self.__isKilled:
                    self.__kill(output_file)
                break

            output_file.write(cipher.decrypt(chunk))

            self.__progress_update(size, chunk_size, progress_event)

        if not output_file.closed:
            output_file.truncate(size)

        return self.__progressValue == 100
