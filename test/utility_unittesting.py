from aescrypto import header, utility
import os
import hashlib
import unittest


directory = "test_dir"
outputDir = "output_dir"
debugging = True


def function_name(text: str):
    print(f"[ + ] Start for: {text}")


class MyTestCase(unittest.TestCase):
    def test_is_supported(self):
        function_name('is_supported')

        # Task
        path = os.path.join(outputDir, f'settings.json.{header.Output.fileExtension}')
        is_supported = utility.is_supported(path)

        # Debugging
        if debugging:
            print(f"""
            path: {path}
            is_supported: {is_supported}
            """)

        # Test
        self.assertTrue(is_supported)

    def test_checksum(self):
        function_name('checksum')

        # Task
        path = os.path.join(outputDir, f'settings.json.{header.Output.fileExtension}')
        checksum = utility.checksum(path)

        # Debugging
        if debugging:
            print(f"""
            path: {path}
            checksum: {checksum}
            """)

        # Test
        self.assertAlmostEqual(len(checksum), 64)

    def test_get_hash_string(self):
        function_name('get_hash_string')

        # Task
        text = "Hello World"
        text_md5 = utility.get_hash_string(text=text, algorithm=hashlib.md5)
        text_md5_expected = 'b10a8db164e0754105b7a99be72e3fe5'
        text_sha1 = utility.get_hash_string(text=text, algorithm=hashlib.sha1)
        text_sha1_expected = '0a4d55a8d778e5022fab701977c5d840bbc486d0'
        text_sha256 = utility.get_hash_string(text=text, algorithm=hashlib.sha256)
        text_sha256_expected = 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
        text_sha512 = utility.get_hash_string(text=text, algorithm=hashlib.sha512)
        text_sha512_expected = '2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e' \
                               '853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b'

        # Debugging
        if debugging:
            print(f"""
            text: {text}
            text_md5: {text_md5}
            text_md5_expected: {text_md5_expected}
            text_sha1: {text_sha1}
            text_sha1_expected: {text_sha1_expected}
            text_sha256: {text_sha256}
            text_sha256_expected: {text_sha256_expected}
            text_sha512: {text_sha512}
            text_sha512_expected: {text_sha512_expected}
            """)

        # Test
        self.assertEqual(text_md5, text_md5_expected)
        self.assertEqual(text_sha1, text_sha1_expected)
        self.assertEqual(text_sha256, text_sha256_expected)
        self.assertEqual(text_sha512, text_sha512_expected)

    def test_get_hash_digest(self):
        function_name('get_hash_digest')

        # Task
        text = "Hello World"
        text_md5 = utility.get_hash_digest(text=text, algorithm=hashlib.md5)
        text_md5_expected = b'\xb1\n\x8d\xb1d\xe0uA\x05\xb7\xa9\x9b\xe7.?\xe5'
        text_sha1 = utility.get_hash_digest(text=text, algorithm=hashlib.sha1)
        text_sha1_expected = b'\nMU\xa8\xd7x\xe5\x02/\xabp\x19w\xc5\xd8@\xbb\xc4\x86\xd0'
        text_sha256 = utility.get_hash_digest(text=text, algorithm=hashlib.sha256)
        text_sha256_expected = b'\xa5\x91\xa6\xd4\x0b\xf4 @J\x01\x173\xcf\xb7\xb1\x90\xd6,e' \
                               b'\xbf\x0b\xcd\xa3+W\xb2w\xd9\xad\x9f\x14n'
        text_sha512 = utility.get_hash_digest(text=text, algorithm=hashlib.sha512)
        text_sha512_expected = b',t\xfd\x17\xed\xaf\xd8\x0e\x84G\xb0\xd4gA\xee$;~\xb7M\xd2\x14' \
                               b'\x9a\n\xb1\xb9$o\xb3\x03\x82\xf2~\x85=\x85\x85q\x9e\x0eg\xcb\xda' \
                               b'\r\xaa\x8fQg\x10da]dZ\xe2z\xcb\x15\xbf\xb1D\x7fE\x9b'

        # Debugging
        if debugging:
            print(f"""
            text: {text}
            text_md5: {text_md5}
            text_md5_expected: {text_md5_expected}
            text_sha1: {text_sha1}
            text_sha1_expected: {text_sha1_expected}
            text_sha256: {text_sha256}
            text_sha256_expected: {text_sha256_expected}
            text_sha512: {text_sha512}
            text_sha512_expected: {text_sha512_expected}
            """)

        # Test
        self.assertEqual(text_md5, text_md5_expected)
        self.assertEqual(text_sha1, text_sha1_expected)
        self.assertEqual(text_sha256, text_sha256_expected)
        self.assertEqual(text_sha512, text_sha512_expected)

    def test_create_key(self):
        function_name('create_key')

        # Task
        key = "123456789"
        new_key = utility.create_key(key)
        expected = b'A\xb2\xc6g\xef(\xc0\xd1!\x19\xde0\xd8*\x8cgW\xf2jZ\xcd\x91\xf6\xd9s:\r"yNg\xde'

        # Debugging
        if debugging:
            print(f"""
            key: {key}
            new_path: {new_key}
            expected: {expected}
            """)

        # Test
        self.assertEqual(new_key, expected)
        self.assertAlmostEqual(len(new_key), header.keyLength)

    def test_add_extension(self):
        function_name('add_extension')

        # Task
        path = os.path.join(outputDir, 'settings.json')
        new_path = utility.add_extension(path)

        # Debugging
        if debugging:
            print(f"""
            path: {path}
            new_path: {new_path}
            """)

        # Test
        self.assertTrue(
            new_path.endswith(header.Output.fileExtension), msg="Extension file doesn't add"
        )

    def test_remove_extension(self):
        function_name('remove_extension')

        # Task
        path = os.path.join(outputDir, f'settings.json.{header.Output.fileExtension}')
        new_path = utility.remove_extension(path)

        # Debugging
        if debugging:
            print(f"""
            path: {path}
            new_path: {new_path}
            """)

        # Test
        self.assertFalse(
            new_path.endswith(header.Output.fileExtension), msg="Extension file doesn't remove"
        )

    def test_add_padding(self):
        function_name('add_padding')

        # Task
        text = "Padding this text"
        new_text = utility.add_padding(text)

        # Debugging
        if debugging:
            print(f"""
            text: {text}
            new_text: {new_text}
            """)

        # Test
        self.assertIn(len(new_text), (16, 32, 48, 64))

    def test_remove_padding(self):
        function_name('remove_padding')

        # Task
        text = b'Padding this text\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
        new_text = utility.remove_padding(text).decode()

        # Debugging
        if debugging:
            print(f"""
            text: {text}
            new_text: {new_text}
            """)

        # Test
        self.assertEqual(new_text, "Padding this text")

    def test_output_path_handler(self):
        function_name('output_path_handler')

        # Task
        path = os.path.join(outputDir, 'settings.json')
        path_encrypted = utility.output_path_handler(path=path)
        path_decrypted = utility.output_path_handler(path=path_encrypted)
        directory_encrypted = utility.output_path_handler(path=path, directory=directory)
        directory_decrypted = utility.output_path_handler(path=directory_encrypted, directory=directory)

        # Debugging
        if debugging:
            print(f"""
            path: {path}
            path_encrypted: {path_encrypted}
            path_decrypted: {path_decrypted}
            directory: {directory}
            directory_encrypted: {directory_encrypted}
            directory_decrypted: {directory_decrypted}
            """)

        # Test
        self.assertTrue(path_encrypted.endswith(header.Output.fileExtension))
        self.assertEqual(path, path_decrypted)
        self.assertTrue(directory_encrypted.endswith(header.Output.fileExtension))
        self.assertEqual(os.path.join(directory, os.path.basename(path)), directory_decrypted)


if __name__ == '__main__':
    unittest.main()
