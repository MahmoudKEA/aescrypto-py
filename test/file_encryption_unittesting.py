from aescrypto import header, utility, AES, AESCrypto
import os
import time
import unittest


directory = "test_dir"
outputDir = "output_dir"
key = "123456789"
debugging = True


def function_name(text: str):
    print(f"[ + ] Start for: {text}")


def encrypt_progress_event(value: int):
    print(f"[ + ] {value}% Encrypting")


def decrypt_progress_event(value: int):
    print(f"[ + ] {value}% Decrypting")


class MyTestCase(unittest.TestCase):
    def test_cbc_mode(self):
        self.__test('cbc_mode', AES.MODE_CBC)

    def test_cfb_mode(self):
        self.__test('cfb_mode', AES.MODE_CFB)

    def test_ofb_mode(self):
        self.__test('ofb_mode', AES.MODE_OFB)

    def test_ctr_mode(self):
        self.__test('ctr_mode', AES.MODE_CTR)

    def __test(self, name: str, mode: int):
        function_name(name)

        for i, file_name in enumerate(os.listdir(directory)):
            if file_name.endswith(header.Output.fileExtension):
                continue

            # Task
            cipher = AESCrypto(key, mode=mode)

            file_path = os.path.join(directory, file_name)
            checksum = utility.checksum(file_path)

            encrypt_start_at = time.time()
            encrypt_status, encrypt_output_path = cipher.encrypt_file(
                file_path, directory=outputDir, ignore_file_exists=True,
                progress_event=encrypt_progress_event
            )
            encrypt_runtime = time.time() - encrypt_start_at

            decrypt_start_at = time.time()
            decrypt_status, decrypt_output_path = cipher.decrypt_file(
                encrypt_output_path, directory=directory, ignore_file_exists=True,
                remove_after_complete=True, progress_event=decrypt_progress_event
            )
            decrypt_runtime = time.time() - decrypt_start_at

            # Debugging
            if debugging:
                print(f"""
                attempt: {i}
                ------------
                key: {key}
                file_path: {file_path}
                checksum: {checksum}
                encrypt_status: {encrypt_status}
                encrypt_output_path: {encrypt_output_path}
                encrypt_runtime: {encrypt_runtime}
                decrypt_status: {decrypt_status}
                decrypt_output_path: {decrypt_output_path}
                decrypt_runtime: {decrypt_runtime}
                """)

            # Test
            self.assertEqual(checksum, utility.checksum(decrypt_output_path))
            self.assertTrue(encrypt_status, msg="Encrypt status is not complete")
            self.assertTrue(decrypt_status, msg="Decrypt status is not complete")


if __name__ == '__main__':
    unittest.main()
