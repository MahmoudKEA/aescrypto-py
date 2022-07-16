from aescrypto import AES, AESCrypto
import time
import unittest


plainText = "Encrypt this plain text"
plainText16 = "Encrypt this txt"
plainTextBytes = b"Encrypt this plain text"
plainTextBytes16 = b"Encrypt this txt"
key = "123456789"
debugging = True


def function_name(text: str):
    print(f"[ + ] Start for: {text}")


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

        for text in (plainText, plainText16, plainTextBytes, plainTextBytes16):
            # Task
            start_at = time.time()
            cipher = AESCrypto(key, mode=mode)
            encrypt = cipher.encrypt(text, add_key=True)
            decrypt = cipher.decrypt(encrypt, check_key=True)
            if isinstance(text, str):
                decrypt = decrypt.decode()
            runtime = time.time() - start_at

            # Debugging
            if debugging:
                print(f"""
                text: {text}
                key: {key}
                encrypt: {encrypt}
                decrypt: {decrypt}
                runtime: {runtime}
                """)

            # Test
            self.assertEqual(text, decrypt)


if __name__ == '__main__':
    unittest.main()
