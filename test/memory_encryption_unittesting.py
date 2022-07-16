from aescrypto import AES, AESCrypto
import os
import time
import json
import unittest


outputDir = "output_dir"
key = "123456789"
debugging = True


def function_name(text: str):
    print(f"[ + ] Start for: {text}")


def dump_progress_event(value: int):
    print(f"[ + ] {value}% Dumping")


def load_progress_event(value: int):
    print(f"[ + ] {value}% Loading")


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

        # Task
        cipher = AESCrypto(key, mode=mode)

        data = {
            "username": "Mahmoud",
            "phone": "+2001111111111",
            "post": 11111,
            "isEnabled": True
        }
        output_path = os.path.join(outputDir, 'settings.json')

        dump_start_at = time.time()
        dump_status, dump_output_path = cipher.dump(
            data=json.dumps(data).encode(), path=output_path, add_key=True,
            ignore_file_exists=True, progress_event=dump_progress_event
        )
        dump_runtime = time.time() - dump_start_at

        load_start_at = time.time()
        load_status, load_output_data = cipher.load(
            path=dump_output_path, check_key=True, progress_event=load_progress_event
        )
        load_output_data = json.loads(load_output_data)
        load_runtime = time.time() - load_start_at

        # Debugging
        if debugging:
            print(f"""
            key: {key}
            output_path: {output_path}
            dump_status: {dump_status}
            dump_output_path: {dump_output_path}
            dump_runtime: {dump_runtime}
            load_status: {load_status}
            load_output_data: {load_output_data}
            load_runtime: {load_runtime}
            """)

        # Test
        self.assertEqual(data, load_output_data)
        self.assertTrue(dump_status, msg="Dump status is not complete")
        self.assertTrue(load_status, msg="Load status is not complete")


if __name__ == '__main__':
    unittest.main()
