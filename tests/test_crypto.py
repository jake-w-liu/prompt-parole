import unittest

from prompt_parole.crypto import hash_password, verify_password
from prompt_parole.errors import PasswordError


class CryptoTests(unittest.TestCase):
    def test_hash_verifies_only_correct_password(self):
        secret = hash_password("correct horse battery staple", scrypt_n=2**10)
        self.assertTrue(verify_password("correct horse battery staple", secret))
        self.assertFalse(verify_password("wrong horse battery staple", secret))

    def test_rejects_short_password(self):
        with self.assertRaises(PasswordError):
            hash_password("short", scrypt_n=2**10)


if __name__ == "__main__":
    unittest.main()
