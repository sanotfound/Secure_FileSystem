"""Hash das senhas (fs/passwords.py)."""

import hmac
import unittest
from unittest import mock

from fs.passwords import hash_password, is_locked, lock, unlock, verify_password
from tests.helpers import fast_scrypt


class RealParametersTest(unittest.TestCase):
    # esse e o unico teste que paga o scrypt de verdade (~1 s): e ele que
    # garante que o sistema usa os parametros que a gente decidiu

    def test_hash_uses_the_real_scrypt_parameters(self):
        """o hash guardado usa scrypt com N=2^17, r=8, p=1, salt de 16 bytes e hash de 32"""
        stored = hash_password("segredo")
        algo, log2_n, r, p, salt_hex, hash_hex = stored.split("$")
        self.assertEqual((algo, log2_n, r, p), ("scrypt", "17", "8", "1"))
        self.assertEqual(len(bytes.fromhex(salt_hex)), 16)
        self.assertEqual(len(bytes.fromhex(hash_hex)), 32)
        self.assertTrue(verify_password("segredo", stored))


class PasswordTest(unittest.TestCase):
    def setUp(self):
        patcher = fast_scrypt()
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_password_is_never_stored(self):
        """a senha nao aparece no que vai pro shadow (nem em texto, nem em hex)"""
        stored = hash_password("minhasenha")
        self.assertNotIn("minhasenha", stored)
        self.assertNotIn("minhasenha".encode().hex(), stored)

    def test_same_password_gets_different_hashes(self):
        """mesma senha com salts diferentes da hashes diferentes, e os dois conferem"""
        first, second = hash_password("igual"), hash_password("igual")
        self.assertNotEqual(first, second)
        self.assertTrue(verify_password("igual", first))
        self.assertTrue(verify_password("igual", second))

    def test_wrong_password_is_refused(self):
        """senha errada (ou vazia) nao confere"""
        stored = hash_password("certa")
        self.assertFalse(verify_password("errada", stored))
        self.assertFalse(verify_password("", stored))

    def test_lock_and_unlock(self):
        """conta bloqueada recusa ate a senha certa; desbloquear devolve a mesma senha"""
        stored = hash_password("x")
        locked = lock(stored)
        self.assertTrue(locked.startswith("!"))
        self.assertTrue(is_locked(locked))
        self.assertEqual(lock(locked), locked)  # bloquear de novo nao muda nada
        self.assertFalse(verify_password("x", locked))
        self.assertEqual(unlock(locked), stored)
        self.assertTrue(verify_password("x", unlock(locked)))

    def test_corrupted_record_is_refused(self):
        """registro corrompido ou de outro algoritmo nunca confere"""
        for stored in ("", "lixo", "scrypt$17$8$1$zz$zz", "md5$1$2$3$aa$bb"):
            with self.subTest(stored=stored):
                self.assertFalse(verify_password("x", stored))

    def test_comparison_uses_compare_digest(self):
        """a comparacao final e feita com hmac.compare_digest (tempo constante)"""
        stored = hash_password("x")
        with mock.patch("fs.passwords.hmac.compare_digest", wraps=hmac.compare_digest) as spy:
            verify_password("x", stored)
        spy.assert_called_once()


if __name__ == "__main__":
    unittest.main()
