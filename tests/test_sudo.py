"""sudo: senha da propria pessoa, sudoers e volta das credenciais (fs/accounts.py)."""

import unittest

from fs.constants import SHADOW_PATH, SUDOERS_PATH
from fs.errors import FSError
from tests.helpers import FSTestCase


class SudoTest(FSTestCase):
    def setUp(self):
        super().setUp()
        self.acc.add_to_groups("ana", ["sudo"])  # a ana e administradora

    def assertSudoRefused(self, password, message):
        with self.assertRaises(FSError) as cm:
            with self.acc.sudo(password):
                self.fail("o comando nao devia ter rodado")
        self.assertIn(message, str(cm.exception))

    def test_user_outside_sudoers_is_refused_after_the_password(self):
        """o bruno nao esta no sudoers: senha certa, mas e recusado"""
        self.become("bruno")
        self.assertSudoRefused("bruno123", "bruno não está no arquivo sudoers")
        self.assertEqual(self.fs.uid, 1001)

    def test_wrong_password_is_refused(self):
        """senha errada: o comando nem roda"""
        self.become("ana")
        self.assertSudoRefused("errada", "senha incorreta")
        self.assertEqual(self.fs.uid, 1000)

    def test_root_only_while_the_command_runs(self):
        """com sudo a ana vira root so durante o comando; depois volta a ser ela"""
        self.become("ana")
        with self.acc.sudo("ana123"):
            self.assertEqual(self.fs.uid, 0)
            self.fs.read_file(SHADOW_PATH)
        self.assertEqual((self.fs.uid, self.fs.gid), (1000, 1000))
        self.assertDenied(self.fs.read_file, SHADOW_PATH)

    def test_credentials_come_back_even_after_an_error(self):
        """se o comando der erro, as credenciais voltam do mesmo jeito"""
        self.become("ana")
        with self.assertRaises(FSError):
            with self.acc.sudo("ana123"):
                raise FSError("erro no meio do comando")
        self.assertEqual(self.fs.uid, 1000)

    def test_sudo_su_keeps_the_switch(self):
        """sudo su vira root de vez; sudo su bruno vira o bruno"""
        self.become("ana")
        with self.acc.sudo("ana123"):
            self.acc.switch_user("root", None)
        self.assertEqual(self.fs.uid, 0)
        self.become("ana")
        with self.acc.sudo("ana123"):
            self.acc.switch_user("bruno", None)
        self.assertEqual(self.fs.uid, 1001)

    def test_root_needs_no_password(self):
        """o root usa sudo sem senha"""
        with self.acc.sudo(None):
            self.assertEqual(self.fs.uid, 0)

    def test_user_listed_by_name(self):
        """uma linha com o nome do usuario no sudoers tambem autoriza"""
        self.fs.write_file(SUDOERS_PATH, b"bruno\n", append=True)
        self.become("bruno")
        with self.acc.sudo("bruno123"):
            self.assertEqual(self.fs.uid, 0)

    def test_linux_style_line(self):
        """linha no formato do Linux (carla ALL=(ALL) ALL) funciona: so a primeira palavra conta"""
        self.fs.write_file(SUDOERS_PATH, b"carla ALL=(ALL) ALL\n", append=True)
        self.become("carla")
        with self.acc.sudo("carla123"):
            self.assertEqual(self.fs.uid, 0)

    def test_leaving_the_sudo_group_revokes_on_the_spot(self):
        """tirou a ana do grupo sudo, o proximo sudo dela ja e recusado"""
        self.acc.remove_from_group("ana", "sudo")
        self.become("ana")
        self.assertSudoRefused("ana123", "ana não está no arquivo sudoers")

    def test_locked_account_cannot_use_sudo(self):
        """conta bloqueada nao passa no sudo, mesmo com a senha certa"""
        self.acc.set_locked("ana", True)
        self.become("ana")
        self.assertSudoRefused("ana123", "senha incorreta")

    def test_without_sudoers_nobody_uses_sudo(self):
        """se o /etc/sudoers sumir, ninguem usa sudo"""
        self.fs.rm(SUDOERS_PATH)
        self.become("ana")
        self.assertSudoRefused("ana123", "ana não está no arquivo sudoers")


if __name__ == "__main__":
    unittest.main()
