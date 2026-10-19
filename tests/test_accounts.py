"""Usuarios, senhas, login, su e grupos (fs/accounts.py)."""

import unittest
from unittest import mock

from fs.constants import GROUP_PATH, PASSWD_PATH, SHADOW_PATH
from fs.errors import FSError
from fs.permissions import perm_string
from tests.helpers import USER_PASSWORDS, FSTestCase


class InitialStructureTest(FSTestCase):
    def test_account_files_owner_and_permissions(self):
        """/etc/passwd e /etc/group todo mundo le; /etc/shadow e /etc/sudoers so o root"""
        expected = {"/etc/passwd": "-rwr-r-", "/etc/group": "-rwr-r-",
                    "/etc/shadow": "-rw----", "/etc/sudoers": "-rw----"}
        for path, perm in expected.items():
            with self.subTest(arquivo=path):
                node = self.inode_of(path)
                self.assertEqual(perm_string(node.perm, node.type), perm)
                self.assertEqual((node.owner_uid, node.gid), (0, 0))

    def test_initial_directories(self):
        """/, /etc e /home sao 644 do root; /root e as homes sao privadas"""
        expected = {"/": ("drwr-r-", 0), "/etc": ("drwr-r-", 0), "/home": ("drwr-r-", 0),
                    "/root": ("drw----", 0), "/home/ana": ("drw----", 1000)}
        for path, (perm, owner) in expected.items():
            with self.subTest(diretorio=path):
                node = self.inode_of(path)
                self.assertEqual(perm_string(node.perm, node.type), perm)
                self.assertEqual(node.owner_uid, owner)

    def test_shadow_keeps_hashes_not_passwords(self):
        """o shadow tem 'nome:scrypt$...' e nenhuma senha em texto"""
        shadow = self.read_as_root(SHADOW_PATH).decode()
        for name, password in USER_PASSWORDS.items():
            self.assertIn(f"{name}:scrypt$", shadow)
            self.assertNotIn(password, shadow)

    def test_passwd_group_and_sudoers_content(self):
        """formato dos arquivos de contas, igual no Linux"""
        self.assertIn("ana:x:1000:1000:/home/ana", self.read_as_root(PASSWD_PATH).decode())
        group = self.read_as_root(GROUP_PATH).decode()
        self.assertIn("ana:x:1000:", group)
        self.assertIn("sudo:x:27:", group)
        self.assertIn("%sudo", self.read_as_root("/etc/sudoers").decode())


class UseraddTest(FSTestCase):
    def test_useradd_creates_private_group_and_home(self):
        """useradd cria usuario, grupo proprio com o mesmo numero e home drw----"""
        user = self.acc.useradd("dave", "d")
        self.assertEqual((user.uid, user.gid, user.home), (1003, 1003, "/home/dave"))
        self.assertEqual(self.acc.get_group("dave").gid, 1003)
        home = self.inode_of("/home/dave")
        self.assertEqual((home.owner_uid, home.gid), (1003, 1003))
        self.assertEqual(perm_string(home.perm, home.type), "drw----")
        self.assertIsNotNone(self.acc.authenticate("dave", "d"))

    def test_only_root_creates_users(self):
        """usuario comum nao usa useradd"""
        self.become("ana")
        self.assertDenied(self.acc.useradd, "dave", "d")

    def test_bad_names_are_refused(self):
        """nome repetido ou fora da regra (minusculas, digitos e _, ate 15) e recusado"""
        for name in ("ana", "9x", "Ana", "a-b", "x" * 16):
            with self.subTest(nome=name):
                with self.assertRaises(FSError):
                    self.acc.useradd(name, "senha")

    def test_empty_password_is_refused(self):
        """senha vazia nao e aceita, e nada e criado"""
        with self.assertRaises(FSError):
            self.acc.useradd("dave", "")
        self.assertNotIn("dave", self.acc.users)
        with self.assertRaises(FSError):
            self.inode_of("/home/dave")

    def test_private_group_takes_next_number_when_taken(self):
        """se o numero do usuario ja e de um grupo, o grupo proprio pega o proximo livre"""
        self.acc.groupadd("projeto")  # fica com o 1003
        user = self.acc.useradd("dave", "d")
        self.assertEqual((user.uid, user.gid), (1003, 1004))

    def test_useradd_is_all_or_nothing(self):
        """se a gravacao falhar no meio (disco cheio), nada fica pela metade"""
        before = {p: self.read_as_root(p) for p in (PASSWD_PATH, SHADOW_PATH, GROUP_PATH)}
        original = self.fs.write_file

        def failing_write(path, content, append):
            if path == PASSWD_PATH:
                raise FSError("disco cheio (simulado)")
            return original(path, content, append)

        with mock.patch.object(self.fs, "write_file", side_effect=failing_write):
            with self.assertRaises(FSError):
                self.acc.useradd("dave", "d")
        self.assertEqual({p: self.read_as_root(p) for p in before}, before)
        self.assertNotIn("dave", self.acc.users)
        with self.assertRaises(FSError):
            self.inode_of("/home/dave")  # a home criada no comeco foi removida
        self.acc.useradd("dave", "d")  # e da pra tentar de novo normalmente


class LoginAndPasswordTest(FSTestCase):
    def test_login_does_not_say_why_it_failed(self):
        """usuario inexistente, senha errada e conta bloqueada dao todos None"""
        self.assertEqual(self.acc.authenticate("ana", "ana123").name, "ana")
        self.assertIsNone(self.acc.authenticate("ana", "errada"))
        self.assertIsNone(self.acc.authenticate("fulano", "qualquer"))
        self.acc.set_locked("ana", True)
        self.assertIsNone(self.acc.authenticate("ana", "ana123"))

    def test_missing_user_still_spends_the_time(self):
        """usuario que nao existe tambem paga um scrypt (o tempo nao entrega quem existe)"""
        with mock.patch("fs.accounts.waste_time") as wasted:
            self.acc.authenticate("fulano", "qualquer")
        wasted.assert_called_once()

    def test_change_own_password_needs_the_current_one(self):
        """passwd do proprio usuario pede a senha atual; depois so a nova funciona"""
        self.become("ana")
        with self.assertRaises(FSError) as cm:
            self.acc.change_password("ana", "nova", "errada")
        self.assertIn("senha atual incorreta", str(cm.exception))
        self.acc.change_password("ana", "nova", "ana123")
        self.assertIsNone(self.acc.authenticate("ana", "ana123"))
        self.assertIsNotNone(self.acc.authenticate("ana", "nova"))

    def test_user_cannot_change_someone_elses_password(self):
        """ana nao troca a senha do bruno"""
        self.become("ana")
        self.assertDenied(self.acc.change_password, "bruno", "nova", "ana123")

    def test_root_changes_any_password(self):
        """root troca a senha de qualquer um, sem precisar da atual"""
        self.acc.change_password("bruno", "nova")
        self.assertIsNotNone(self.acc.authenticate("bruno", "nova"))

    def test_lock_and_unlock_account(self):
        """passwd -l bloqueia (com ! no shadow) e passwd -u devolve a mesma senha"""
        self.acc.set_locked("bruno", True)
        self.assertIn("bruno:!scrypt$", self.read_as_root(SHADOW_PATH).decode())
        self.assertIsNone(self.acc.authenticate("bruno", "bruno123"))
        self.acc.set_locked("bruno", False)
        self.assertIsNotNone(self.acc.authenticate("bruno", "bruno123"))

    def test_root_cannot_be_locked_and_users_cannot_lock(self):
        """bloquear o root e recusado; usuario comum nao bloqueia ninguem"""
        with self.assertRaises(FSError):
            self.acc.set_locked("root", True)
        self.become("ana")
        self.assertDenied(self.acc.set_locked, "bruno", True)

    def test_su(self):
        """su: root troca sem senha; os outros precisam da senha do usuario de destino"""
        self.acc.switch_user("ana", None)
        self.assertEqual(self.fs.uid, 1000)
        self.assertDenied(self.acc.switch_user, "bruno", "errada", message="Falha de autenticação")
        self.assertEqual(self.fs.uid, 1000)
        self.acc.switch_user("bruno", "bruno123")
        self.assertEqual(self.fs.uid, 1001)


class GroupTest(FSTestCase):
    def test_groupadd(self):
        """groupadd cria o grupo com o primeiro numero livre a partir de 1000"""
        self.assertEqual(self.acc.groupadd("alunos").gid, 1003)
        self.assertIn("alunos:x:1003:", self.read_as_root(GROUP_PATH).decode())
        with self.assertRaises(FSError):
            self.acc.groupadd("alunos")
        with self.assertRaises(FSError):
            self.acc.groupadd("9x")

    def test_add_to_groups(self):
        """usermod -aG coloca em um ou mais grupos, sem repetir membro"""
        self.acc.groupadd("alunos")
        self.acc.add_to_groups("ana", ["alunos", "sudo"])
        self.acc.add_to_groups("ana", ["alunos"])
        self.assertEqual(self.acc.group_ids_of(self.acc.get_user("ana")), [1000, 27, 1003])
        self.assertEqual(self.acc.get_group("alunos").members, ["ana"])

    def test_add_to_groups_is_all_or_nothing(self):
        """se um dos grupos nao existe, nenhum e alterado"""
        self.acc.groupadd("alunos")
        with self.assertRaises(FSError):
            self.acc.add_to_groups("ana", ["alunos", "naoexiste"])
        self.assertEqual(self.acc.get_group("alunos").members, [])

    def test_remove_from_group(self):
        """gpasswd -d tira do grupo; nao tira do grupo primario; avisa se nao e membro"""
        self.acc.groupadd("alunos")
        self.acc.add_to_groups("ana", ["alunos"])
        self.acc.remove_from_group("ana", "alunos")
        self.assertEqual(self.acc.get_group("alunos").members, [])
        with self.assertRaises(FSError) as cm:
            self.acc.remove_from_group("ana", "alunos")
        self.assertIn("não é membro", str(cm.exception))
        with self.assertRaises(FSError) as cm:
            self.acc.remove_from_group("ana", "ana")
        self.assertIn("grupo primário", str(cm.exception))

    def test_group_commands_are_root_only(self):
        """usuario comum nao cria grupo nem mexe em membros"""
        self.acc.groupadd("alunos")
        self.become("ana")
        self.assertDenied(self.acc.groupadd, "hackers")
        self.assertDenied(self.acc.add_to_groups, "ana", ["sudo"])
        self.assertDenied(self.acc.remove_from_group, "bruno", "bruno")

    def test_manual_edit_is_picked_up(self):
        """o root pode editar /etc/group na mao; a proxima leitura ja enxerga"""
        self.fs.write_file(GROUP_PATH, b"extra:x:1500:ana\n", append=True)
        self.acc.load()
        self.assertEqual(self.acc.get_group("extra").members, ["ana"])


if __name__ == "__main__":
    unittest.main()
