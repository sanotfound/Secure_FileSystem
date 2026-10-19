"""chmod, chown e chgrp: quem pode usar cada um (fs/filesystem.py)."""

import unittest

from fs.constants import SHADOW_PATH
from fs.errors import FSError
from fs.permissions import perm_string
from tests.helpers import FSTestCase


class ChmodTest(FSTestCase):
    def setUp(self):
        super().setUp()
        self.become("ana")
        self.fs.write_file("/home/ana/a.txt", b"oi\n", False)

    def perm(self, path, follow_symlink=True):
        node = self.inode_of(path, follow_symlink)
        return perm_string(node.perm, node.type)

    def test_owner_changes_the_permissions(self):
        """o dono usa chmod numerico e simbolico no proprio arquivo"""
        for text, expected in (("600", "-rw----"), ("644", "-rwr-r-"), ("o-r", "-rwr---"),
                               ("u=rw,g=,o=", "-rw----"), ("g+r", "-rwr---")):
            with self.subTest(modo=text):
                self.fs.chmod("/home/ana/a.txt", text)
                self.assertEqual(self.perm("/home/ana/a.txt"), expected)

    def test_owner_can_take_away_her_own_write(self):
        """sem w nem o dono escreve; com chmod u+w volta a escrever"""
        self.fs.chmod("/home/ana/a.txt", "u=r")
        self.assertDenied(self.fs.write_file, "/home/ana/a.txt", b"x", False)
        self.fs.chmod("/home/ana/a.txt", "u+w")
        self.fs.write_file("/home/ana/a.txt", b"voltou\n", False)

    def test_invalid_mode_is_refused_and_nothing_changes(self):
        """modo invalido (ou com x) da erro e a permissao fica como estava"""
        for text in ("755", "7", "u+x", "abc"):
            with self.subTest(modo=text):
                with self.assertRaises(FSError):
                    self.fs.chmod("/home/ana/a.txt", text)
                self.assertEqual(self.perm("/home/ana/a.txt"), "-rwr---")

    def test_only_owner_or_root_uses_chmod(self):
        """chmod no arquivo de outra pessoa: Operacao nao permitida"""
        self.assertNotPermitted(self.fs.chmod, SHADOW_PATH, "666")
        self.assertNotPermitted(self.fs.chmod, "/etc/passwd", "666")
        self.become_root()
        self.fs.chmod("/home/ana", "644")  # deixa o bruno atravessar a home
        self.become("bruno")
        self.assertNotPermitted(self.fs.chmod, "/home/ana/a.txt", "666")
        self.become_root()
        self.fs.chmod("/home/ana/a.txt", "600")  # root pode

    def test_chmod_on_a_link_changes_the_target(self):
        """chmod num link muda o alvo; o link continua lrwrwrw"""
        self.fs.ln_s("a.txt", "/home/ana/link")
        self.fs.chmod("/home/ana/link", "600")
        self.assertEqual(self.perm("/home/ana/a.txt"), "-rw----")
        self.assertEqual(self.perm("/home/ana/link", follow_symlink=False), "lrwrwrw")


class ChownChgrpTest(FSTestCase):
    def setUp(self):
        super().setUp()
        self.become("ana")
        self.fs.write_file("/home/ana/a.txt", b"oi\n", False)
        self.become_root()

    def owner_and_group(self, path):
        node = self.inode_of(path)
        return node.owner_uid, node.gid

    def test_chown_is_root_only(self):
        """usuario comum nao usa chown, nem no proprio arquivo"""
        self.become("ana")
        self.assertNotPermitted(self.fs.chown, "/home/ana/a.txt", "bruno", None)
        self.assertNotPermitted(self.fs.chown, SHADOW_PATH, "ana", "ana")
        self.assertEqual(self.owner_and_group("/home/ana/a.txt"), (1000, 1000))

    def test_root_chown_keeps_the_creator(self):
        """chown do root troca o dono, o criador continua; o antigo dono perde o chmod"""
        self.fs.chown("/home/ana/a.txt", "bruno", None)
        node = self.inode_of("/home/ana/a.txt")
        self.assertEqual((node.owner_uid, node.gid, node.creator_uid), (1001, 1000, 1000))
        self.become("ana")
        self.assertNotPermitted(self.fs.chmod, "/home/ana/a.txt", "600")

    def test_chown_forms(self):
        """chown dono, chown dono:grupo e chown :grupo"""
        self.fs.chown("/home/ana/a.txt", None, "sudo")
        self.assertEqual(self.owner_and_group("/home/ana/a.txt"), (1000, 27))
        self.fs.chown("/home/ana/a.txt", "carla", "carla")
        self.assertEqual(self.owner_and_group("/home/ana/a.txt"), (1002, 1002))

    def test_chown_with_unknown_names_changes_nothing(self):
        """usuario ou grupo que nao existe: erro, e nada muda"""
        for owner, group in (("fulano", None), (None, "naoexiste"), ("bruno", "naoexiste")):
            with self.subTest(dono=owner, grupo=group):
                with self.assertRaises(FSError) as cm:
                    self.fs.chown("/home/ana/a.txt", owner, group)
                self.assertIn("não existe", str(cm.exception))
                self.assertEqual(self.owner_and_group("/home/ana/a.txt"), (1000, 1000))

    def test_chgrp_rules(self):
        """chgrp: o dono so pra grupo do qual e membro; outros nao; root pode tudo"""
        self.acc.groupadd("alunos")
        self.acc.add_to_groups("ana", ["alunos"])
        self.become("ana")
        self.fs.chgrp("/home/ana/a.txt", "alunos")
        self.assertEqual(self.owner_and_group("/home/ana/a.txt"), (1000, 1003))
        self.assertNotPermitted(self.fs.chgrp, "/home/ana/a.txt", "sudo")  # nao e membro
        self.assertNotPermitted(self.fs.chgrp, SHADOW_PATH, "ana")         # nao e dona
        self.fs.chmod("/home/ana", "644")
        self.become("bruno")
        self.assertNotPermitted(self.fs.chgrp, "/home/ana/a.txt", "bruno")  # nao e dono
        self.become_root()
        self.fs.chgrp("/home/ana/a.txt", "sudo")
        self.assertEqual(self.owner_and_group("/home/ana/a.txt"), (1000, 27))


if __name__ == "__main__":
    unittest.main()
