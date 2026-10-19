"""Regra de permissao, formato do ls -l e leitura do modo do chmod (fs/permissions.py)."""

import unittest

from fs.constants import PERM_R, PERM_RW, PERM_W, TYPE_DIR, TYPE_FILE, TYPE_SYMLINK
from fs.errors import FSError
from fs.permissions import GROUP, OTHER, OWNER, ROOT, effective_access, parse_mode, perm_string
from fs.structs import Inode


def mode(digits: str) -> int:
    return parse_mode(digits, 0)


class PermStringTest(unittest.TestCase):
    def test_ls_format(self):
        """formato do ls -l: tipo + rw do dono, do grupo e dos outros (sem x)"""
        cases = [
            ("644", TYPE_DIR, "drwr-r-"),
            ("640", TYPE_FILE, "-rwr---"),
            ("600", TYPE_DIR, "drw----"),
            ("666", TYPE_SYMLINK, "lrwrwrw"),
            ("000", TYPE_FILE, "-------"),
            ("062", TYPE_FILE, "---rw-w"),
        ]
        for digits, itype, expected in cases:
            with self.subTest(modo=digits):
                self.assertEqual(perm_string(mode(digits), itype), expected)


class ParseModeTest(unittest.TestCase):
    def test_numeric_modes(self):
        """chmod numerico: 3 digitos com r=4 e w=2, igual no Linux sem o x"""
        cases = {"640": "-rwr---", "644": "-rwr-r-", "600": "-rw----", "666": "-rwrwrw", "000": "-------"}
        for digits, expected in cases.items():
            with self.subTest(modo=digits):
                self.assertEqual(perm_string(mode(digits), TYPE_FILE), expected)

    def test_numeric_mode_replaces_everything(self):
        """o modo numerico define tudo, nao importa o que tinha antes"""
        self.assertEqual(parse_mode("600", mode("666")), mode("600"))

    def test_symbolic_modes(self):
        """chmod simbolico: mexe so no que foi pedido, a partir da permissao atual"""
        current = mode("640")  # -rwr---
        cases = {
            "o+r": "-rwr-r-",
            "o-r": "-rwr---",
            "u-w": "-r-r---",
            "g=rw": "-rwrw--",
            "a=r": "-r-r-r-",
            "u=rw,g=r,o=": "-rwr---",
            "+w": "-rwrw-w",   # sem dizer quem, vale pra todos
            "-r": "--w----",
            "ug+w": "-rwrw--",
            "a-rw": "-------",
            "go=": "-rw----",
        }
        for text, expected in cases.items():
            with self.subTest(modo=text):
                self.assertEqual(perm_string(parse_mode(text, current), TYPE_FILE), expected)

    def test_invalid_modes(self):
        """modos invalidos sao recusados; o x tem mensagem propria"""
        for text in ("7", "999", "6400", "abc", "", "u=rw,x"):
            with self.subTest(modo=text):
                with self.assertRaises(FSError):
                    parse_mode(text, 0)
        for text in ("755", "u+x"):
            with self.subTest(modo=text):
                with self.assertRaises(FSError) as cm:
                    parse_mode(text, 0)
                self.assertIn("x", str(cm.exception))


class EffectiveAccessTest(unittest.TestCase):
    # uids: ana 1000, bruno 1001, carla 1002, diego 1003; grupo 1100 tem
    # ana e bruno; grupo 1101 tem diego

    def node(self, digits: str, owner: int, gid: int) -> Inode:
        return Inode(owner_uid=owner, gid=gid, perm=mode(digits))

    def test_root_ignores_permissions(self):
        """root pode tudo, mesmo num arquivo ---------"""
        self.assertEqual(effective_access(self.node("000", 1000, 1000), 0, [0]), (ROOT, PERM_RW))

    def test_owner_group_and_others(self):
        """cada pessoa cai em uma classe: dono, grupo ou outros"""
        node = self.node("642", owner=1001, gid=1100)  # dono rw, grupo r, outros w
        self.assertEqual(effective_access(node, 1001, [1001, 1100]), (OWNER, PERM_RW))
        self.assertEqual(effective_access(node, 1000, [1000, 1100]), (GROUP, PERM_R))
        self.assertEqual(effective_access(node, 1002, [1002]), (OTHER, PERM_W))

    def test_owner_only_gets_owner_bits(self):
        """classes exclusivas: num -r-rw--, o dono so le, mesmo estando no grupo que escreve"""
        node = self.node("460", owner=1001, gid=1100)
        self.assertEqual(effective_access(node, 1001, [1001, 1100]), (OWNER, PERM_R))
        self.assertEqual(effective_access(node, 1000, [1000, 1100]), (GROUP, PERM_RW))

    def test_group_can_get_less_than_others(self):
        """'todo mundo le, menos o grupo': num -rw--r-, quem e do grupo nao le"""
        node = self.node("604", owner=1000, gid=1101)
        self.assertEqual(effective_access(node, 1003, [1003, 1101]), (GROUP, 0))
        self.assertEqual(effective_access(node, 1002, [1002]), (OTHER, PERM_R))


if __name__ == "__main__":
    unittest.main()
