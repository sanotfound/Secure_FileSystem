"""Formato do disco, formatacao e persistencia."""

import os
import unittest

from fs.constants import INODE_SIZE
from fs.errors import FSError
from fs.filesystem import FileSystem
from fs.permissions import perm_string
from fs.structs import Inode
from tests.helpers import FSTestCase, fast_scrypt, temp_path


class FormatTest(unittest.TestCase):
    def setUp(self):
        patcher = fast_scrypt()
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_inode_is_128_bytes_and_round_trips(self):
        """o i-node continua com 128 bytes e guarda dono, grupo e criador como numero"""
        node = Inode(used=1, type=0, perm=0o70, name="a.txt", owner_uid=1000, gid=1003,
                     creator_uid=1001, size=5, created_at=1.0, modified_at=2.0)
        raw = node.pack()
        self.assertEqual(len(raw), INODE_SIZE)
        self.assertEqual(INODE_SIZE, 128)
        back = Inode.unpack(raw)
        self.assertEqual((back.owner_uid, back.gid, back.creator_uid, back.name), (1000, 1003, 1001, "a.txt"))

    def test_old_format_disk_is_refused_and_left_untouched(self):
        """disco da versao antiga (SOFS) nao e montado e nao e alterado"""
        path = temp_path("antigo.img")
        content = b"SOFS" + bytes(2044)
        with open(path, "wb") as f:
            f.write(content)
        with self.assertRaises(FSError) as cm:
            FileSystem(path)
        self.assertIn("formato antigo", str(cm.exception))
        with open(path, "rb") as f:
            self.assertEqual(f.read(), content)
        os.remove(path)  # da pra apagar: o arquivo foi fechado

    def test_new_disk_needs_a_root_password(self):
        """sem senha do root (ou com senha vazia) o disco nem e criado"""
        path = temp_path("novo.img")
        for password in (None, ""):
            with self.subTest(senha=password):
                with self.assertRaises(FSError):
                    FileSystem(path, root_password=password)
                self.assertFalse(os.path.exists(path))


class PersistenceTest(FSTestCase):
    def test_everything_survives_a_remount(self):
        """depois de desmontar e montar de novo, arquivos, donos, grupos e permissoes continuam"""
        self.acc.groupadd("projeto")
        self.acc.add_to_groups("ana", ["projeto"])
        self.acc.set_locked("carla", True)
        self.become("ana")
        self.fs.write_file("/home/ana/a.txt", b"persistiu\n", False)
        self.fs.chgrp("/home/ana/a.txt", "projeto")
        self.fs.chmod("/home/ana/a.txt", "600")

        self.remount()

        self.assertIn(1003, self.acc.group_ids_of(self.acc.get_user("ana")))
        self.assertIsNone(self.acc.authenticate("carla", "carla123"))  # continua bloqueada
        self.assertIsNotNone(self.acc.authenticate("ana", "ana123"))
        node = self.inode_of("/home/ana/a.txt")
        self.assertEqual((node.owner_uid, node.gid, perm_string(node.perm, node.type)), (1000, 1003, "-rw----"))
        self.become("ana")
        self.assertEqual(self.fs.read_file("/home/ana/a.txt"), b"persistiu\n")


if __name__ == "__main__":
    unittest.main()
