"""Controle de acesso: as checagens de r/w em cada operacao (fs/filesystem.py)."""

import unittest

from fs.constants import PERM_R, PERM_RW, SHADOW_PATH
from fs.permissions import OTHER, OWNER, ROOT, parse_mode, perm_string
from tests.helpers import FSTestCase


class ShadowTest(FSTestCase):
    def test_regular_user_cannot_touch_the_shadow(self):
        """todas as tentativas de usuario comum contra o /etc/shadow sao negadas"""
        before = self.read_as_root(SHADOW_PATH)
        self.become("ana")
        attempts = {
            "cat": lambda: self.fs.read_file(SHADOW_PATH),
            "cp": lambda: self.fs.cp(SHADOW_PATH, "/home/ana/copia"),
            "echo >": lambda: self.fs.write_file(SHADOW_PATH, b"hack\n", False),
            "echo >>": lambda: self.fs.write_file(SHADOW_PATH, b"hack\n", True),
            "touch": lambda: self.fs.touch(SHADOW_PATH),
            "rm": lambda: self.fs.rm(SHADOW_PATH),
            "mv": lambda: self.fs.mv(SHADOW_PATH, "/home/ana/x"),
            "criar outro em /etc": lambda: self.fs.touch("/etc/shadow2"),
            "mkdir em /etc": lambda: self.fs.mkdir("/etc/pasta"),
        }
        for name, attempt in attempts.items():
            with self.subTest(tentativa=name):
                self.assertDenied(attempt)
        self.assertEqual(self.read_as_root(SHADOW_PATH), before)

    def test_link_to_the_shadow_does_not_help(self):
        """criar link pro shadow pode, mas ler por ele cai na permissao do alvo"""
        self.become("ana")
        self.fs.ln_s(SHADOW_PATH, "/home/ana/atalho")
        self.assertDenied(self.fs.read_file, "/home/ana/atalho")
        link = self.inode_of("/home/ana/atalho", follow_symlink=False)
        self.assertEqual(perm_string(link.perm, link.type), "lrwrwrw")

    def test_public_account_files_are_readable(self):
        """/etc/passwd e /etc/group todo mundo le"""
        self.become("ana")
        self.assertIn(b"ana:x:1000", self.fs.read_file("/etc/passwd"))
        self.assertIn(b"sudo:x:27", self.fs.read_file("/etc/group"))

    def test_kernel_still_writes_the_shadow_for_users(self):
        """com usuario comum logado, o passwd grava o shadow (modo kernel) e ele continua fechado"""
        self.become("ana")
        self.acc.change_password("ana", "nova", "ana123")
        self.assertIsNotNone(self.acc.authenticate("ana", "nova"))
        shadow = self.inode_of(SHADOW_PATH)
        self.assertEqual((shadow.owner_uid, perm_string(shadow.perm, shadow.type)), (0, "-rw----"))


class PrivacyTest(FSTestCase):
    def setUp(self):
        super().setUp()
        self.become("ana")
        self.fs.write_file("/home/ana/notas.txt", b"da ana\n", False)

    def test_home_is_private(self):
        """ninguem entra, lista, le, cria ou apaga nada na home de outro usuario"""
        self.become("bruno")
        attempts = {
            "ls": lambda: self.fs.ls("/home/ana"),
            "cd": lambda: self.fs.cd("/home/ana"),
            "cat": lambda: self.fs.read_file("/home/ana/notas.txt"),
            "echo >": lambda: self.fs.write_file("/home/ana/notas.txt", b"x", False),
            "touch": lambda: self.fs.touch("/home/ana/novo"),
            "rm": lambda: self.fs.rm("/home/ana/notas.txt"),
        }
        for name, attempt in attempts.items():
            with self.subTest(tentativa=name):
                error = self.assertDenied(attempt)
                self.assertIn("/home/ana", str(error))  # a mensagem diz onde parou

    def test_root_ignores_permissions(self):
        """o root le e escreve em qualquer lugar"""
        self.become_root()
        self.assertEqual(self.fs.read_file("/home/ana/notas.txt"), b"da ana\n")
        self.fs.write_file("/home/ana/do_root.txt", b"oi\n", False)
        self.assertIsNotNone(self.fs.read_file(SHADOW_PATH))

    def test_new_files_are_private_by_default(self):
        """arquivo e diretorio novos: dono e criador = quem criou, grupo proprio, 640"""
        self.fs.mkdir("/home/ana/docs")
        for path, perm in (("/home/ana/notas.txt", "-rwr---"), ("/home/ana/docs", "drwr---")):
            with self.subTest(caminho=path):
                node = self.inode_of(path)
                self.assertEqual((node.owner_uid, node.gid, node.creator_uid), (1000, 1000, 1000))
                self.assertEqual(perm_string(node.perm, node.type), perm)

    def test_opening_the_home_does_not_expose_the_files(self):
        """grupo proprio + 640: a ana abre a home (644), o bruno lista mas nao le o arquivo"""
        self.fs.chmod("/home/ana", "644")
        self.become("bruno")
        self.assertEqual([name for name, _, _ in self.fs.ls("/home/ana")], ["notas.txt"])
        self.assertDenied(self.fs.read_file, "/home/ana/notas.txt")

    def test_access_of_tells_the_class(self):
        """access_of diz em qual classe a pessoa cai (e o que o stat mostra como 'seu acesso')"""
        self.assertEqual(self.fs.access_of(self.inode_of("/home/ana/notas.txt")), (OWNER, PERM_RW))
        self.assertEqual(self.fs.access_of(self.inode_of("/etc/passwd")), (OTHER, PERM_R))
        self.become_root()
        self.assertEqual(self.fs.access_of(self.inode_of(SHADOW_PATH))[0], ROOT)


class DirectoryTest(FSTestCase):
    def test_crossing_a_directory_needs_r(self):
        """so w num diretorio nao basta: pra criar algo dentro precisa atravessar (r)"""
        self.fs.mkdir("/home/caixa")
        self.fs.chmod("/home/caixa", "602")  # outros: so w
        self.become("carla")
        error = self.assertDenied(self.fs.touch, "/home/caixa/x")
        self.assertIn("/home/caixa", str(error))
        self.become_root()
        self.fs.chmod("/home/caixa", "606")  # outros: rw
        self.become("carla")
        self.fs.touch("/home/caixa/x")

    def test_mv_does_not_reveal_what_is_inside(self):
        """mv pra uma pasta sem permissao da 'Permissao negada', nunca 'ja existe'"""
        self.become("bruno")
        self.fs.write_file("/home/bruno/x.txt", b"do bruno\n", False)
        self.become("ana")
        self.fs.write_file("/home/ana/x.txt", b"da ana\n", False)
        self.assertDenied(self.fs.mv, "/home/ana/x.txt", "/home/bruno")


class SharedFolderTest(FSTestCase):
    def setUp(self):
        super().setUp()
        self.acc.groupadd("alunos")
        self.acc.add_to_groups("ana", ["alunos"])
        self.acc.add_to_groups("bruno", ["alunos"])
        self.fs.mkdir("/home/projeto")
        self.fs.chown("/home/projeto", "ana", "alunos")
        self.fs.chmod("/home/projeto", "664")  # grupo rw, outros so r (pra atravessar)

    def test_sharing_needs_chgrp(self):
        """arquivo novo na pasta nasce com o grupo de quem criou; o chgrp e que compartilha"""
        self.become("bruno")
        self.fs.write_file("/home/projeto/b.txt", b"do bruno\n", False)
        self.assertEqual(self.inode_of("/home/projeto/b.txt").gid, 1001)
        self.become("ana")
        self.assertDenied(self.fs.read_file, "/home/projeto/b.txt")
        self.become("bruno")
        self.fs.chgrp("/home/projeto/b.txt", "alunos")
        self.become("ana")
        self.assertEqual(self.fs.read_file("/home/projeto/b.txt"), b"do bruno\n")
        self.assertDenied(self.fs.write_file, "/home/projeto/b.txt", b"x", False)  # grupo so r
        self.become("carla")
        self.assertDenied(self.fs.read_file, "/home/projeto/b.txt")  # outros: --

    def test_owner_class_wins_even_with_weaker_bits(self):
        """-r-rw-- do bruno, grupo alunos: o bruno (dono) nao escreve, a ana (grupo) escreve"""
        self.fs.write_file("/home/projeto/r.txt", b"v1\n", False)
        self.fs.chown("/home/projeto/r.txt", "bruno", "alunos")
        self.fs.chmod("/home/projeto/r.txt", "460")
        self.become("bruno")
        self.assertDenied(self.fs.write_file, "/home/projeto/r.txt", b"v2\n", False)
        self.become("ana")
        self.fs.write_file("/home/projeto/r.txt", b"v2\n", False)

    def test_a_group_can_be_left_out(self):
        """'todo mundo le, menos os estagiarios': -rw--r- com grupo estagiarios"""
        self.acc.groupadd("estagiarios")
        self.acc.add_to_groups("carla", ["estagiarios"])
        self.fs.write_file("/home/projeto/politica.txt", b"regras\n", False)
        self.fs.chown("/home/projeto/politica.txt", "ana", "estagiarios")
        self.fs.chmod("/home/projeto/politica.txt", "604")
        self.become("carla")
        self.assertDenied(self.fs.read_file, "/home/projeto/politica.txt")
        self.become("bruno")  # bruno nao e estagiario: cai em outros
        self.assertEqual(self.fs.read_file("/home/projeto/politica.txt"), b"regras\n")

    def test_leaving_a_group_cuts_access_immediately(self):
        """tirou do grupo, a proxima leitura ja e negada"""
        self.fs.write_file("/home/projeto/a.txt", b"da ana\n", False)
        self.fs.chown("/home/projeto/a.txt", "ana", "alunos")
        self.become("bruno")
        self.assertEqual(self.fs.read_file("/home/projeto/a.txt"), b"da ana\n")
        self.become_root()
        self.acc.remove_from_group("bruno", "alunos")
        self.become("bruno")
        self.assertDenied(self.fs.read_file, "/home/projeto/a.txt")


class CopyTest(FSTestCase):
    def setUp(self):
        super().setUp()
        self.become("ana")
        self.fs.write_file("/home/ana/priv.txt", b"p\n", False)
        self.fs.write_file("/home/ana/pub.txt", b"p\n", False)
        self.fs.chmod("/home/ana/priv.txt", "600")
        self.fs.chmod("/home/ana/pub.txt", "644")

    def perm(self, path):
        node = self.inode_of(path)
        return perm_string(node.perm, node.type)

    def test_copy_is_never_more_open_than_the_original(self):
        """copia nova = permissoes do original limitadas por 640 (600 -> 600, 644 -> 640)"""
        self.fs.cp("/home/ana/priv.txt", "/home/ana/c1")
        self.fs.cp("/home/ana/pub.txt", "/home/ana/c2")
        self.assertEqual(self.perm("/home/ana/c1"), "-rw----")
        self.assertEqual(self.perm("/home/ana/c2"), "-rwr---")
        self.assertEqual(parse_mode("644", 0) & parse_mode("640", 0), parse_mode("640", 0))

    def test_copy_over_existing_file_keeps_its_permissions(self):
        """cp em cima de um arquivo que ja existe mantem as permissoes dele"""
        self.fs.write_file("/home/ana/destino", b"velho\n", False)
        self.fs.chmod("/home/ana/destino", "600")
        self.fs.cp("/home/ana/pub.txt", "/home/ana/destino")
        self.assertEqual(self.perm("/home/ana/destino"), "-rw----")

    def test_copy_belongs_to_who_copied(self):
        """a carla copia um arquivo legivel da ana: a copia e da carla (dono, grupo e criador)"""
        self.fs.chmod("/home/ana", "644")
        self.become("carla")
        self.fs.cp("/home/ana/pub.txt", "/home/carla/de_ana.txt")
        node = self.inode_of("/home/carla/de_ana.txt")
        self.assertEqual((node.owner_uid, node.gid, node.creator_uid), (1002, 1002, 1002))
        self.assertDenied(self.fs.cp, "/home/ana/priv.txt", "/home/carla/x")  # 600: nem le


if __name__ == "__main__":
    unittest.main()
