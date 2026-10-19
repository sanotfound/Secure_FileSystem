"""O programa de verdade: o main.py rodando com uma lista de comandos."""

import contextlib
import io
import os
import unittest
from unittest import mock

import fs.shell as shell_module
from fs.filesystem import FileSystem
from tests.helpers import InOrderMixin, fast_scrypt, new_disk_copy, run_shell, temp_path


class ShellTest(InOrderMixin, unittest.TestCase):
    # aqui o main.py roda num processo separado, com o scrypt de verdade; os
    # usuarios do disco-modelo tem hash barato, entao o login deles e rapido

    def setUp(self):
        self.disk = new_disk_copy()
        self.addCleanup(os.remove, self.disk)

    def test_first_run_creates_and_formats_the_disk(self):
        """primeira execucao: cria o disco, pede a senha do root e ja da pra entrar"""
        path = temp_path("primeiro.img")
        result = run_shell(path, ["r1", "r1", "root", "r1", "whoami", "ls /", "exit"])
        self.addCleanup(os.remove, path)
        self.assertEqual(result.returncode, 0)
        self.assertInOrder(result.stdout, [
            "Nenhum disco", "Defina a senha do administrador (root).",
            "Disco criado e formatado", "root@sofs:~# root", "etc  home  root", "Disco desmontado",
        ])

    def test_three_wrong_logins_close_the_program(self):
        """3 logins errados (sempre a mesma mensagem) e o programa fecha"""
        result = run_shell(self.disk, ["ana", "x", "bruno", "y", "carla", "z"])
        self.assertEqual(result.returncode, 0)
        self.assertInOrder(result.stdout, ["Login incorreto.", "Login incorreto.", "Login incorreto.",
                                           "Número máximo de tentativas atingido."])

    def test_readme_example_session(self):
        """a sessao de exemplo do README funciona como esta escrita la"""
        path = temp_path("readme.img")
        result = run_shell(path, [
            "root123", "root123", "root", "root123",
            "useradd ana", "ana123", "ana123",
            "usermod -aG sudo ana",
            "su ana", "cd",
            'echo "minhas notas" > notas.txt',
            "ls -l",
            "cat /etc/shadow",
            "sudo cat /etc/shadow", "ana123",
            "exit",
        ])
        self.addCleanup(os.remove, path)
        self.assertInOrder(result.stdout, [
            "root@sofs:~# ", "ana@sofs:/root$ ", "ana@sofs:~$ ",
            "-rwr---  ana        ana                13", "notas.txt",
            "erro: /etc/shadow: Permissão negada",
            "[sudo] senha para ana: root:scrypt$17$8$1$", "ana:scrypt$17$8$1$",
        ])

    def test_prompt_tilde_and_ls(self):
        """prompt com ~, caminho com ~, ls so com nomes e ls -l completo"""
        result = run_shell(self.disk, ["ana", "ana123", "echo oi > ~/a.txt", "cat ~/a.txt",
                                       "ls", "ls -l", "pwd", "exit"])
        self.assertInOrder(result.stdout, ["ana@sofs:~$ ", "oi", "a.txt", "-rwr---  ana        ana", "/home/ana"])

    def test_denied_and_not_permitted_messages(self):
        """usuario comum ve 'Permissao negada' e 'Operacao nao permitida'; o root le o shadow"""
        result = run_shell(self.disk, [
            "ana", "ana123", "cat /etc/shadow", "chmod 666 /etc/shadow", "stat /etc/shadow", "logout",
            "root", "root123", "cat /etc/shadow", "exit",
        ])
        self.assertInOrder(result.stdout, [
            "erro: /etc/shadow: Permissão negada",
            "erro: chmod: /etc/shadow: Operação não permitida",
            "seu acesso:    --  (você não é o dono nem está no grupo: vale 'outros')",
            "root@sofs:~# ", "root:scrypt$",
        ])

    def test_help_lists_the_security_commands(self):
        """o help mostra os comandos de usuarios, permissoes, grupos e sudo"""
        result = run_shell(self.disk, ["ana", "ana123", "help", "exit"])
        for cmd in ("useradd", "passwd", "su [usuário]", "chmod", "chown", "chgrp",
                    "groupadd", "usermod -aG", "gpasswd -d", "sudo"):
            with self.subTest(comando=cmd):
                self.assertIn(cmd, result.stdout)

    def test_old_disk_is_refused(self):
        """disco da versao antiga: mensagem explicando e codigo de saida 1"""
        path = temp_path("antigo.img")
        with open(path, "wb") as f:
            f.write(b"SOFS" + bytes(2044))
        self.addCleanup(os.remove, path)
        result = run_shell(path, [])
        self.assertEqual(result.returncode, 1)
        self.assertIn("formato antigo", result.stdout)


class InterruptTest(InOrderMixin, unittest.TestCase):
    # Ctrl+C nao da pra mandar pelo subprocess, entao aqui o shell roda no
    # proprio processo com o input trocado por uma lista que "aperta" Ctrl+C

    def test_ctrl_c_and_end_of_input_in_the_middle_of_commands(self):
        """Ctrl+C no meio de um comando cancela so ele (e o sudo devolve as credenciais); fim da entrada fecha limpo"""
        patcher = fast_scrypt()
        patcher.start()
        self.addCleanup(patcher.stop)
        disk = new_disk_copy()
        self.addCleanup(os.remove, disk)
        fs = FileSystem(disk)
        fs.accounts.add_to_groups("ana", ["sudo"])
        fs.close()

        ctrl_c, end = object(), object()
        inputs = iter([
            "ana", "ana123",
            "sudo whoami", ctrl_c,              # Ctrl+C pedindo a senha do sudo
            "whoami",
            "sudo useradd zed", "ana123", ctrl_c,  # Ctrl+C ja como root, no meio do useradd
            "whoami",
            "cat /etc/shadow",
            "passwd", end,                      # a entrada acaba pedindo a senha atual
        ])

        def fake_input(prompt=""):
            value = next(inputs)
            if value is ctrl_c:
                raise KeyboardInterrupt
            if value is end:
                raise EOFError
            return value

        out = io.StringIO()
        with mock.patch("builtins.input", fake_input), \
                mock.patch.object(shell_module, "_ask_password", fake_input), \
                contextlib.redirect_stdout(out):
            shell_module.Shell(disk).run()

        self.assertInOrder(out.getvalue(), [
            "cancelado.", "ana\n",                       # continua sendo a ana
            "cancelado.", "ana\n",                       # o sudo devolveu as credenciais
            "erro: /etc/shadow: Permissão negada",
            "Disco desmontado",
        ])
        fs = FileSystem(disk)
        self.assertNotIn("zed", fs.accounts.users)  # o useradd interrompido nao deixou nada
        fs.close()


if __name__ == "__main__":
    unittest.main()
