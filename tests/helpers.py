"""
O que todos os testes usam: disco temporario, scrypt barato e o shell
rodando de verdade.

Dois truques pra suite nao demorar minutos:

- scrypt barato: com os parametros reais cada senha custa ~0,6 s, e os
  testes criam e conferem dezenas delas. Entao, durante os testes, o N cai
  pra 2^10 (troca temporaria com unittest.mock, o codigo do sistema nao
  muda). Como os parametros vao gravados junto com cada hash, a verificacao
  continua certinha. O test_passwords tem um teste que confere os
  parametros reais.

- disco-modelo: criar um disco de 128 MB leva ~0,5 s. Em vez de criar um
  por teste, a gente monta UM disco-modelo por execucao (formatado e ja com
  os usuarios ana, bruno e carla) e cada teste ganha uma copia so dele.
  Assim um teste nunca atrapalha o outro.
"""

from __future__ import annotations

import atexit
import itertools
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Callable, List, Optional
from unittest import mock

from fs.constants import ROOT_GID, ROOT_UID
from fs.errors import FSError
from fs.filesystem import FileSystem
from fs.structs import Inode

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_PY = os.path.join(PROJECT_ROOT, "main.py")

FAST_LOG2_N = 10
ROOT_PASSWORD = "root123"
USER_PASSWORDS = {"ana": "ana123", "bruno": "bruno123", "carla": "carla123"}
# no disco-modelo: ana 1000, bruno 1001, carla 1002 (e o grupo proprio de
# cada um tem o mesmo numero)

_tmp_dir = tempfile.mkdtemp(prefix="sofs-testes-")
atexit.register(shutil.rmtree, _tmp_dir, ignore_errors=True)
_template: Optional[str] = None
_counter = itertools.count()


def fast_scrypt():
    """Troca temporaria do custo do scrypt (ver explicacao la em cima)."""
    return mock.patch("fs.passwords.SCRYPT_LOG2_N", FAST_LOG2_N)


def temp_path(name: str) -> str:
    """Um caminho novo dentro da pasta temporaria dos testes."""
    return os.path.join(_tmp_dir, f"{next(_counter)}-{name}")


def new_disk_copy() -> str:
    """Copia do disco-modelo, so pra quem pediu. O modelo e montado na
    primeira vez que alguem pede."""
    global _template
    if _template is None:
        path = os.path.join(_tmp_dir, "modelo.img")
        with fast_scrypt():
            fs = FileSystem(path, root_password=ROOT_PASSWORD)
            for name, password in USER_PASSWORDS.items():
                fs.accounts.useradd(name, password)
            fs.close()
        _template = path
    path = temp_path("disco.img")
    shutil.copyfile(_template, path)
    return path


def run_shell(disk: str, lines: List[str], timeout: int = 120) -> subprocess.CompletedProcess:
    """Roda o main.py de verdade, mandando as linhas como se alguem tivesse
    digitado. Como a entrada nao e um terminal, as senhas tambem vem dessas
    linhas (ver _ask_password no shell)."""
    return subprocess.run(
        [sys.executable, MAIN_PY, "--disk", disk],
        input="\n".join(lines) + "\n", capture_output=True, text=True,
        encoding="utf-8", timeout=timeout, cwd=PROJECT_ROOT,
    )


class InOrderMixin:
    def assertInOrder(self, text: str, parts: List[str]) -> None:
        """Confere que cada trecho aparece no texto, um depois do outro."""
        pos = 0
        for part in parts:
            idx = text.find(part, pos)
            if idx < 0:
                self.fail(f"nao achei {part!r} (depois da posicao {pos}) na saida:\n{text}")
            pos = idx + len(part)


class FSTestCase(InOrderMixin, unittest.TestCase):
    """Base dos testes do kernel: cada teste ganha uma copia do disco-modelo
    so pra ele e comeca como root."""

    def setUp(self) -> None:
        patcher = fast_scrypt()
        patcher.start()
        self.addCleanup(patcher.stop)
        self.disk = new_disk_copy()
        self.fs = FileSystem(self.disk)
        self.acc = self.fs.accounts
        self.addCleanup(self._close_and_remove)

    def _close_and_remove(self) -> None:
        try:
            self.fs.close()
        except ValueError:
            pass  # ja tava fechado
        os.remove(self.disk)

    # ---- trocar de usuario sem passar senha (o login e testado a parte) ----

    def become(self, name: str) -> None:
        user = self.acc.get_user(name)
        self.fs.set_credentials(user.uid, user.gid)

    def become_root(self) -> None:
        self.fs.set_credentials(ROOT_UID, ROOT_GID)

    # ---- atalhos ----

    def inode_of(self, path: str, follow_symlink: bool = True) -> Inode:
        """Le o i-node como root, pra olhar qualquer coisa sem esbarrar em permissao."""
        with self.fs.as_root():
            return self.fs.read_inode(self.fs.resolve(path, follow_symlink=follow_symlink))

    def read_as_root(self, path: str) -> bytes:
        with self.fs.as_root():
            return self.fs.read_file(path)

    def remount(self) -> None:
        """Desmonta e monta o disco de novo (pra testar persistencia)."""
        self.fs.close()
        self.fs = FileSystem(self.disk)
        self.acc = self.fs.accounts

    def assertDenied(self, fn: Callable, *args, message: str = "Permissão negada") -> FSError:
        """Confere que a operacao falhou com essa mensagem."""
        with self.assertRaises(FSError) as cm:
            fn(*args)
        self.assertIn(message, str(cm.exception))
        return cm.exception

    def assertNotPermitted(self, fn: Callable, *args) -> FSError:
        return self.assertDenied(fn, *args, message="Operação não permitida")
