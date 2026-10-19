"""
Permissoes de arquivos e diretorios: 2 bits (r e w) pra cada uma das tres
classes -- dono, grupo e outros -- guardados no byte `perm` do i-node (o
desenho do byte ta no constants.py).

A effective_access e a unica regra de permissao do sistema inteiro: o
kernel (filesystem.py) usa ela pra decidir tudo, e o stat usa a mesma pra
mostrar "seu acesso". Assim o que aparece na tela e exatamente o que o
kernel aplica.
"""

from __future__ import annotations

from typing import Iterable, Tuple

from fs.constants import (
    PERM_R,
    PERM_RW,
    PERM_W,
    ROOT_UID,
    SHIFT_GROUP,
    SHIFT_OTHER,
    SHIFT_OWNER,
    TYPE_DIR,
    TYPE_FILE,
    TYPE_SYMLINK,
)
from fs.structs import Inode

ROOT, OWNER, GROUP, OTHER = "root", "dono", "grupo", "outros"


def effective_access(inode: Inode, uid: int, gids: Iterable[int]) -> Tuple[str, int]:
    """Em qual classe o `uid` cai pra esse i-node, e quais bits r/w valem.

    As classes sao exclusivas, igual no Linux: a primeira que encaixar ganha
    e as outras nem sao olhadas. Ex.: num arquivo -r-rw-- do bruno com grupo
    rh, o bruno so le, mesmo estando no rh, porque ele e o dono.
    """
    if uid == ROOT_UID:
        return ROOT, PERM_RW  # root nem passa pelas permissoes
    if inode.owner_uid == uid:
        return OWNER, (inode.perm >> SHIFT_OWNER) & PERM_RW
    if inode.gid in gids:
        return GROUP, (inode.perm >> SHIFT_GROUP) & PERM_RW
    return OTHER, (inode.perm >> SHIFT_OTHER) & PERM_RW


def bits_string(bits: int) -> str:
    """Os bits de uma classe em texto: 3 vira "rw", 2 vira "r-", 0 vira "--"."""
    return ("r" if bits & PERM_R else "-") + ("w" if bits & PERM_W else "-")


def perm_string(perm: int, itype: int) -> str:
    """Formato do ls -l, so que sem a coluna do x: tipo + rw do dono, do
    grupo e dos outros. Ex.: arquivo 640 vira "-rwr---", diretorio 600 vira
    "drw----".
    """
    out = {TYPE_FILE: "-", TYPE_DIR: "d", TYPE_SYMLINK: "l"}.get(itype, "?")
    for shift in (SHIFT_OWNER, SHIFT_GROUP, SHIFT_OTHER):
        out += bits_string((perm >> shift) & PERM_RW)
    return out
