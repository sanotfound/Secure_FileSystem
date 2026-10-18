"""
Permissoes de arquivos e diretorios: 2 bits (r, w) para cada uma das tres
classes -- dono, grupo e outros -- guardados no byte `perm` do i-node (ver
constants.py).
"""

from __future__ import annotations

from fs.constants import (
    PERM_R,
    PERM_RW,
    PERM_W,
    SHIFT_GROUP,
    SHIFT_OTHER,
    SHIFT_OWNER,
    TYPE_DIR,
    TYPE_FILE,
    TYPE_SYMLINK,
)


def perm_string(perm: int, itype: int) -> str:
    """Formato do ls -l, sem a coluna do x: tipo + rw do dono, do grupo e
    dos outros. Ex.: arquivo 640 -> "-rwr---", diretorio 600 -> "drw----".
    """
    out = {TYPE_FILE: "-", TYPE_DIR: "d", TYPE_SYMLINK: "l"}.get(itype, "?")
    for shift in (SHIFT_OWNER, SHIFT_GROUP, SHIFT_OTHER):
        bits = (perm >> shift) & PERM_RW
        out += ("r" if bits & PERM_R else "-") + ("w" if bits & PERM_W else "-")
    return out
