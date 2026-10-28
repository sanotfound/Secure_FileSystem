"""
Permissoes de arquivos e diretorios: 2 bits (r e w) pra cada uma das tres
classes -- dono, grupo e outros -- guardados no byte `perm` do i-node (o
desenho do byte ta no constants.py).

A effective_access e a unica regra de permissao do sistema inteiro: o
kernel (filesystem.py) usa ela pra decidir tudo, e o stat usa a mesma pra
mostrar "seu acesso". Assim o que aparece na tela e exatamente o que o
kernel aplica.

O parse_mode le o modo do chmod (640, u+w, o-r...) e devolve o byte novo.
"""

from __future__ import annotations

import re
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
from fs.errors import FSError
from fs.structs import Inode

ROOT, OWNER, GROUP, OTHER = "root", "dono", "grupo", "outros"

# letras do chmod simbolico: quem (u/g/o/a) -> em quais classes mexe, e
# quais bits cada letra de permissao liga
WHO_SHIFTS = {
    "u": (SHIFT_OWNER,),
    "g": (SHIFT_GROUP,),
    "o": (SHIFT_OTHER,),
    "a": (SHIFT_OWNER, SHIFT_GROUP, SHIFT_OTHER),
}
LETTER_BITS = {"r": PERM_R, "w": PERM_W}
# uma clausula: quem (pode ser vazio = todos), a operacao e as letras. O x
# entra na regex so pra gente conseguir dar uma mensagem clara recusando ele
CLAUSE_RE = re.compile(r"([ugoa]*)([+=-])([rwx]*)")
ALL_PERM_BITS = PERM_RW << SHIFT_OWNER | PERM_RW << SHIFT_GROUP | PERM_RW << SHIFT_OTHER


# A REGRA de permissão do sistema inteiro. Responde: 'pra esse arquivo, essa
# pessoa conta como root, dono, grupo ou outros? E o q ela pode fazer: ler (r),
# escrever (w), os dois ou nada?'. Td checagem de leitura/escrita termina aqui.
def effective_access(inode: Inode, uid: int, gids: Iterable[int]) -> Tuple[str, int]:
    """Em qual classe o `uid` cai pra esse i-node, e quais bits r/w valem.

    As classes sao exclusivas, igual no Linux: a primeira que encaixar ganha
    e as outras nem sao olhadas. Ex.: num arquivo -r-rw-- do bruno com grupo
    rh, o bruno so le, mesmo estando no rh, porque ele e o dono.
    """
    # 1º: é o root (uid 0)? Pode td, nem olha as permissões.
    if uid == ROOT_UID:
        return ROOT, PERM_RW  # root nem passa pelas permissoes
    # 2º: é o dono do arquivo? Valem só os 2 bits do dono. O '>> SHIFT_OWNER'
    # empurra os bits do dono pro final do byte e o '& PERM_RW' apaga o resto.
    if inode.owner_uid == uid:
        return OWNER, (inode.perm >> SHIFT_OWNER) & PERM_RW
    # 3º: tá no grupo do arquivo? Valem só os bits do grupo. Se a pessoa já
    # caiu como dono lá em cima, nem chega aqui (classes exclusivas, igual
    # Linux).
    if inode.gid in gids:
        return GROUP, (inode.perm >> SHIFT_GROUP) & PERM_RW
    # 4º: ñ é nada disso -> vale o q foi liberado pros 'outros'.
    return OTHER, (inode.perm >> SHIFT_OTHER) & PERM_RW


# Transforma os 2 bits de uma classe em texto: 11 -> 'rw', 10 -> 'r-', 00 ->
# '--'. Só p/ exibir.
def bits_string(bits: int) -> str:
    """Os bits de uma classe em texto: 3 vira "rw", 2 vira "r-", 0 vira "--"."""
    return ("r" if bits & PERM_R else "-") + ("w" if bits & PERM_W else "-")


# Monta o texto de permissão do ls -l, tipo '-rwr---'.
def perm_string(perm: int, itype: int) -> str:
    """Formato do ls -l, so que sem a coluna do x: tipo + rw do dono, do
    grupo e dos outros. Ex.: arquivo 640 vira "-rwr---", diretorio 600 vira
    "drw----".
    """
    # 1ª letra: o tipo (- arquivo, d diretório, l link).
    out = {TYPE_FILE: "-", TYPE_DIR: "d", TYPE_SYMLINK: "l"}.get(itype, "?")
    # Depois 2 letras p/ cada classe: dono, grupo e outros. Ex.: 640 vira
    # -rwr---.
    for shift in (SHIFT_OWNER, SHIFT_GROUP, SHIFT_OTHER):
        out += bits_string((perm >> shift) & PERM_RW)
    return out


# Porta de entrada do chmod: recebe o q a pessoa digitou (640 ou u+w) e devolve
# o byte novo de permissão.
def parse_mode(mode: str, current: int) -> int:
    """Le o modo do chmod e devolve o byte de permissao novo.

    Numerico (640) define tudo de uma vez. Simbolico (u+w, o-r...) mexe so
    no que foi pedido, por isso precisa saber a permissao atual (`current`).
    """
    # Só números (640) -> modo numérico, q define td de uma vez. Senão (u+w) ->
    # modo simbólico, q mexe só no q foi pedido.
    if mode.isdigit():
        return _numeric_mode(mode)
    return _symbolic_mode(mode, current)


# Lê o modo em números, tipo 640. São 3 dígitos: o 1º é do dono, o 2º do grupo
# e o 3º dos outros. Cada dígito é a soma de r=4 e w=2, então 6 = ler e
# escrever, 4 = só ler, 0 = nada.
def _numeric_mode(mode: str) -> int:
    # 3 digitos: dono, grupo, outros. Cada um e a soma de r=4 e w=2, igual
    # no Linux, entao so pode ser 0, 2, 4 ou 6. Ex.: 640 -> rw r- --
    # Tem q ser exatamente 3 dígitos.
    if len(mode) != 3:
        raise FSError(f"chmod: modo '{mode}' inválido (use 3 dígitos: dono, grupo e outros, ex.: 640)")
    perm = 0
    for digit, shift in zip(mode, (SHIFT_OWNER, SHIFT_GROUP, SHIFT_OTHER)):
        d = int(digit)
        if d > 7:
            raise FSError(f"chmod: modo '{mode}' inválido (cada dígito vai de 0 a 7)")
        # Dígito ímpar (1, 3, 5, 7) teria o x do Linux (executar), q aqui ñ
        # existe -> recusa.
        if d & 1:
            # o 1 do Linux e o x, que aqui nao existe (so tem arquivo de texto)
            raise FSError(f"chmod: modo '{mode}': aqui não existe x, use 0, 2, 4 ou 6 em cada dígito")
        # d >> 1 transforma o digito (r=4, w=2) nos nossos 2 bits (r=10,
        # w=01): 6 -> 11 (rw), 4 -> 10 (r), 2 -> 01 (w), 0 -> 00
        # O '<< shift' coloca os 2 bits na posição da classe certa (dono, grupo
        # ou outros) dentro do byte.
        perm |= (d >> 1) << shift
    return perm


# Lê o modo em letras: u (dono), g (grupo), o (outros), a (todos); + (dar), -
# (tirar), = (deixar exatamente assim); r (ler), w (escrever). Ex.: 'o-r' =
# tira a leitura dos outros. Mexe só no q foi pedido, o resto continua igual.
def _symbolic_mode(mode: str, current: int) -> int:
    # ex.: "u=rw,g=r,o=" -> cada pedaco separado por virgula e aplicado em
    # cima do resultado do anterior, comecando da permissao atual
    # Começa da permissão q o arquivo já tem.
    perm = current
    # Dá pra pedir várias mudanças separadas por vírgula (u=rw,o=); aplica uma
    # de cada vez.
    for clause in mode.split(","):
        # Separa o pedaço em: quem, operação e letras. Se ñ seguir esse
        # formato, é modo inválido.
        m = CLAUSE_RE.fullmatch(clause)
        if not m:
            raise FSError(f"chmod: modo '{mode}' inválido (ex.: 640, u+w, o-r, g=r, u=rw,o=)")
        who, op, letters = m.groups()
        if "x" in letters:
            raise FSError(f"chmod: modo '{mode}': aqui não existe x (só r e w)")
        bits = 0
        for letter in letters:
            bits |= LETTER_BITS[letter]
        shifts = set()
        for who_letter in who or "a":  # sem dizer quem, vale pra todo mundo
            shifts.update(WHO_SHIFTS[who_letter])
        for shift in shifts:
            # + liga os bits pedidos, - desliga, = zera a classe e liga só os
            # pedidos.
            if op == "+":
                perm |= bits << shift  # liga os bits pedidos
            elif op == "-":
                perm &= ~(bits << shift)  # desliga os bits pedidos
            else:
                # "=" deixa a classe exatamente com essas letras: zera os 2
                # bits dela e liga so os pedidos ("o=" sozinho tira tudo)
                perm = (perm & ~(PERM_RW << shift)) | (bits << shift)
    # Garante q só os 6 bits de permissão fiquem ligados no final.
    return perm & ALL_PERM_BITS
