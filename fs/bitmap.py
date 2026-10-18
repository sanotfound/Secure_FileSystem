"""
Bitmap generico usado tanto para controlar i-nodes livres/ocupados quanto
blocos de dados livres/ocupados (item exigido no enunciado: "controle sobre
quais blocos/i-nodes estao livres ou ocupados").

find_free() guarda em self._cursor onde parou a ultima busca, pra nao
comecar do zero de novo a cada chamada -- isso importa quando o disco vai
enchendo aos poucos (ex.: escrevendo um arquivo grande bloco por bloco),
onde procurar sempre a partir do inicio ia ficando mais lento a cada bloco
novo alocado.
"""

from __future__ import annotations


class Bitmap:
    def __init__(self, data: bytearray, size_bits: int):
        self.data = data
        self.size_bits = size_bits
        self._cursor = 0  # ultima posicao livre encontrada; so uma dica pra busca

    def get(self, i: int) -> bool:
        return bool(self.data[i // 8] & (1 << (i % 8)))

    def set(self, i: int, value: bool) -> None:
        if value:
            self.data[i // 8] |= 1 << (i % 8)
        else:
            self.data[i // 8] &= ~(1 << (i % 8)) & 0xFF
            if i < self._cursor:
                self._cursor = i  # ficou uma posicao livre antes do cursor, aproveita

    def find_free(self, start: int = 0):
        begin = max(start, self._cursor)
        for i in range(begin, self.size_bits):
            if not self.get(i):
                self._cursor = i + 1
                return i
        # nao achou dai pra frente -- volta e tenta [start, begin), que pode
        # ter posicao livre por causa de algum free() que aconteceu antes
        for i in range(start, min(begin, self.size_bits)):
            if not self.get(i):
                self._cursor = i + 1
                return i
        return None

    def count_free(self, start: int = 0) -> int:
        return sum(1 for i in range(start, self.size_bits) if not self.get(i))
