"""
Camada mais baixa: le/escreve blocos de tamanho fixo em um arquivo que
representa o disco inteiro (128 MB). Nenhuma outra parte do sistema acessa
o arquivo de disco diretamente -- tudo passa por aqui.
"""

from __future__ import annotations

import os

from fs.constants import BLOCK_SIZE, DISK_SIZE, TOTAL_BLOCKS


class Disk:
    def __init__(self, path: str):
        self.path = path
        self._file = open(path, "r+b")

    @staticmethod
    def exists(path: str) -> bool:
        return os.path.exists(path)

    @staticmethod
    def create(path: str) -> None:
        """Cria o arquivo de disco com exatamente DISK_SIZE bytes, todos zero."""
        chunk = b"\x00" * BLOCK_SIZE
        with open(path, "wb") as f:
            for _ in range(TOTAL_BLOCKS):
                f.write(chunk)
        assert os.path.getsize(path) == DISK_SIZE

    def read_block(self, index: int) -> bytes:
        if not (0 <= index < TOTAL_BLOCKS):
            raise IndexError(f"bloco {index} fora do disco")
        self._file.seek(index * BLOCK_SIZE)
        data = self._file.read(BLOCK_SIZE)
        if len(data) < BLOCK_SIZE:
            data = data + b"\x00" * (BLOCK_SIZE - len(data))
        return data

    def write_block(self, index: int, data: bytes) -> None:
        if not (0 <= index < TOTAL_BLOCKS):
            raise IndexError(f"bloco {index} fora do disco")
        if len(data) != BLOCK_SIZE:
            raise ValueError("bloco deve ter exatamente BLOCK_SIZE bytes")
        self._file.seek(index * BLOCK_SIZE)
        self._file.write(data)

    def flush(self) -> None:
        self._file.flush()
        os.fsync(self._file.fileno())

    def close(self) -> None:
        self.flush()
        self._file.close()
