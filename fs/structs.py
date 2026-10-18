"""
(De)serializacao binaria das estruturas persistidas no disco: Superbloco,
I-node e Entrada de diretorio. Tudo empacotado com o modulo `struct` da
biblioteca padrao -- nenhum JSON/pickle e usado em nenhum lugar do projeto.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field

from fs.constants import (
    DIRENT_FORMAT,
    DIRECT_POINTERS,
    EMPTY_ENTRY,
    INODE_FORMAT,
    SUPERBLOCK_FORMAT,
    SUPERBLOCK_MAGIC,
    SUPERBLOCK_SIZE,
)


def _enc(s: str, limit: int) -> bytes:
    return s.encode("utf-8", errors="replace")[:limit]


def _dec(b: bytes) -> str:
    return b.rstrip(b"\x00").decode("utf-8", errors="replace")


@dataclass
class SuperBlock:
    block_size: int
    total_blocks: int
    num_inodes: int
    inode_size: int
    inode_bitmap_start: int
    block_bitmap_start: int
    inode_table_start: int
    data_start: int
    root_inode: int
    free_blocks: int
    free_inodes: int
    created_at: float = field(default_factory=time.time)

    def pack(self) -> bytes:
        raw = struct.pack(
            SUPERBLOCK_FORMAT,
            SUPERBLOCK_MAGIC,
            self.block_size,
            self.total_blocks,
            self.num_inodes,
            self.inode_size,
            self.inode_bitmap_start,
            self.block_bitmap_start,
            self.inode_table_start,
            self.data_start,
            self.root_inode,
            self.free_blocks,
            self.free_inodes,
            self.created_at,
        )
        return raw

    @classmethod
    def unpack(cls, data: bytes) -> "SuperBlock":
        vals = struct.unpack(SUPERBLOCK_FORMAT, data[:SUPERBLOCK_SIZE])
        magic = vals[0]
        if magic != SUPERBLOCK_MAGIC:
            raise ValueError("magic invalido: imagem de disco nao reconhecida")
        return cls(
            block_size=vals[1],
            total_blocks=vals[2],
            num_inodes=vals[3],
            inode_size=vals[4],
            inode_bitmap_start=vals[5],
            block_bitmap_start=vals[6],
            inode_table_start=vals[7],
            data_start=vals[8],
            root_inode=vals[9],
            free_blocks=vals[10],
            free_inodes=vals[11],
            created_at=vals[12],
        )


@dataclass
class Inode:
    used: int = 0
    type: int = 0
    perm: int = 0
    name: str = ""
    creator: str = ""
    owner: str = ""
    size: int = 0
    created_at: float = 0.0
    modified_at: float = 0.0
    pointers: list = field(default_factory=lambda: [0] * DIRECT_POINTERS)
    next_inode: int = -1

    def pack(self) -> bytes:
        pointers = list(self.pointers)
        if len(pointers) < DIRECT_POINTERS:
            pointers += [0] * (DIRECT_POINTERS - len(pointers))
        return struct.pack(
            INODE_FORMAT,
            self.used,
            self.type,
            self.perm,
            0,
            _enc(self.name, 32),
            _enc(self.creator, 16),
            _enc(self.owner, 16),
            self.size,
            self.created_at,
            self.modified_at,
            *pointers[:DIRECT_POINTERS],
            self.next_inode,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "Inode":
        vals = struct.unpack(INODE_FORMAT, data)
        used, type_, perm, _reserved = vals[0:4]
        name_b, creator_b, owner_b = vals[4:7]
        size, created_at, modified_at = vals[7:10]
        pointers = list(vals[10:10 + DIRECT_POINTERS])
        next_inode = vals[10 + DIRECT_POINTERS]
        return cls(
            used=used,
            type=type_,
            perm=perm,
            name=_dec(name_b),
            creator=_dec(creator_b),
            owner=_dec(owner_b),
            size=size,
            created_at=created_at,
            modified_at=modified_at,
            pointers=pointers,
            next_inode=next_inode,
        )


@dataclass
class DirEntry:
    name: str
    inode_num: int

    def pack(self) -> bytes:
        return struct.pack(DIRENT_FORMAT, _enc(self.name, 28), self.inode_num)

    @classmethod
    def unpack(cls, data: bytes) -> "DirEntry":
        name_b, inode_num = struct.unpack(DIRENT_FORMAT, data)
        return cls(name=_dec(name_b), inode_num=inode_num)

    @classmethod
    def blank(cls) -> "DirEntry":
        return cls(name="", inode_num=EMPTY_ENTRY)
