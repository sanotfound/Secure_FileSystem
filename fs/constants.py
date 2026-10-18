# Constantes e layout do disco.
#
# O disco e um arquivo binario de exatamente 128 MiB, dividido em blocos de
# 2048B. Bloco 0 e o superbloco, bloco 1 e o bitmap de i-nodes, blocos 2-5
# sao o bitmap de blocos, blocos 6-517 sao a tabela de i-nodes, e o resto
# (518 em diante) e a area de dados. As contas estao todas abaixo, com
# assert pra garantir que fecha certinho em 128MB (ver README pra mais
# detalhe de como cheguei nesses numeros).

import struct

DISK_SIZE = 128 * 1024 * 1024
BLOCK_SIZE = 2048
TOTAL_BLOCKS = DISK_SIZE // BLOCK_SIZE
assert TOTAL_BLOCKS * BLOCK_SIZE == DISK_SIZE

# i-node de tamanho fixo, potencia de 2 (128B). 8 ponteiros diretos cobrem
# 16KB por i-node; passou disso, encadeia em outro i-node via next_inode.
DIRECT_POINTERS = 8
INODE_FORMAT = "<BBBB32s16s16sQdd8Ii"
# used(B) type(B) perm(B) reservado(B) name(32s) creator(16s) owner(16s)
# size(Q) created_at(d) modified_at(d) pointers(8I) next_inode(i)
INODE_SIZE = struct.calcsize(INODE_FORMAT)
assert INODE_SIZE == 128, INODE_SIZE
assert (INODE_SIZE & (INODE_SIZE - 1)) == 0, "i-node precisa ter tamanho potencia de 2"

MAX_NAME_LEN = 27  # cabe com folga em name[32] e no dirent
MAX_USER_LEN = 15

NUM_INODES = 8192  # da pra sobra pra qualquer teste, gasta so 1MB de tabela
INODE_TABLE_BYTES = NUM_INODES * INODE_SIZE
assert INODE_TABLE_BYTES % BLOCK_SIZE == 0
INODE_TABLE_BLOCKS = INODE_TABLE_BYTES // BLOCK_SIZE

TYPE_FILE = 0
TYPE_DIR = 1
TYPE_SYMLINK = 2

# byte de permissao: 3 bits dono (rwx) + 3 bits outros (rwx)
PERM_R, PERM_W, PERM_X = 0b100, 0b010, 0b001
DEFAULT_FILE_PERM = (PERM_R | PERM_W) << 3 | PERM_R                     # rw-r--
DEFAULT_DIR_PERM = (PERM_R | PERM_W | PERM_X) << 3 | (PERM_R | PERM_X)  # rwxr-x
DEFAULT_SYMLINK_PERM = (PERM_R | PERM_W | PERM_X) << 3 | (PERM_R | PERM_W | PERM_X)

# entrada de diretorio: nome (28B) + numero do i-node (4B) = 32B, entao
# cada bloco de 2048B guarda exatamente 64 entradas
DIRENT_FORMAT = "<28sI"
DIRENT_SIZE = struct.calcsize(DIRENT_FORMAT)
assert DIRENT_SIZE == 32
ENTRIES_PER_BLOCK = BLOCK_SIZE // DIRENT_SIZE
assert ENTRIES_PER_BLOCK * DIRENT_SIZE == BLOCK_SIZE
EMPTY_ENTRY = 0xFFFFFFFF  # marca slot de diretorio livre

SUPERBLOCK_MAGIC = b"SOFS"
SUPERBLOCK_FORMAT = "<4s11Id"
SUPERBLOCK_SIZE = struct.calcsize(SUPERBLOCK_FORMAT)
assert SUPERBLOCK_SIZE <= BLOCK_SIZE

# layout final em blocos
SUPERBLOCK_START = 0
SUPERBLOCK_BLOCKS = 1

INODE_BITMAP_START = SUPERBLOCK_START + SUPERBLOCK_BLOCKS  # bloco 1
INODE_BITMAP_BYTES = (NUM_INODES + 7) // 8
INODE_BITMAP_BLOCKS = (INODE_BITMAP_BYTES + BLOCK_SIZE - 1) // BLOCK_SIZE

BLOCK_BITMAP_START = INODE_BITMAP_START + INODE_BITMAP_BLOCKS  # bloco 2
BLOCK_BITMAP_BYTES = (TOTAL_BLOCKS + 7) // 8
BLOCK_BITMAP_BLOCKS = (BLOCK_BITMAP_BYTES + BLOCK_SIZE - 1) // BLOCK_SIZE

INODE_TABLE_START = BLOCK_BITMAP_START + BLOCK_BITMAP_BLOCKS  # bloco 6, termina no 517

DATA_START = INODE_TABLE_START + INODE_TABLE_BLOCKS  # bloco 518 em diante
DATA_BLOCKS = TOTAL_BLOCKS - DATA_START
assert DATA_BLOCKS > 0

ROOT_INODE = 0
RESERVED_BLOCKS = DATA_START
