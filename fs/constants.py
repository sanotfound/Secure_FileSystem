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
INODE_FORMAT = "<BBBB32sIII20sQdd8Ii"
# used(B) type(B) perm(B) reservado(B) name(32s) owner_uid(I) gid(I)
# creator_uid(I) reservado(20s) size(Q) created_at(d) modified_at(d)
# pointers(8I) next_inode(i)
# dono e criador eram nomes de 16B cada; viraram numeros (UID/GID, igual no
# Linux) e os 20B que sobraram ficam de reserva, pra continuar com 128B
# certinhos (16 i-nodes por bloco)
INODE_SIZE = struct.calcsize(INODE_FORMAT)
assert INODE_SIZE == 128, INODE_SIZE
assert (INODE_SIZE & (INODE_SIZE - 1)) == 0, "i-node precisa ter tamanho potencia de 2"

MAX_NAME_LEN = 27  # cabe com folga em name[32] e no dirent
MAX_USER_LEN = 15  # nomes de usuario e de grupo

NUM_INODES = 8192  # da pra sobra pra qualquer teste, gasta so 1MB de tabela
INODE_TABLE_BYTES = NUM_INODES * INODE_SIZE
assert INODE_TABLE_BYTES % BLOCK_SIZE == 0
INODE_TABLE_BLOCKS = INODE_TABLE_BYTES // BLOCK_SIZE

TYPE_FILE = 0
TYPE_DIR = 1
TYPE_SYMLINK = 2

# byte de permissao: 2 bits (r e w) pra cada classe -- dono, grupo e
# outros, nessa ordem a partir do bit mais alto: 00 rw rw rw. Nao tem x:
# aqui so existe arquivo de texto, e atravessar diretorio quem controla e o r.
# Os nomes PERM_644 e cia. seguem os numeros do chmod (r=4, w=2), pra ficar
# facil de ler
PERM_R, PERM_W = 0b10, 0b01
PERM_RW = PERM_R | PERM_W
SHIFT_OWNER, SHIFT_GROUP, SHIFT_OTHER = 4, 2, 0
PERM_644 = PERM_RW << SHIFT_OWNER | PERM_R << SHIFT_GROUP | PERM_R << SHIFT_OTHER   # rwr-r-
PERM_640 = PERM_RW << SHIFT_OWNER | PERM_R << SHIFT_GROUP                           # rwr---
PERM_600 = PERM_RW << SHIFT_OWNER                                                   # rw----
PERM_666 = PERM_RW << SHIFT_OWNER | PERM_RW << SHIFT_GROUP | PERM_RW << SHIFT_OTHER  # rwrwrw
DEFAULT_FILE_PERM = PERM_640
DEFAULT_DIR_PERM = PERM_640
DEFAULT_SYMLINK_PERM = PERM_666  # so pra mostrar: no link quem vale e a permissao do alvo

# usuarios e grupos (mesmos numeros do Linux/Ubuntu)
ROOT_UID = 0
ROOT_GID = 0
SUDO_GID = 27
FIRST_ID = 1000  # UIDs/GIDs de usuarios e grupos comuns comecam aqui

# arquivos de contas -- ficam dentro do proprio sistema de arquivos, igual no Linux
PASSWD_PATH = "/etc/passwd"
SHADOW_PATH = "/etc/shadow"
GROUP_PATH = "/etc/group"
SUDOERS_PATH = "/etc/sudoers"

# hash de senha: scrypt com N=2^17, r=8, p=1 (o minimo que a OWASP
# recomenda). Cada calculo leva ~0,6 s e usa 128 MiB de memoria -- pra quem
# faz login nem da pra notar, mas pra quem tenta milhoes de senhas pesa muito
SCRYPT_LOG2_N = 17
SCRYPT_R = 8
SCRYPT_P = 1
SALT_SIZE = 16
HASH_SIZE = 32

# entrada de diretorio: nome (28B) + numero do i-node (4B) = 32B, entao
# cada bloco de 2048B guarda exatamente 64 entradas
DIRENT_FORMAT = "<28sI"
DIRENT_SIZE = struct.calcsize(DIRENT_FORMAT)
assert DIRENT_SIZE == 32
ENTRIES_PER_BLOCK = BLOCK_SIZE // DIRENT_SIZE
assert ENTRIES_PER_BLOCK * DIRENT_SIZE == BLOCK_SIZE
EMPTY_ENTRY = 0xFFFFFFFF  # marca slot de diretorio livre

SUPERBLOCK_MAGIC = b"SOF2"      # versao com usuarios e permissoes
OLD_SUPERBLOCK_MAGIC = b"SOFS"  # versao antiga, sem usuarios: so serve pra reconhecer e recusar
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
