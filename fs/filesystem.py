# Logica do sistema de arquivos: alocacao de blocos/i-nodes, leitura e
# escrita de conteudo, diretorios, links simbolicos e resolucao de
# caminhos absolutos/relativos.
#
# Essa classe faz o papel do kernel: sabe quem ta usando o sistema agora
# (self.uid/self.gid, tipo as credenciais de um processo no Linux), carimba
# dono, grupo e permissoes em todo i-node que nasce e confere r/w antes de
# cada operacao (_require). As contas de usuarios e grupos ficam no
# accounts.py, e a regra de permissao em si no permissions.py.
#
# As checagens ficam nas operacoes "de fora" (touch, read_file, mkdir...) e
# na resolucao de caminhos. As funcoes de baixo nivel (read_data,
# write_data, add_dir_entry...) nao conferem nada de proposito: elas sao o
# miolo do kernel e so rodam depois que a operacao ja foi liberada.

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Dict, Iterator, List, Optional, Tuple

from fs.accounts import Accounts
from fs.bitmap import Bitmap
from fs.constants import (
    BLOCK_BITMAP_BLOCKS,
    BLOCK_BITMAP_START,
    BLOCK_SIZE,
    DATA_BLOCKS,
    DATA_START,
    DEFAULT_DIR_PERM,
    DEFAULT_FILE_PERM,
    DEFAULT_SYMLINK_PERM,
    DIRECT_POINTERS,
    DIRENT_SIZE,
    EMPTY_ENTRY,
    ENTRIES_PER_BLOCK,
    INODE_BITMAP_BLOCKS,
    INODE_BITMAP_START,
    INODE_SIZE,
    INODE_TABLE_START,
    MAX_NAME_LEN,
    NUM_INODES,
    OLD_SUPERBLOCK_MAGIC,
    PERM_600,
    PERM_644,
    PERM_R,
    PERM_RW,
    PERM_W,
    RESERVED_BLOCKS,
    ROOT_GID,
    ROOT_INODE,
    ROOT_UID,
    TOTAL_BLOCKS,
    TYPE_DIR,
    TYPE_FILE,
    TYPE_SYMLINK,
)
from fs.disk import Disk
from fs.errors import FSError
from fs.permissions import effective_access, parse_mode
from fs.structs import DirEntry, Inode, SuperBlock

# o que a formatacao cria alem da raiz (que e 644): /etc e /home todo mundo
# le e atravessa, mas so o root cria coisa dentro; /root e a home do root,
# fechada igual a dos outros usuarios
INITIAL_DIRS = (("/etc", PERM_644), ("/home", PERM_644), ("/root", PERM_600))


class FileSystem:
    def __init__(self, path: str, root_password: Optional[str] = None):
        """Monta o disco que ta em `path`. Se o arquivo nao existir, cria e
        formata um disco novo -- e pra isso precisa da senha do root."""
        self.path = path

        # credenciais de quem ta usando o sistema agora. Comeca como root so
        # pra montar/formatar; depois o login troca pro usuario que entrou
        self.uid = ROOT_UID
        self.gid = ROOT_GID
        self.cred_changes = 0  # quantas vezes o usuario foi trocado (ver Accounts.sudo)
        self.accounts = Accounts(self)
        # a formatacao ja cria diretorios e a montagem ja le o /etc, e os dois
        # resolvem caminhos -- que precisam de um diretorio atual pra comecar
        self.cwd_inode = ROOT_INODE

        # cache em memoria do conteudo de diretorios ja lidos nesta sessao:
        # dir_inode -> {nome: (i-node, bloco, slot)}, mais a lista de slots
        # livres de cada um. Evita reler o diretorio inteiro do disco toda
        # vez que precisa achar/checar um nome (ver _load_dir_cache). Como
        # so a gente mesmo escreve no disco.img, da pra manter isso
        # sincronizado com toda escrita sem se preocupar com outro processo
        # mexendo por baixo.
        self._dir_cache: Dict[int, Dict[str, Tuple[int, int, int]]] = {}
        self._dir_free_slots: Dict[int, List[Tuple[int, int]]] = {}

        if not Disk.exists(path):
            if root_password is None:
                raise FSError(f"'{path}' não existe e nenhuma senha de root foi dada para formatar")
            Accounts.check_password(root_password)  # confere antes de criar os 128 MB, pra nao sobrar disco pela metade
            Disk.create(path)
            self.disk = Disk(path)
            self._mkfs(root_password)
        else:
            self.disk = Disk(path)
            try:
                self._mount()
            except FSError:
                self.disk.close()  # nao deixa o arquivo preso (no Windows nao daria pra renomear)
                raise
            self.accounts.load()

        self.cwd_inode = self.sb.root_inode

    def _mkfs(self, root_password: str) -> None:
        self.sb = SuperBlock(
            block_size=BLOCK_SIZE,
            total_blocks=TOTAL_BLOCKS,
            num_inodes=NUM_INODES,
            inode_size=INODE_SIZE,
            inode_bitmap_start=INODE_BITMAP_START,
            block_bitmap_start=BLOCK_BITMAP_START,
            inode_table_start=INODE_TABLE_START,
            data_start=DATA_START,
            root_inode=ROOT_INODE,
            free_blocks=DATA_BLOCKS,
            free_inodes=NUM_INODES,
        )

        self.inode_bitmap = Bitmap(bytearray(INODE_BITMAP_BLOCKS * BLOCK_SIZE), NUM_INODES)
        self.block_bitmap = Bitmap(bytearray(BLOCK_BITMAP_BLOCKS * BLOCK_SIZE), TOTAL_BLOCKS)
        for b in range(RESERVED_BLOCKS):
            self.block_bitmap.set(b, True)

        # zera toda a tabela de i-nodes
        blank_inode_block = bytes(BLOCK_SIZE)
        for b in range(INODE_TABLE_START, INODE_TABLE_START + (NUM_INODES * INODE_SIZE) // BLOCK_SIZE):
            self.disk.write_block(b, blank_inode_block)

        self._save_superblock()
        self._save_inode_bitmap()
        self._save_block_bitmap()

        # cria o diretorio raiz (i-node 0)
        root_num = self.alloc_inode()
        assert root_num == ROOT_INODE
        now = time.time()
        root = Inode(
            used=1, type=TYPE_DIR, perm=PERM_644,
            name="/", owner_uid=ROOT_UID, gid=ROOT_GID, creator_uid=ROOT_UID,
            size=0, created_at=now, modified_at=now,
        )
        self.write_inode(root_num, root)
        self.add_dir_entry(root_num, ".", root_num, _validate=False)
        self.add_dir_entry(root_num, "..", root_num, _validate=False)

        # o resto nasce como root (aqui o self.uid/gid ainda sao do root)
        for dir_path, perm in INITIAL_DIRS:
            self.set_attrs(self.mkdir(dir_path), perm=perm)
        self.accounts.initialize(root_password)
        self.disk.flush()

    # Monta (abre) um disco q já existe.
    def _mount(self) -> None:
        sb_block = self.disk.read_block(0)
        # Lê a 'assinatura' gravada no começo do disco. SOFS = formato antigo,
        # sem usuários nem permissões: recusa em vez de montar, pq ali os
        # arquivos ñ têm dono.
        if sb_block[:len(OLD_SUPERBLOCK_MAGIC)] == OLD_SUPERBLOCK_MAGIC:
            raise FSError(
                f"'{self.path}' está no formato antigo (sem usuários e permissões) e não "
                "pode ser montado. Renomeie ou apague esse arquivo para criar um disco novo."
            )
        try:
            self.sb = SuperBlock.unpack(sb_block)
        except ValueError as exc:
            raise FSError(f"imagem de disco invalida ou corrompida: {exc}") from exc

        expected = {
            "block_size": BLOCK_SIZE,
            "total_blocks": TOTAL_BLOCKS,
            "num_inodes": NUM_INODES,
            "inode_size": INODE_SIZE,
            "inode_bitmap_start": INODE_BITMAP_START,
            "block_bitmap_start": BLOCK_BITMAP_START,
            "inode_table_start": INODE_TABLE_START,
            "data_start": DATA_START,
            "root_inode": ROOT_INODE,
        }
        for field_name, expected_value in expected.items():
            if getattr(self.sb, field_name) != expected_value:
                raise FSError(
                    f"imagem incompatível: {field_name}={getattr(self.sb, field_name)} "
                    f"(esperado {expected_value})"
                )

        ib = bytearray()
        for i in range(INODE_BITMAP_BLOCKS):
            ib += self.disk.read_block(self.sb.inode_bitmap_start + i)
        self.inode_bitmap = Bitmap(ib, self.sb.num_inodes)

        bb = bytearray()
        for i in range(BLOCK_BITMAP_BLOCKS):
            bb += self.disk.read_block(self.sb.block_bitmap_start + i)
        self.block_bitmap = Bitmap(bb, self.sb.total_blocks)

    def _save_superblock(self) -> None:
        raw = self.sb.pack()
        raw = raw + b"\x00" * (BLOCK_SIZE - len(raw))
        self.disk.write_block(0, raw)

    def _save_inode_bitmap(self) -> None:
        data = bytes(self.inode_bitmap.data)
        for i in range(INODE_BITMAP_BLOCKS):
            chunk = data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
            self.disk.write_block(self.sb.inode_bitmap_start + i, chunk)

    def _save_block_bitmap(self) -> None:
        data = bytes(self.block_bitmap.data)
        for i in range(BLOCK_BITMAP_BLOCKS):
            chunk = data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
            self.disk.write_block(self.sb.block_bitmap_start + i, chunk)

    # versoes que persistem so o bloco do bitmap que contem o bit alterado,
    # em vez do bitmap inteiro -- usadas em toda alocacao/liberacao de
    # i-node ou bloco (ver alloc_inode/free_inode/alloc_block/free_block
    # abaixo). As funcoes acima (_save_inode_bitmap/_save_block_bitmap)
    # continuam existindo pra escrever o bitmap inteiro de uma vez, usadas
    # so no mkfs.
    def _save_inode_bitmap_bit(self, idx: int) -> None:
        bits_per_block = BLOCK_SIZE * 8
        block_off = idx // bits_per_block
        byte_start = block_off * BLOCK_SIZE
        chunk = bytes(self.inode_bitmap.data[byte_start:byte_start + BLOCK_SIZE])
        self.disk.write_block(self.sb.inode_bitmap_start + block_off, chunk)

    def _save_block_bitmap_bit(self, idx: int) -> None:
        bits_per_block = BLOCK_SIZE * 8
        block_off = idx // bits_per_block
        byte_start = block_off * BLOCK_SIZE
        chunk = bytes(self.block_bitmap.data[byte_start:byte_start + BLOCK_SIZE])
        self.disk.write_block(self.sb.block_bitmap_start + block_off, chunk)

    def close(self) -> None:
        self.disk.close()

    def flush(self) -> None:
        self.disk.flush()

    # ---- credenciais ----

    # Troca quem tá usando o sistema. self.uid/self.gid são o 'crachá' atual:
    # td checagem de permissão olha pra eles. Chamada pelo login e pelo su.
    def set_credentials(self, uid: int, gid: int) -> None:
        self.uid = uid
        self.gid = gid
        # Conta qtas trocas de usuário já rolaram. O sudo usa isso pra saber se
        # o comando dele foi um 'su'.
        self.cred_changes += 1

    # 'Modo kernel': roda um pedaço de código como root e depois volta a ser
    # quem era. É o q permite, por ex., o login ler o /etc/shadow (q é 600) c/
    # um usuário comum logado. Nenhum comando digitado chega aqui, só código
    # interno do sistema.
    @contextmanager
    def as_root(self) -> Iterator[None]:
        # Anota quem tá logado...
        saved = (self.uid, self.gid)
        # ...e vira root.
        self.uid, self.gid = ROOT_UID, ROOT_GID
        try:
            # Aqui roda o trecho q tá dentro do 'with'.
            yield
        finally:
            # No finally: volta a ser quem era SEMPRE, msm se deu erro. Sem
            # isso, um erro no meio deixaria a pessoa como root pra sempre.
            self.uid, self.gid = saved

    # Lista os grupos de quem tá logado (o primário + os adicionais). É
    # calculado de novo a cada checagem, por isso tirar alguém de um grupo
    # corta o acesso na hora.
    def group_ids(self) -> List[int]:
        user = self.accounts.user_by_uid(self.uid)
        return self.accounts.group_ids_of(user) if user else [self.gid]

    # Atalho: pergunta pro effective_access (permissions.py) o q quem tá logado
    # pode fazer c/ esse arquivo.
    def access_of(self, inode: Inode) -> Tuple[str, int]:
        return effective_access(inode, self.uid, self.group_ids())

    # O PONTO ÚNICO de checagem de leitura/escrita: td operação q precisa de r
    # ou w passa por aqui antes de fazer qq coisa.
    def _require(self, inode: Inode, want: int, label: str) -> None:
        # Descobre o q a pessoa pode fazer nesse arquivo (ex.: 10 = só ler).
        _, bits = self.access_of(inode)
        # Tem td q foi pedido? Ex.: pediu w (01) mas só tem r (10): 10 & 01 =
        # 00, diferente de 01 -> 'Permissão negada', antes de mexer em qq coisa
        # no disco.
        if bits & want != want:
            raise FSError(f"{label}: Permissão negada")

    # Muda dono, grupo e/ou permissão de um arquivo SEM conferir nada. Só o
    # próprio sistema usa direto (ex.: entregar a home pro usuário novo). O
    # chmod/chown/chgrp de vdd conferem as regras antes e só depois chamam esta
    # função.
    def set_attrs(self, num: int, owner_uid: Optional[int] = None,
                  gid: Optional[int] = None, perm: Optional[int] = None) -> None:
        # Lê a ficha (i-node) do arquivo, troca só os campos q vieram e grava
        # de volta.
        inode = self.read_inode(num)
        if owner_uid is not None:
            inode.owner_uid = owner_uid
        if gid is not None:
            inode.gid = gid
        if perm is not None:
            inode.perm = perm
        self.write_inode(num, inode)

    # aloca/libera i-nodes e blocos usando os bitmaps
    def alloc_inode(self) -> int:
        idx = self.inode_bitmap.find_free()
        if idx is None:
            raise FSError("sem i-nodes livres (limite de arquivos/diretorios atingido)")
        self.inode_bitmap.set(idx, True)
        self.sb.free_inodes -= 1
        self._save_inode_bitmap_bit(idx)
        self._save_superblock()
        return idx

    def free_inode(self, num: int) -> None:
        self.inode_bitmap.set(num, False)
        self.sb.free_inodes += 1
        self._save_inode_bitmap_bit(num)
        self._save_superblock()
        self.write_inode(num, Inode())
        # tira do cache se esse numero de i-node ja foi usado como
        # diretorio -- caso contrario, quando alloc_inode devolver esse
        # mesmo numero pra um diretorio novo, ele ia aparecer com as
        # entradas do diretorio antigo
        self._dir_cache.pop(num, None)
        self._dir_free_slots.pop(num, None)

    def alloc_block(self) -> int:
        idx = self.block_bitmap.find_free(start=DATA_START)
        if idx is None:
            raise FSError("disco cheio: sem blocos de dados livres")
        self.block_bitmap.set(idx, True)
        self.sb.free_blocks -= 1
        self._save_block_bitmap_bit(idx)
        self._save_superblock()
        return idx

    def free_block(self, num: int) -> None:
        if num < DATA_START:
            return
        self.block_bitmap.set(num, False)
        self.sb.free_blocks += 1
        self._save_block_bitmap_bit(num)
        self._save_superblock()

    def _inode_location(self, num: int) -> Tuple[int, int]:
        per_block = BLOCK_SIZE // INODE_SIZE
        block = self.sb.inode_table_start + num // per_block
        offset = (num % per_block) * INODE_SIZE
        return block, offset

    def read_inode(self, num: int) -> Inode:
        block, offset = self._inode_location(num)
        data = self.disk.read_block(block)
        return Inode.unpack(data[offset:offset + INODE_SIZE])

    def write_inode(self, num: int, inode: Inode) -> None:
        block, offset = self._inode_location(num)
        data = bytearray(self.disk.read_block(block))
        data[offset:offset + INODE_SIZE] = inode.pack()
        self.disk.write_block(block, bytes(data))

    # a partir daqui, funcoes que andam na cadeia de blocos de um i-node
    # (ponteiros diretos + i-node de continuacao, se precisar)
    def _chain(self, head_inode_num: int) -> List[Tuple[int, Inode]]:
        """Devolve [(numero, i-node)] do i-node cabeca e de todas as continuacoes.

        O i-node 0 e sempre a raiz e nunca e continuacao de ninguem, entao
        next_inode <= 0 encerra a cadeia (-1 = fim normal; 0 = registro que
        nunca foi inicializado, que num disco zerado le como 0). Tambem para
        em ciclo ou em i-node marcado como livre (imagem corrompida).
        """
        chain: List[Tuple[int, Inode]] = []
        seen = set()
        cur_num = head_inode_num
        while cur_num not in seen:
            seen.add(cur_num)
            cur = self.read_inode(cur_num)
            chain.append((cur_num, cur))
            nxt = cur.next_inode
            if nxt <= 0 or nxt >= NUM_INODES or not self.inode_bitmap.get(nxt):
                break
            cur_num = nxt
        return chain

    @staticmethod
    def _used_pointers(inode: Inode) -> int:
        n = 0
        for p in inode.pointers:
            if p == 0:
                break
            n += 1
        return n

    def _iter_blocks(self, head_inode_num: int) -> List[int]:
        blocks = []
        for _, ino in self._chain(head_inode_num):
            for p in ino.pointers:
                if p == 0:
                    break
                blocks.append(p)
        return blocks

    def _grow(self, head_inode_num: int, needed_blocks: int) -> None:
        """Faz a cadeia ter pelo menos `needed_blocks` blocos.

        Tudo ou nada: se nao houver blocos/i-nodes suficientes (ou se algo
        falhar no meio), levanta FSError sem deixar nada alocado e sem
        alterar o que ja estava gravado no disco. As mudancas so vao pro
        disco depois que tudo foi alocado, e as continuacoes novas sao
        gravadas ANTES do i-node que aponta pra elas (assim nenhum
        next_inode aponta pra registro nao inicializado).
        """
        chain = self._chain(head_inode_num)
        have = sum(self._used_pointers(ino) for _, ino in chain)
        to_add = needed_blocks - have
        if to_add <= 0:
            return

        last_num, last = chain[-1]
        used_in_last = self._used_pointers(last)
        extra = max(0, to_add - (DIRECT_POINTERS - used_in_last))
        new_inodes_needed = (extra + DIRECT_POINTERS - 1) // DIRECT_POINTERS
        if self.sb.free_blocks < to_add:
            raise FSError("disco cheio: sem blocos de dados livres")
        if self.sb.free_inodes < new_inodes_needed:
            raise FSError("sem i-nodes livres (limite de arquivos/diretorios atingido)")

        new_blocks: List[int] = []
        fresh: List[Tuple[int, Inode]] = []  # continuacoes criadas agora
        try:
            cur_num, cur, used = last_num, last, used_in_last
            for _ in range(to_add):
                if used == DIRECT_POINTERS:
                    new_num = self.alloc_inode()
                    new_ino = Inode(used=1, type=cur.type)  # next_inode = -1
                    fresh.append((new_num, new_ino))
                    cur.next_inode = new_num  # so em memoria por enquanto
                    cur_num, cur, used = new_num, new_ino, 0
                b = self.alloc_block()
                new_blocks.append(b)
                cur.pointers[used] = b
                used += 1
        except FSError:
            for b in new_blocks:
                self.free_block(b)
            for n, _ in fresh:
                self.free_inode(n)
            raise

        for n, ino in fresh:
            self.write_inode(n, ino)
        self.write_inode(last_num, last)

    def _shrink(self, head_inode_num: int, needed_blocks: int) -> None:
        chain = self._chain(head_inode_num)
        kept = 0
        last_keep = 0
        to_free: List[int] = []
        changed = set()
        for idx, (_, ino) in enumerate(chain):
            for slot in range(DIRECT_POINTERS):
                p = ino.pointers[slot]
                if p == 0:
                    break
                if kept < needed_blocks:
                    kept += 1
                    last_keep = idx
                else:
                    to_free.append(p)
                    ino.pointers[slot] = 0
                    changed.add(idx)

        surplus = chain[last_keep + 1:]  # continuacoes que ficaram vazias
        if surplus:
            chain[last_keep][1].next_inode = -1
            changed.add(last_keep)
        if not to_free and not surplus:
            return

        # grava primeiro os i-nodes que continuam (sem apontar pro que vai
        # ser liberado) e so depois libera blocos e i-nodes
        for idx in sorted(changed):
            if idx <= last_keep:
                num, ino = chain[idx]
                self.write_inode(num, ino)
        for b in to_free:
            self.free_block(b)
        for num, _ in surplus:
            self.free_inode(num)

    # leitura/escrita do conteudo (usado tambem pro "conteudo" de symlinks,
    # que e so o caminho de destino guardado como bytes)
    def read_data(self, head_inode_num: int) -> bytes:
        inode = self.read_inode(head_inode_num)
        size = inode.size
        if size == 0:
            return b""
        blocks = self._iter_blocks(head_inode_num)
        buf = bytearray()
        remaining = size
        for b in blocks:
            if remaining <= 0:
                break
            chunk = self.disk.read_block(b)
            take = min(BLOCK_SIZE, remaining)
            buf += chunk[:take]
            remaining -= take
        return bytes(buf)

    def write_data(self, head_inode_num: int, data: bytes) -> None:
        needed_blocks = (len(data) + BLOCK_SIZE - 1) // BLOCK_SIZE
        current_blocks = len(self._iter_blocks(head_inode_num))
        if needed_blocks > current_blocks:
            self._grow(head_inode_num, needed_blocks)
        elif needed_blocks < current_blocks:
            self._shrink(head_inode_num, needed_blocks)

        blocks = self._iter_blocks(head_inode_num)
        offset = 0
        for b in blocks:
            chunk = data[offset:offset + BLOCK_SIZE]
            if len(chunk) < BLOCK_SIZE:
                chunk = chunk + b"\x00" * (BLOCK_SIZE - len(chunk))
            self.disk.write_block(b, chunk)
            offset += BLOCK_SIZE

        inode = self.read_inode(head_inode_num)
        inode.size = len(data)
        inode.modified_at = time.time()
        self.write_inode(head_inode_num, inode)

    def append_data(self, head_inode_num: int, data: bytes) -> None:
        """Acrescenta ao final sem precisar reler o arquivo inteiro e
        escrever tudo de novo -- so mexe no ultimo bloco (se ele estiver
        parcialmente cheio) e nos blocos novos que essa escrita precisar.
        """
        if not data:
            return
        old_size = self.read_inode(head_inode_num).size
        new_size = old_size + len(data)
        needed_blocks = (new_size + BLOCK_SIZE - 1) // BLOCK_SIZE
        current_blocks = len(self._iter_blocks(head_inode_num))
        if needed_blocks > current_blocks:
            self._grow(head_inode_num, needed_blocks)

        blocks = self._iter_blocks(head_inode_num)
        pos_in_block = old_size % BLOCK_SIZE
        remaining = data
        for bi in range(old_size // BLOCK_SIZE, len(blocks)):
            if not remaining:
                break
            b = blocks[bi]
            if pos_in_block > 0:
                # ultimo bloco existente, parcialmente cheio: preserva o
                # que ja tinha e so completa a partir de onde parou
                existing = bytearray(self.disk.read_block(b))
                space = BLOCK_SIZE - pos_in_block
                take = remaining[:space]
                existing[pos_in_block:pos_in_block + len(take)] = take
                self.disk.write_block(b, bytes(existing))
                remaining = remaining[len(take):]
                pos_in_block = 0
            else:
                # bloco novo (alocado agora ou reaproveitado): escreve direto
                chunk = remaining[:BLOCK_SIZE]
                if len(chunk) < BLOCK_SIZE:
                    chunk = chunk + b"\x00" * (BLOCK_SIZE - len(chunk))
                self.disk.write_block(b, chunk)
                remaining = remaining[BLOCK_SIZE:]

        # le o i-node de novo (so agora, depois do _grow) antes de atualizar
        # tamanho/data -- se reusasse o objeto lido no inicio da funcao,
        # essa escrita apagaria os ponteiros novos que o _grow acabou de
        # gravar no disco
        inode = self.read_inode(head_inode_num)
        inode.size = new_size
        inode.modified_at = time.time()
        self.write_inode(head_inode_num, inode)

    def free_all_data(self, head_inode_num: int) -> None:
        """Libera todos os blocos de dados e i-nodes de continuacao (mas nao o i-node cabeca)."""
        self._shrink(head_inode_num, 0)

    def _init_dir_block(self, block_num: int) -> None:
        blank = DirEntry.blank().pack()
        self.disk.write_block(block_num, blank * ENTRIES_PER_BLOCK)

    def _load_dir_cache(self, dir_inode_num: int) -> Dict[str, Tuple[int, int, int]]:
        """Devolve o conteudo de um diretorio (nome -> i-node/bloco/slot),
        lendo do disco so na primeira vez que esse diretorio e acessado
        nesta sessao -- da segunda vez em diante usa o que ja esta em
        self._dir_cache. Sem isso, cada touch/mkdir/ln/rm tinha que reler
        o diretorio inteiro do zero so pra checar se o nome ja existia.
        """
        if dir_inode_num in self._dir_cache:
            return self._dir_cache[dir_inode_num]
        entries: Dict[str, Tuple[int, int, int]] = {}
        free_slots: List[Tuple[int, int]] = []
        for b in self._iter_blocks(dir_inode_num):
            data = self.disk.read_block(b)
            for i in range(ENTRIES_PER_BLOCK):
                raw = data[i * DIRENT_SIZE:(i + 1) * DIRENT_SIZE]
                entry = DirEntry.unpack(raw)
                if entry.inode_num == EMPTY_ENTRY:
                    free_slots.append((b, i))
                else:
                    entries[entry.name] = (entry.inode_num, b, i)
        self._dir_cache[dir_inode_num] = entries
        self._dir_free_slots[dir_inode_num] = free_slots
        return entries

    def _dir_lookup(self, dir_inode_num: int, name: str) -> Optional[int]:
        # acha o i-node de `name` num diretorio sem montar a lista toda
        # (usar isso em vez de read_dir_entries()+dict() quando so precisa
        # de um nome so)
        info = self._load_dir_cache(dir_inode_num).get(name)
        return info[0] if info else None

    def read_dir_entries(self, dir_inode_num: int) -> List[Tuple[str, int]]:
        entries = self._load_dir_cache(dir_inode_num)
        return [(name, info[0]) for name, info in entries.items()]

    def add_dir_entry(self, dir_inode_num: int, name: str, target_inode_num: int, _validate: bool = True) -> None:
        entries = self._load_dir_cache(dir_inode_num)
        if _validate:
            self._check_name(name)
            if name in entries:
                raise FSError(f"{name}: já existe")

        free_slots = self._dir_free_slots[dir_inode_num]
        if free_slots:
            block_num, slot_idx = free_slots.pop()
        else:
            current = len(self._iter_blocks(dir_inode_num))
            self._grow(dir_inode_num, current + 1)
            blocks = self._iter_blocks(dir_inode_num)
            new_block = blocks[-1]
            self._init_dir_block(new_block)
            di = self.read_inode(dir_inode_num)
            di.size = len(blocks) * BLOCK_SIZE
            di.modified_at = time.time()
            self.write_inode(dir_inode_num, di)
            # o bloco novo tem ENTRIES_PER_BLOCK slots livres; usa o slot 0
            # agora e guarda o resto pras proximas chamadas (sem isso, cada
            # add_dir_entry voltaria a varrer o diretorio pra achar o slot)
            for i in range(1, ENTRIES_PER_BLOCK):
                free_slots.append((new_block, i))
            block_num, slot_idx = new_block, 0

        data = bytearray(self.disk.read_block(block_num))
        entry = DirEntry(name=name, inode_num=target_inode_num)
        data[slot_idx * DIRENT_SIZE:(slot_idx + 1) * DIRENT_SIZE] = entry.pack()
        self.disk.write_block(block_num, bytes(data))
        entries[name] = (target_inode_num, block_num, slot_idx)

    def remove_dir_entry(self, dir_inode_num: int, name: str) -> None:
        entries = self._load_dir_cache(dir_inode_num)
        info = entries.pop(name, None)
        if info is None:
            raise FSError(f"{name}: não encontrado")
        _, block_num, slot_idx = info
        data = bytearray(self.disk.read_block(block_num))
        data[slot_idx * DIRENT_SIZE:(slot_idx + 1) * DIRENT_SIZE] = DirEntry.blank().pack()
        self.disk.write_block(block_num, bytes(data))
        self._dir_free_slots[dir_inode_num].append((block_num, slot_idx))

    def _set_dir_entry(self, dir_inode_num: int, name: str, target_inode_num: int) -> None:
        """Troca, no lugar, o i-node para o qual uma entrada existente aponta."""
        entries = self._load_dir_cache(dir_inode_num)
        info = entries.get(name)
        if info is None:
            raise FSError(f"{name}: não encontrado")
        _, block_num, slot_idx = info
        data = bytearray(self.disk.read_block(block_num))
        data[slot_idx * DIRENT_SIZE:(slot_idx + 1) * DIRENT_SIZE] = DirEntry(name, target_inode_num).pack()
        self.disk.write_block(block_num, bytes(data))
        entries[name] = (target_inode_num, block_num, slot_idx)

    @staticmethod
    def _check_name(name: str) -> None:
        if name in ("", ".", ".."):
            raise FSError(f"'{name}': nome inválido")
        if "/" in name:
            raise FSError(f"'{name}': nome não pode conter '/'")
        if len(name.encode("utf-8")) > MAX_NAME_LEN:
            raise FSError(f"'{name}': nome muito longo (máx. {MAX_NAME_LEN} bytes em UTF-8)")

    # Transforma um caminho em texto (/home/ana/notas.txt) no número da ficha
    # (i-node) do arquivo, andando pasta por pasta. É aqui q mora uma regra
    # importante: pra atravessar uma pasta, precisa de r nela.
    def resolve(self, path: str, cwd_inode: Optional[int] = None,
                follow_symlink: bool = True, _depth: int = 0) -> int:
        if _depth > 20:
            raise FSError("loop de links simbólicos detectado")
        if cwd_inode is None:
            cwd_inode = self.cwd_inode
        if not path:
            raise FSError("caminho vazio")

        # Começa da raiz (/) se o caminho é absoluto, ou da pasta atual se é
        # relativo.
        if path.startswith("/"):
            cur = self.sb.root_inode
        else:
            cur = cwd_inode

        # Quebra o caminho nos pedaços: '/home/ana/notas.txt' -> ['home',
        # 'ana', 'notas.txt'].
        parts = [p for p in path.split("/") if p != ""]
        if not parts:
            return cur

        for i, part in enumerate(parts):
            is_last = i == len(parts) - 1
            inode = self.read_inode(cur)
            if inode.type != TYPE_DIR:
                raise FSError(f"{part}: '{inode.name}' não é um diretório")
            # Exige r na pasta atual antes de procurar o próximo nome (aqui o r
            # faz o papel do x do Linux). Sem r em /home/ana, vc ñ chega em
            # nada lá dentro, msm sabendo o nome do arquivo.
            self._require(inode, PERM_R, self._path_prefix(path, parts, i))
            # Procura o nome dentro da pasta.
            target = self._dir_lookup(cur, part)
            if target is None:
                raise FSError(f"{part}: arquivo ou diretório não encontrado")
            target_inode = self.read_inode(target)
            # Achou um link? Segue até o alvo. O caminho do alvo passa pelas
            # msms checagens, por isso um link pro shadow ñ dá acesso a nada.
            if target_inode.type == TYPE_SYMLINK and (follow_symlink or not is_last):
                link_path = self.read_data(target).decode("utf-8", errors="replace")
                target = self.resolve(link_path, cwd_inode=cur, follow_symlink=True, _depth=_depth + 1)
            cur = target
        return cur

    # Só monta o texto da msg de erro (ex.: '/home/ana: Permissão negada'),
    # mostrando em q pasta a resolução travou.
    @staticmethod
    def _path_prefix(path: str, parts: List[str], i: int) -> str:
        prefix = "/".join(parts[:i])
        if path.startswith("/"):
            return "/" + prefix
        return prefix or "."

    def _exists(self, path: str) -> bool:
        try:
            self.resolve(path)
            return True
        except FSError:
            return False

    # Separa o caminho em 'pasta pai' + 'nome': '/etc/shadow' -> '/etc' e
    # 'shadow'. Usada por td operação q cria, apaga ou renomeia.
    def split_parent(self, path: str) -> Tuple[int, str]:
        path = path.rstrip("/")
        if path == "":
            raise FSError("caminho inválido")
        idx = path.rfind("/")
        if idx == -1:
            parent_path, name = ".", path
        elif idx == 0:
            parent_path, name = "/", path[1:]
        else:
            parent_path, name = path[:idx], path[idx + 1:]
        if name in ("", ".", ".."):
            raise FSError(f"'{path}': nome inválido")
        # Acha a pasta pai (passando pelas checagens de r no caminho).
        parent_inode = self.resolve(parent_path)
        parent = self.read_inode(parent_inode)
        if parent.type != TYPE_DIR:
            # sem isso, "touch arq/x" gravava entradas de diretorio dentro
            # dos blocos de dados de um arquivo comum e o corrompia
            raise FSError(f"{parent_path}: não é um diretório")
        # E exige r tb no próprio pai, pq a operação vai procurar ou criar o
        # nome lá dentro.
        self._require(parent, PERM_R, parent_path)
        return parent_inode, name

    def path_of(self, inode_num: int) -> str:
        if inode_num == self.sb.root_inode:
            return "/"
        components = []
        cur = inode_num
        guard = 0
        while cur != self.sb.root_inode:
            guard += 1
            if guard > 1000:
                raise FSError("caminho corrompido (profundidade excessiva)")
            entries = dict(self.read_dir_entries(cur))
            parent = entries.get("..")
            if parent is None:
                raise FSError("diretório corrompido: entrada '..' ausente")
            parent_entries = self.read_dir_entries(parent)
            name = None
            for n, num in parent_entries:
                if num == cur and n not in (".", ".."):
                    name = n
                    break
            if name is None:
                name = "?"
            components.append(name)
            cur = parent
        return "/" + "/".join(reversed(components))

    def _is_ancestor(self, maybe_ancestor: int, inode_num: int) -> bool:
        cur = inode_num
        guard = 0
        while cur != self.sb.root_inode:
            guard += 1
            if guard > 1000:
                return False
            if cur == maybe_ancestor:
                return True
            entries = dict(self.read_dir_entries(cur))
            cur = entries.get("..", self.sb.root_inode)
        return maybe_ancestor == self.sb.root_inode

    # Monta a ficha (i-node) de um arquivo ou pasta nova.
    def _new_inode(self, itype: int, perm: int, name: str, now: float) -> Inode:
        return Inode(
            used=1, type=itype, perm=perm, name=name,
            # Quem criou vira dono e criador; o grupo é o grupo primário de
            # quem criou. Como cada usuário tem um grupo só dele, td nasce
            # privado.
            owner_uid=self.uid, gid=self.gid, creator_uid=self.uid,
            size=0, created_at=now, modified_at=now,
        )

    # ---- operacoes sobre arquivos ----

    # O touch: cria um arquivo vazio ou, se já existe, atualiza a data.
    def touch(self, path: str) -> int:
        parent, name = self.split_parent(path)
        num = self._dir_lookup(parent, name)
        if num is not None:
            num = self.resolve(path)  # se for link, atualiza o alvo (igual no Linux)
            inode = self.read_inode(num)
            # Já existe: mudar a data é mexer no arquivo, então precisa de w
            # nele.
            self._require(inode, PERM_W, path)
            inode.modified_at = time.time()
            self.write_inode(num, inode)
            return num

        self._check_name(name)  # valida antes de gastar i-node
        # Arquivo novo: criar é colocar um nome novo dentro da pasta, então
        # precisa de w na PASTA PAI.
        self._require(self.read_inode(parent), PERM_W, path)
        num = self.alloc_inode()
        now = time.time()
        inode = self._new_inode(TYPE_FILE, DEFAULT_FILE_PERM, name, now)
        self.write_inode(num, inode)
        try:
            self.add_dir_entry(parent, name, num)
        except FSError:
            self.free_inode(num)  # nao deixa i-node orfao (ex.: disco cheio)
            raise
        return num

    # O echo > (sobrescreve) e o echo >> (acrescenta no fim).
    def write_file(self, path: str, content: bytes, append: bool) -> int:
        parent, name = self.split_parent(path)
        num = self._dir_lookup(parent, name)
        if num is not None:
            inode = self.read_inode(num)
            if inode.type == TYPE_SYMLINK:
                # Se o nome é um link, escreve no alvo.
                num = self.resolve(path)
                inode = self.read_inode(num)
            if inode.type == TYPE_DIR:
                raise FSError(f"{name}: é um diretório")
            # Arquivo existe: precisa de w nele.
            self._require(inode, PERM_W, path)
        else:
            # Ñ existe: cria pelo touch, q confere w na pasta pai.
            num = self.touch(path)

        if append:
            self.append_data(num, content)
        else:
            self.write_data(num, content)
        return num

    # O cat: lê o conteúdo de um arquivo.
    def read_file(self, path: str) -> bytes:
        # Acha o arquivo (exigindo r em cada pasta do caminho)...
        num = self.resolve(path)
        inode = self.read_inode(num)
        if inode.type == TYPE_DIR:
            raise FSError(f"{path}: é um diretório")
        # ...e exige r no próprio arquivo. Só depois lê.
        self._require(inode, PERM_R, path)
        return self.read_data(num)

    # O rm: apaga um arquivo.
    def rm(self, path: str) -> None:
        parent, name = self.split_parent(path)
        num = self._dir_lookup(parent, name)
        if num is None:
            raise FSError(f"{name}: arquivo não encontrado")
        inode = self.read_inode(num)
        if inode.type == TYPE_DIR:
            raise FSError(f"{name}: é um diretório (use rmdir)")
        # Precisa de w na PASTA PAI, ñ no arquivo: apagar é tirar o nome de
        # dentro da pasta (igual Linux). Por isso usuário comum ñ apaga o
        # /etc/shadow: o /etc é só do root.
        self._require(self.read_inode(parent), PERM_W, path)
        # Liberado: tira o nome da pasta e libera os blocos e a ficha do
        # arquivo.
        self.remove_dir_entry(parent, name)
        self.free_all_data(num)
        self.free_inode(num)

    # O cp: copia um arquivo.
    def cp(self, src: str, dst: str) -> None:
        src_num = self.resolve(src)
        src_inode = self.read_inode(src_num)
        if src_inode.type != TYPE_FILE:
            raise FSError(f"{src}: cp só é suportado para arquivos")
        # Precisa de r no original.
        self._require(src_inode, PERM_R, src)
        data = self.read_data(src_num)

        dst_final = dst
        try:
            maybe_dir = self.resolve(dst)
            if self.read_inode(maybe_dir).type == TYPE_DIR:
                base = src.rstrip("/").split("/")[-1]
                dst_final = dst.rstrip("/") + "/" + base
        except FSError:
            pass

        created = not self._exists(dst_final)
        # Cria/grava o destino pelo write_file (q confere w). Como quem cria é
        # quem tá logado, a cópia é de QUEM COPIOU, ñ do dono do original (se
        # ficasse c/ o dono do original, dava pra criar arquivo no nome dos
        # outros).
        num = self.write_file(dst_final, data, append=False)
        if created:
            # Cópia nova: pega as permissões do original 'E' 640, então nasce
            # no máx tão aberta qto o original (600 continua 600; 644 vira
            # 640).
            self.set_attrs(num, perm=src_inode.perm & DEFAULT_FILE_PERM)

    # O mv: move ou renomeia um arquivo ou pasta.
    def mv(self, src: str, dst: str) -> None:
        src_parent, src_name = self.split_parent(src)
        src_num = self._dir_lookup(src_parent, src_name)
        if src_num is None:
            raise FSError(f"{src_name}: não encontrado")
        src_inode = self.read_inode(src_num)

        dst_parent, dst_name = None, None
        try:
            maybe_dir = self.resolve(dst)
            if self.read_inode(maybe_dir).type == TYPE_DIR:
                dst_parent, dst_name = maybe_dir, src_name
        except FSError:
            pass
        if dst_parent is None:
            dst_parent, dst_name = self.split_parent(dst)

        # Precisa de w na pasta de onde sai...
        self._require(self.read_inode(src_parent), PERM_W, src)
        # ...e de r+w na pasta pra onde vai. Isso é conferido ANTES de dizer
        # 'já existe', pra ñ entregar o q tem dentro de uma pasta q vc nem pode
        # ler.
        self._require(self.read_inode(dst_parent), PERM_RW, dst)

        if self._dir_lookup(dst_parent, dst_name) is not None:
            raise FSError(f"{dst_name}: já existe")

        if src_inode.type == TYPE_DIR:
            if src_num == dst_parent or self._is_ancestor(src_num, dst_parent):
                raise FSError("não é possível mover um diretório para dentro de si mesmo")

        self._check_name(dst_name)
        # cria a entrada nova ANTES de remover a antiga: se o disco estiver
        # cheio e o diretorio destino precisar de um bloco novo, falha aqui
        # sem ter mexido em nada (antes o arquivo podia ficar sem nome).
        self.add_dir_entry(dst_parent, dst_name, src_num, _validate=False)
        self.remove_dir_entry(src_parent, src_name)
        src_inode.name = dst_name
        src_inode.modified_at = time.time()
        self.write_inode(src_num, src_inode)

        if src_inode.type == TYPE_DIR and dst_parent != src_parent:
            self._set_dir_entry(src_num, "..", dst_parent)

    # O ln -s: cria um link simbólico (um 'atalho' q guarda o caminho de outro
    # arquivo).
    def ln_s(self, target: str, link_path: str) -> int:
        parent, name = self.split_parent(link_path)
        if self._dir_lookup(parent, name) is not None:
            raise FSError(f"{name}: já existe")
        self._check_name(name)
        # Só exige w na pasta onde o link vai ficar. Criar link pro shadow
        # pode, mas qd alguém segue o link cai na checagem do alvo e dá
        # Permissão negada.
        self._require(self.read_inode(parent), PERM_W, link_path)
        num = self.alloc_inode()
        now = time.time()
        inode = self._new_inode(TYPE_SYMLINK, DEFAULT_SYMLINK_PERM, name, now)
        self.write_inode(num, inode)
        try:
            self.write_data(num, target.encode("utf-8"))
            self.add_dir_entry(parent, name, num)
        except FSError:
            self.free_all_data(num)
            self.free_inode(num)
            raise
        return num

    # e daqui pra baixo, diretorio
    # O mkdir: cria uma pasta.
    def mkdir(self, path: str) -> int:
        parent, name = self.split_parent(path)
        if self._dir_lookup(parent, name) is not None:
            raise FSError(f"{name}: já existe")

        self._check_name(name)
        # Precisa de w na pasta pai.
        self._require(self.read_inode(parent), PERM_W, path)
        num = self.alloc_inode()
        now = time.time()
        inode = self._new_inode(TYPE_DIR, DEFAULT_DIR_PERM, name, now)
        self.write_inode(num, inode)
        try:
            # monta o diretorio novo por inteiro e so depois o "pendura" no pai
            self.add_dir_entry(num, ".", num, _validate=False)
            self.add_dir_entry(num, "..", parent, _validate=False)
            self.add_dir_entry(parent, name, num)
        except FSError:
            self.free_all_data(num)
            self.free_inode(num)
            raise
        return num

    # O rmdir: apaga uma pasta vazia.
    def rmdir(self, path: str) -> None:
        parent, name = self.split_parent(path)
        num = self._dir_lookup(parent, name)
        if num is None:
            raise FSError(f"{name}: diretório não encontrado")
        inode = self.read_inode(num)
        if inode.type != TYPE_DIR:
            raise FSError(f"{name}: não é um diretório")
        # Precisa de w na pasta pai.
        self._require(self.read_inode(parent), PERM_W, path)
        contents = [e for e in self.read_dir_entries(num) if e[0] not in (".", "..")]
        if contents:
            raise FSError(f"{name}: diretório não está vazio")
        if num == self.cwd_inode:
            raise FSError(f"{name}: é o diretório atual, faça cd para outro lugar antes")

        self.remove_dir_entry(parent, name)
        self.free_all_data(num)
        self.free_inode(num)

    # O ls: lista o q tem numa pasta.
    def ls(self, path: Optional[str] = None) -> List[Tuple[str, Inode, int]]:
        num = self.resolve(path) if path else self.cwd_inode
        inode = self.read_inode(num)
        if inode.type != TYPE_DIR:
            raise FSError(f"{path}: não é um diretório")
        # Precisa de r na pasta.
        self._require(inode, PERM_R, path or ".")
        result = []
        for name, child_num in sorted(self.read_dir_entries(num)):
            if name in (".", ".."):
                continue
            child = self.read_inode(child_num)
            result.append((name, child, child_num))
        return result

    # O cd: entra numa pasta.
    def cd(self, path: str) -> None:
        num = self.resolve(path)
        inode = self.read_inode(num)
        if inode.type != TYPE_DIR:
            raise FSError(f"{path}: não é um diretório")
        # Precisa de r (entrar = atravessar).
        self._require(inode, PERM_R, path)
        self.cwd_inode = num

    # ---- chmod, chown, chgrp ----
    #
    # Os tres seguem link (mexem no alvo, igual no Linux) e passam pela
    # resolucao normal do caminho, entao atravessar continua exigindo r. Aqui
    # a regra nao e r/w, e sim QUEM e a pessoa (dono ou root); por isso o
    # erro e "Operacao nao permitida" e nao "Permissao negada" -- o Linux
    # tambem separa as duas coisas. O "criador" nunca muda.

    # O chmod: muda as permissões (quem pode ler e escrever) de um arquivo ou
    # pasta.
    def chmod(self, path: str, mode: str) -> None:
        # Acha o arquivo (se for link, o alvo).
        num = self.resolve(path)
        inode = self.read_inode(num)
        # Calcula a permissão nova a partir do q foi digitado. Modo inválido dá
        # erro aqui, antes de mexer em qq coisa.
        new_perm = parse_mode(mode, inode.perm)
        # Só o DONO ou o root podem. A msg é 'Operação não permitida' (e ñ
        # 'Permissão negada') pq aqui a regra é QUEM vc é, ñ q bits vc tem.
        if self.uid != ROOT_UID and inode.owner_uid != self.uid:
            raise FSError(f"chmod: {path}: Operação não permitida")
        # Grava só o byte de permissão novo. Dono, criador e conteúdo continuam
        # iguais.
        self.set_attrs(num, perm=new_perm)

    # O chown: troca o dono (e/ou o grupo) de um arquivo.
    def chown(self, path: str, owner: Optional[str], group: Optional[str]) -> None:
        # Converte os nomes digitados nos números (UID/GID). Nome q ñ existe dá
        # erro aqui, sem mexer em nada.
        uid = self.accounts.get_user(owner).uid if owner else None
        gid = self.accounts.get_group(group).gid if group else None
        num = self.resolve(path)
        # SÓ o root pode. Pq: senão a ana podia 'dar' um arquivo pro bruno, pra
        # incriminar ele ou deixar c/ ele algo q ele ñ controla.
        if self.uid != ROOT_UID:
            raise FSError(f"chown: {path}: Operação não permitida")
        # Grava o dono/grupo novo. O 'criador' nunca muda.
        self.set_attrs(num, owner_uid=uid, gid=gid)

    # O chgrp: troca só o grupo de um arquivo. É o jeito de compartilhar: passa
    # o arquivo pra um grupo, e quem tá nele passa a usar os bits do grupo.
    def chgrp(self, path: str, group: str) -> None:
        gid = self.accounts.get_group(group).gid
        num = self.resolve(path)
        inode = self.read_inode(num)
        # Root pode td. Usuário comum: tem q ser o dono E fazer parte do grupo
        # de destino. Assim ninguém 'joga' arquivo num grupo do qual ñ faz
        # parte.
        if self.uid != ROOT_UID and (inode.owner_uid != self.uid or gid not in self.group_ids()):
            raise FSError(f"chgrp: {path}: Operação não permitida")
        self.set_attrs(num, gid=gid)

    def usage(self) -> dict:
        return {
            "total_blocks": self.sb.total_blocks,
            "data_blocks": DATA_BLOCKS,
            "free_blocks": self.sb.free_blocks,
            "used_data_blocks": DATA_BLOCKS - self.sb.free_blocks,
            "block_size": self.sb.block_size,
            "total_inodes": self.sb.num_inodes,
            "free_inodes": self.sb.free_inodes,
            "used_inodes": self.sb.num_inodes - self.sb.free_inodes,
            "disk_size_bytes": TOTAL_BLOCKS * BLOCK_SIZE,
            "metadata_blocks": RESERVED_BLOCKS,
        }
