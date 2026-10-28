"""
Contas de usuarios e grupos, guardadas igual no Linux: arquivos de texto
dentro do proprio sistema de arquivos.

  /etc/passwd   nome:x:uid:gid:home              todo mundo le  (rwr-r-)
  /etc/shadow   nome:hash                        so o root      (rw----)
  /etc/group    nome:x:gid:membro1,membro2       todo mundo le  (rwr-r-)
  /etc/sudoers  um usuario ou %grupo por linha   so o root      (rw----)

O "x" no passwd e no group so avisa que a senha nao ta ali (ta no shadow),
igual no Linux. No group, a lista de membros so tem quem foi colocado no
grupo depois; o grupo primario de cada um e o gid que ta no passwd.

Essa classe faz parte do "kernel": ela le e grava esses arquivos sempre em
modo root (FileSystem.as_root), entao funciona mesmo com o shadow fechado
pra quem ta logado. As regras de quem pode fazer o que (ex.: so o root cria
usuario) tambem ficam aqui, e nao no shell.
"""

from __future__ import annotations

import copy
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, Iterable, Iterator, List, Optional

from fs.constants import (
    FIRST_ID,
    GROUP_PATH,
    MAX_USER_LEN,
    PASSWD_PATH,
    PERM_600,
    PERM_644,
    ROOT_GID,
    ROOT_UID,
    SHADOW_PATH,
    SUDO_GID,
    SUDOERS_PATH,
)
from fs.errors import FSError
from fs.passwords import hash_password, lock, unlock, verify_password, waste_time

if TYPE_CHECKING:
    from fs.filesystem import FileSystem

# nome de usuario/grupo: minusculas, digitos e _, sem comecar com digito (o
# tamanho maximo e conferido separado, com o MAX_USER_LEN). Com isso um nome
# nunca tem ":" nem quebra de linha e nao bagunca o formato dos arquivos
NAME_RE = re.compile(r"[a-z_][a-z0-9_]*")

# permissao com que o kernel regrava cada arquivo de contas, toda vez
FILE_PERMS = {PASSWD_PATH: PERM_644, SHADOW_PATH: PERM_600, GROUP_PATH: PERM_644}

DEFAULT_SUDOERS = (
    "# quem pode usar sudo: um usuario por linha, ou %grupo para todos os membros\n"
    "%sudo\n"
)


@dataclass
class User:
    name: str
    uid: int
    gid: int  # grupo primario
    home: str


@dataclass
class Group:
    name: str
    gid: int
    members: List[str] = field(default_factory=list)


class Accounts:
    def __init__(self, fs: "FileSystem"):
        self.fs = fs
        self.users: Dict[str, User] = {}
        self.hashes: Dict[str, str] = {}  # nome -> texto que ta no shadow
        self.groups: Dict[str, Group] = {}

    # ---- leitura e gravacao dos arquivos de contas ----

    # Lê os arquivos de contas do disco (passwd, shadow e group) e monta 3
    # dicionários na memória: users (dados públicos), hashes (o q tá no shadow)
    # e groups. Roda antes de td comando, pq o root pode ter editado algum
    # desses arquivos na mão, e o q vale é sempre o q tá no disco.
    def load(self) -> None:
        # Vira root por um instante, pq o shadow é 600 e quem tá logado
        # normalmente ñ poderia ler.
        with self.fs.as_root():
            passwd = self._read_lines(PASSWD_PATH)
            shadow = self._read_lines(SHADOW_PATH)
            group = self._read_lines(GROUP_PATH)
        users: Dict[str, User] = {}
        hashes: Dict[str, str] = {}
        groups: Dict[str, Group] = {}
        # Cada linha do passwd vira um User. Só aceita linha c/ 5 campos e
        # números onde tem q ter número; linha torta é ignorada.
        for f in passwd:
            if len(f) == 5 and f[2].isdigit() and f[3].isdigit():
                users[f[0]] = User(f[0], int(f[2]), int(f[3]), f[4])
        for f in shadow:
            if len(f) == 2:
                hashes[f[0]] = f[1]
        for f in group:
            if len(f) == 4 and f[2].isdigit():
                groups[f[0]] = Group(f[0], int(f[2]), [m for m in f[3].split(",") if m])
        # Troca as tabelas antigas pelas novas de uma vez só.
        self.users, self.hashes, self.groups = users, hashes, groups

    # Lê um arquivo de contas e devolve as linhas já separadas em campos.
    def _read_lines(self, path: str) -> List[List[str]]:
        try:
            # Lê o arquivo do disco e transforma de bytes em texto.
            text = self.fs.read_file(path).decode("utf-8", errors="replace")
        except FSError:
            # Arquivo apagado: segue sem essas contas em vez de travar.
            return []
        # Quebra em linhas, pula vazias e comentários (#), e quebra cada linha
        # nos ':'. Ex.: 'ana:x:1000:1000:/home/ana' vira ['ana', 'x', '1000',
        # '1000', '/home/ana'].
        return [line.split(":") for line in text.splitlines()
                if line.strip() and not line.startswith("#")]

    # O caminho inverso do load: pega os dicionários da memória e gera o texto
    # do arquivo, pronto pra gravar.
    def _render(self, path: str) -> bytes:
        users = sorted(self.users.values(), key=lambda u: u.uid)
        # passwd: nome:x:uid:gid:home (o x avisa q a senha ñ tá aqui, tá no
        # shadow).
        if path == PASSWD_PATH:
            lines = [f"{u.name}:x:{u.uid}:{u.gid}:{u.home}" for u in users]
        # shadow: nome:hash.
        elif path == SHADOW_PATH:
            lines = [f"{u.name}:{self.hashes[u.name]}" for u in users if u.name in self.hashes]
        else:
            # group: nome:x:gid:membros separados por vírgula.
            groups = sorted(self.groups.values(), key=lambda g: g.gid)
            lines = [f"{g.name}:x:{g.gid}:{','.join(g.members)}" for g in groups]
        return ("\n".join(lines) + "\n").encode("utf-8")

    # Grava um arquivo de contas no disco.
    def _write_one(self, path: str) -> None:
        with self.fs.as_root():
            # Grava o texto novo por cima do antigo (em modo root).
            num = self.fs.write_file(path, self._render(path), append=False)
            # E SEMPRE devolve o arquivo pra root:root c/ a permissão certa
            # (shadow 600, os outros 644). Assim, msm se alguém apagar o shadow
            # e ele for recriado, já nasce fechado.
            self.fs.set_attrs(num, owner_uid=ROOT_UID, gid=ROOT_GID, perm=FILE_PERMS[path])

    # Faz uma cópia dos 3 dicionários: é o 'backup' pra poder desfazer se der
    # erro.
    def _snapshot(self):
        return copy.deepcopy((self.users, self.hashes, self.groups))

    # Grava vários arquivos de contas em sequência, no esquema 'tudo ou nada'.
    def _save(self, paths: List[str], backup) -> None:
        written: List[str] = []
        try:
            # Grava um por um e anota quais já foram.
            for path in paths:
                self._write_one(path)
                written.append(path)
        # Deu erro no meio (ex.: disco cheio): volta a memória pro backup,
        # regrava os q já tinham sido gravados c/ o conteúdo antigo e repassa o
        # erro. Ñ fica nada pela metade.
        except FSError:
            self.users, self.hashes, self.groups = backup
            for path in written:
                self._write_one(path)
            raise

    # ---- consultas ----

    # Busca o usuário pelo nome; se ñ existe, dá erro. Usada qd o nome TEM q
    # existir (chown, su do root, passwd...).
    def get_user(self, name: str) -> User:
        user = self.users.get(name)
        if user is None:
            raise FSError(f"usuário '{name}' não existe")
        return user

    # Msm coisa do get_user, só q p/ grupo (chown, chgrp, usermod...).
    def get_group(self, name: str) -> Group:
        group = self.groups.get(name)
        if group is None:
            raise FSError(f"grupo '{name}' não existe")
        return group

    # O contrário do get_user: acha o usuário pelo número (ex.: 'quem é o uid
    # 1000?'). Devolve None se ñ achar.
    def user_by_uid(self, uid: int) -> Optional[User]:
        for user in self.users.values():
            if user.uid == uid:
                return user
        return None

    # Número -> nome do usuário, pro ls -l, prompt etc. Se ñ achar, mostra o
    # próprio número (ex.: arquivo de um usuário q ñ existe mais).
    def user_name(self, uid: int) -> str:
        user = self.user_by_uid(uid)
        return user.name if user else str(uid)  # dono sem conta: mostra o numero mesmo

    # Msm coisa do user_name, só q p/ grupo.
    def group_name(self, gid: int) -> str:
        for group in self.groups.values():
            if group.gid == gid:
                return group.name
        return str(gid)

    # Lista td mundo em ordem de UID, pro comando users.
    def user_names(self) -> List[str]:
        return [u.name for u in sorted(self.users.values(), key=lambda u: u.uid)]

    # Devolve a lista de grupos de uma pessoa. É essa lista q vai pro
    # effective_access decidir se ela cai na classe 'grupo'.
    def group_ids_of(self, user: User) -> List[int]:
        """Grupo primario + os grupos em que a pessoa foi colocada depois."""
        # Começa pelo grupo primário (o do passwd: o grupo próprio da pessoa).
        gids = [user.gid]
        for group in sorted(self.groups.values(), key=lambda g: g.gid):
            # Depois soma td grupo em q o nome dela aparece na lista de membros
            # (no /etc/group).
            if user.name in group.members and group.gid not in gids:
                gids.append(group.gid)
        return gids

    # ---- regras ----

    # Trava de 'só o root pode': se quem tá logado ñ é o root (uid 0), para c/
    # 'Permissão negada'. Usada nos comandos de administração (useradd,
    # groupadd, usermod, gpasswd, passwd -l, reset).
    def require_root(self, command: str) -> None:
        if self.fs.uid != ROOT_UID:
            raise FSError(f"{command}: Permissão negada")

    # Só recusa senha vazia (pra um Enter sem querer ñ deixar a conta sem
    # senha). Ñ tem regra de tamanho: decisão do relatório, ambiente
    # controlado.
    @staticmethod
    def check_password(password: str) -> None:
        if not password:
            raise FSError("a senha não pode ser vazia")

    # Confere se um nome de usuário ou grupo é válido.
    @staticmethod
    def check_name(name: str) -> None:
        # Só minúsculas, dígitos e _, sem começar c/ dígito, até 15 chars.
        # Assim um nome nunca tem ':' nem quebra de linha, q bagunçariam o
        # formato dos arquivos.
        if len(name) > MAX_USER_LEN or not NAME_RE.fullmatch(name):
            raise FSError(f"'{name}': nome inválido (letras minúsculas, dígitos e _, "
                          f"sem começar com dígito, até {MAX_USER_LEN} caracteres)")

    # Escolhe um número novo de usuário ou grupo.
    @staticmethod
    def _free_id(used: Iterable[int]) -> int:
        taken = set(used)
        n = FIRST_ID
        # Começa em 1000 e vai subindo até achar um número q ninguém usa.
        while n in taken:
            n += 1
        return n

    # ---- operacoes ----

    # Roda só uma vez, qd o disco é formatado: cria as contas q já nascem c/ o
    # sistema.
    def initialize(self, root_password: str) -> None:
        # Cria o usuário root (uid 0), c/ a senha definida na formatação já
        # transformada em hash.
        self.users = {"root": User("root", ROOT_UID, ROOT_GID, "/root")}
        self.hashes = {"root": hash_password(root_password)}
        # Cria os grupos root (0) e sudo (27, o msm nº do Ubuntu).
        self.groups = {"root": Group("root", ROOT_GID), "sudo": Group("sudo", SUDO_GID)}
        # Grava os 3 arquivos de contas.
        for path in (SHADOW_PATH, GROUP_PATH, PASSWD_PATH):
            self._write_one(path)
        with self.fs.as_root():
            # Cria o /etc/sudoers c/ a linha %sudo (quem tá no grupo sudo pode
            # usar sudo) e fecha ele (600).
            num = self.fs.write_file(SUDOERS_PATH, DEFAULT_SUDOERS.encode("utf-8"), append=False)
            self.fs.set_attrs(num, owner_uid=ROOT_UID, gid=ROOT_GID, perm=PERM_600)

    # Confere usuário + senha. É o coração do login (e tb é usada pelo su, sudo
    # e passwd). Devolve a pessoa se td bate, ou None se ñ bate, SEM contar o
    # motivo.
    def authenticate(self, name: str, password: str) -> Optional[User]:
        # Relê as contas do disco antes de conferir.
        self.load()
        # Busca a pessoa pelo nome e o texto dela no shadow. O .get devolve
        # None se ñ existir.
        user, stored = self.users.get(name), self.hashes.get(name)
        # Usuário ñ existe: gasta o msm tempo de uma conferência de vdd
        # (waste_time) e responde None, igual a uma senha errada. Assim ninguém
        # descobre quais contas existem.
        if user is None or stored is None:
            waste_time(password)
            return None
        # Existe: confere a senha (scrypt). Senha errada ou conta bloqueada ->
        # None.
        return user if verify_password(password, stored) else None

    # Faz o login de fato.
    def login(self, name: str, password: str) -> Optional[User]:
        # Confere nome e senha.
        user = self.authenticate(name, password)
        if user is not None:
            # Deu certo: avisa o kernel quem tá usando o sistema agora. É tipo
            # entregar o crachá: td checagem dali pra frente usa esse uid.
            self.fs.set_credentials(user.uid, user.gid)
        return user

    # O comando su: trocar de usuário sem sair do programa.
    def switch_user(self, name: str, password: Optional[str]) -> User:
        # Quem pede é o root? Troca direto, sem senha (igual Linux).
        if self.fs.uid == ROOT_UID:
            user = self.get_user(name)
        else:
            # Senão, precisa da senha do usuário de DESTINO (ex.: 'su bruno'
            # pede a senha do bruno).
            user = self.authenticate(name, password or "")
            if user is None:
                raise FSError("su: Falha de autenticação")
        # Troca o crachá.
        self.fs.set_credentials(user.uid, user.gid)
        return user

    # Confere td antes de criar uma conta: é root? o nome é válido? já existe?
    # Fica separado do useradd pq o shell chama ela ANTES de pedir a senha, pra
    # pessoa ñ digitar senha à toa se o pedido vai ser recusado.
    def check_useradd(self, name: str) -> None:
        self.require_root("useradd")
        self.check_name(name)
        if name in self.users or name in self.groups:
            raise FSError(f"useradd: '{name}' já existe")

    # Cria uma conta nova inteira: usuário, grupo próprio, senha e pasta
    # pessoal (home).
    def useradd(self, name: str, password: str) -> User:
        self.check_useradd(name)
        self.check_password(password)
        # Escolhe o número do usuário (UID): o 1º livre a partir de 1000.
        uid = self._free_id(u.uid for u in self.users.values())
        group_ids = {g.gid for g in self.groups.values()}
        # O grupo próprio ganha o msm número, se tiver livre.
        gid = uid if uid not in group_ids else self._free_id(group_ids)
        user = User(name, uid, gid, f"/home/{name}")
        # Transforma a senha em hash (~0,6 s). A senha em si ñ é guardada.
        hashed = hash_password(password)

        # a home vem primeiro: se ja existir alguma coisa com esse nome, falha
        # aqui, antes de mexer nas contas
        with self.fs.as_root():
            # Cria a home /home/<nome> e entrega pra pessoa c/ permissão 600
            # (só ela lê e escreve).
            num = self.fs.mkdir(user.home)
            self.fs.set_attrs(num, owner_uid=uid, gid=gid, perm=PERM_600)

        # Guarda uma cópia das contas antes de mexer, pra poder desfazer.
        backup = self._snapshot()
        self.users[name] = user
        self.hashes[name] = hashed
        self.groups[name] = Group(name, gid)
        try:
            # Grava shadow, group e passwd nessa ordem. O shadow vem 1º pra
            # nunca existir usuário no passwd sem senha no shadow.
            self._save([SHADOW_PATH, GROUP_PATH, PASSWD_PATH], backup)
        except FSError:
            with self.fs.as_root():
                # Se a gravação falhou, apaga a home q tinha sido criada.
                self.fs.rmdir(user.home)
            raise
        return user

    # O comando passwd: trocar uma senha.
    def change_password(self, name: str, new_password: str,
                        current_password: Optional[str] = None) -> None:
        user = self.get_user(name)
        # Quem pede ñ é root? Aí tem regras: só pode trocar a PRÓPRIA senha e
        # tem q acertar a senha atual.
        if self.fs.uid != ROOT_UID:
            # Tentando trocar a senha de outra pessoa -> negado.
            if user.uid != self.fs.uid:
                raise FSError("passwd: Permissão negada")
            stored = self.hashes.get(name, "")
            # Confere a senha atual (scrypt). Errou -> negado.
            if current_password is None or not verify_password(current_password, stored):
                raise FSError("passwd: senha atual incorreta")
        self.check_password(new_password)
        # Gera o hash da senha nova, c/ um salt novo.
        hashed = hash_password(new_password)
        backup = self._snapshot()
        self.hashes[name] = hashed
        # Grava só o shadow (é o único arquivo q muda).
        self._save([SHADOW_PATH], backup)

    # O groupadd: cria um grupo novo (só root).
    def groupadd(self, name: str) -> Group:
        self.require_root("groupadd")
        self.check_name(name)
        if name in self.groups:
            raise FSError(f"groupadd: grupo '{name}' já existe")
        # Pega o 1º número de grupo livre a partir de 1000.
        gid = self._free_id(g.gid for g in self.groups.values())
        backup = self._snapshot()
        group = Group(name, gid)
        self.groups[name] = group
        # Grava o /etc/group.
        self._save([GROUP_PATH], backup)
        return group

    # O usermod -aG: coloca alguém em um ou mais grupos (só root). É assim q se
    # compartilha arquivo c/ um grupo, ou q se dá sudo pra alguém (usermod -aG
    # sudo ana).
    def add_to_groups(self, user_name: str, group_names: List[str]) -> None:
        self.require_root("usermod")
        self.get_user(user_name)
        # Confere se TODOS os grupos existem antes de mexer em qq um. Se um ñ
        # existir, dá erro aqui e nada muda.
        groups = [self.get_group(g) for g in group_names]
        backup = self._snapshot()
        for group in groups:
            # Acrescenta o nome na lista de membros (se já tá lá, ñ duplica).
            if user_name not in group.members:
                group.members.append(user_name)
        self._save([GROUP_PATH], backup)

    # O gpasswd -d: tira alguém de um grupo (só root). O efeito é na hora: se a
    # pessoa lia algo pelo grupo, na próxima tentativa já ñ lê.
    def remove_from_group(self, user_name: str, group_name: str) -> None:
        self.require_root("gpasswd")
        user = self.get_user(user_name)
        group = self.get_group(group_name)
        # Ñ deixa tirar alguém do próprio grupo primário (o grupo q tem o msm
        # nome da pessoa). Ele fica no passwd, ñ na lista de membros, e sem ele
        # os arquivos novos da pessoa iam ficar sem o grupo dela.
        if group.gid == user.gid:
            raise FSError(f"gpasswd: '{group_name}' é o grupo primário de {user_name}, não dá pra tirar")
        if user_name not in group.members:
            raise FSError(f"gpasswd: {user_name} não é membro de '{group_name}'")
        backup = self._snapshot()
        # Tira o nome da lista de membros e grava o /etc/group.
        group.members.remove(user_name)
        self._save([GROUP_PATH], backup)

    # ---- sudo ----

    # Lê o /etc/sudoers e devolve a lista de quem pode usar sudo, tipo
    # ['%sudo', 'bruno']. Só lê, ñ decide nada.
    def _sudoers_entries(self) -> List[str]:
        # Vira root por um instante, pq o sudoers é 600.
        with self.fs.as_root():
            try:
                text = self.fs.read_file(SUDOERS_PATH).decode("utf-8", errors="replace")
            except FSError:
                # Sem arquivo -> lista vazia -> ninguém usa sudo. Na dúvida,
                # nega.
                return []
        entries = []
        for line in text.splitlines():
            line = line.strip()
            # Pula linha vazia e comentário.
            if line and not line.startswith("#"):
                # Guarda só a 1ª palavra da linha (o nome ou o %grupo). Assim
                # uma linha no formato do Linux ('ana ALL=(ALL) ALL') tb
                # funciona.
                entries.append(line.split()[0])
        return entries

    # Responde 'essa pessoa pode usar sudo?' olhando a lista do
    # _sudoers_entries.
    def can_sudo(self, user: User) -> bool:
        # Nomes de td grupo da pessoa (primário + adicionais).
        group_names = {self.group_name(g) for g in self.group_ids_of(user)}
        for entry in self._sudoers_entries():
            # A linha é o nome dela? Pode.
            if entry == user.name:
                return True
            # A linha é %grupo e ela tá nesse grupo? Pode. O entry[1:] tira o %
            # (ex.: '%sudo' -> 'sudo').
            if entry.startswith("%") and entry[1:] in group_names:
                return True
        # Ñ achou em lugar nenhum -> ñ pode.
        return False

    # O sudo: deixa alguém autorizado rodar UM comando como root, usando a
    # PRÓPRIA senha (ñ a do root). É usado assim: 'with accounts.sudo(senha):
    # <roda o comando>'.
    @contextmanager
    def sudo(self, password: Optional[str]) -> Iterator[None]:
        # ANTES do comando (o root ñ precisa de nada disso):
        if self.fs.uid != ROOT_UID:
            me = self.user_by_uid(self.fs.uid)
            # 1) prova q é vc msm: confere a SUA senha. Conta bloqueada tb
            # falha aqui.
            if me is None or self.authenticate(me.name, password or "") is None:
                raise FSError("sudo: senha incorreta")
            # 2) vê se vc tá autorizado no /etc/sudoers.
            if not self.can_sudo(me):
                raise FSError(f"sudo: {me.name} não está no arquivo sudoers")

        # DURANTE: guarda quem vc era e qtas trocas de usuário já rolaram...
        saved = (self.fs.uid, self.fs.gid)
        changes = self.fs.cred_changes
        # ...e vira root (uid 0).
        self.fs.uid, self.fs.gid = ROOT_UID, ROOT_GID
        try:
            # Aqui o comando roda, já como root.
            yield
        finally:
            # DEPOIS (o finally roda msm se o comando deu erro): volta a ser
            # quem era. Só ñ volta se o próprio comando trocou de usuário
            # ('sudo su'), pq aí a troca era o objetivo.
            if self.fs.cred_changes == changes:
                self.fs.uid, self.fs.gid = saved

    # O passwd -l / -u: bloqueia ou desbloqueia uma conta (só root). É o jeito
    # de cortar o acesso de alguém, já q ñ existe userdel.
    def set_locked(self, name: str, locked: bool) -> None:
        self.require_root("passwd -l" if locked else "passwd -u")
        self.get_user(name)
        # Ñ deixa bloquear o root, senão o sistema ficava sem administrador.
        if locked and name == "root":
            raise FSError("passwd: não é permitido bloquear o root")
        stored = self.hashes.get(name)
        if stored is None:
            raise FSError(f"passwd: '{name}' não tem senha no shadow")
        backup = self._snapshot()
        # Põe ou tira o ! na frente do hash e grava o shadow. O hash ñ muda,
        # então desbloquear volta a msm senha.
        self.hashes[name] = lock(stored) if locked else unlock(stored)
        self._save([SHADOW_PATH], backup)
