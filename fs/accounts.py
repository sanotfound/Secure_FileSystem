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

    def load(self) -> None:
        """Le passwd, shadow e group do disco pras tabelas em memoria.

        O shell chama isso antes de cada comando, porque o root pode ter
        editado um desses arquivos na mao (ex.: echo >> /etc/group) e o que
        vale e sempre o que ta no disco. Linha mal formada e so ignorada, pra
        nao derrubar o sistema por causa de uma linha torta.
        """
        with self.fs.as_root():
            passwd = self._read_lines(PASSWD_PATH)
            shadow = self._read_lines(SHADOW_PATH)
            group = self._read_lines(GROUP_PATH)
        users: Dict[str, User] = {}
        hashes: Dict[str, str] = {}
        groups: Dict[str, Group] = {}
        for f in passwd:
            if len(f) == 5 and f[2].isdigit() and f[3].isdigit():
                users[f[0]] = User(f[0], int(f[2]), int(f[3]), f[4])
        for f in shadow:
            if len(f) == 2:
                hashes[f[0]] = f[1]
        for f in group:
            if len(f) == 4 and f[2].isdigit():
                groups[f[0]] = Group(f[0], int(f[2]), [m for m in f[3].split(",") if m])
        self.users, self.hashes, self.groups = users, hashes, groups

    def _read_lines(self, path: str) -> List[List[str]]:
        try:
            text = self.fs.read_file(path).decode("utf-8", errors="replace")
        except FSError:
            return []  # arquivo apagado: fica sem essas contas, igual no Linux
        return [line.split(":") for line in text.splitlines()
                if line.strip() and not line.startswith("#")]

    def _render(self, path: str) -> bytes:
        users = sorted(self.users.values(), key=lambda u: u.uid)
        if path == PASSWD_PATH:
            lines = [f"{u.name}:x:{u.uid}:{u.gid}:{u.home}" for u in users]
        elif path == SHADOW_PATH:
            lines = [f"{u.name}:{self.hashes[u.name]}" for u in users if u.name in self.hashes]
        else:
            groups = sorted(self.groups.values(), key=lambda g: g.gid)
            lines = [f"{g.name}:x:{g.gid}:{','.join(g.members)}" for g in groups]
        return ("\n".join(lines) + "\n").encode("utf-8")

    def _write_one(self, path: str) -> None:
        with self.fs.as_root():
            num = self.fs.write_file(path, self._render(path), append=False)
            # sempre root:root e com a permissao padrao do arquivo, mesmo se
            # alguem tiver apagado ele e o write_file tiver criado de novo --
            # assim o shadow nunca fica aberto
            self.fs.set_attrs(num, owner_uid=ROOT_UID, gid=ROOT_GID, perm=FILE_PERMS[path])

    def _snapshot(self):
        return copy.deepcopy((self.users, self.hashes, self.groups))

    def _save(self, paths: List[str], backup) -> None:
        """Grava os arquivos na ordem que vieram, tudo ou nada.

        Se o disco encher no meio, desfaz: o arquivo que deu erro ja ficou
        como tava (o write_data e tudo ou nada), entao so precisa voltar os
        que ja tinham sido gravados antes dele.
        """
        written: List[str] = []
        try:
            for path in paths:
                self._write_one(path)
                written.append(path)
        except FSError:
            self.users, self.hashes, self.groups = backup
            for path in written:
                self._write_one(path)
            raise

    # ---- consultas ----

    def get_user(self, name: str) -> User:
        user = self.users.get(name)
        if user is None:
            raise FSError(f"usuário '{name}' não existe")
        return user

    def get_group(self, name: str) -> Group:
        group = self.groups.get(name)
        if group is None:
            raise FSError(f"grupo '{name}' não existe")
        return group

    def user_by_uid(self, uid: int) -> Optional[User]:
        for user in self.users.values():
            if user.uid == uid:
                return user
        return None

    def user_name(self, uid: int) -> str:
        user = self.user_by_uid(uid)
        return user.name if user else str(uid)  # dono sem conta: mostra o numero mesmo

    def group_name(self, gid: int) -> str:
        for group in self.groups.values():
            if group.gid == gid:
                return group.name
        return str(gid)

    def user_names(self) -> List[str]:
        return [u.name for u in sorted(self.users.values(), key=lambda u: u.uid)]

    def group_ids_of(self, user: User) -> List[int]:
        """Grupo primario + os grupos em que a pessoa foi colocada depois."""
        gids = [user.gid]
        for group in sorted(self.groups.values(), key=lambda g: g.gid):
            if user.name in group.members and group.gid not in gids:
                gids.append(group.gid)
        return gids

    # ---- regras ----

    def require_root(self, command: str) -> None:
        if self.fs.uid != ROOT_UID:
            raise FSError(f"{command}: Permissão negada")

    @staticmethod
    def check_password(password: str) -> None:
        # sem regra de tamanho nem de simbolo (ambiente controlado, aqui nao
        # faz diferenca); so nao aceita senha vazia, pra um Enter sem querer
        # nao deixar a conta sem senha
        if not password:
            raise FSError("a senha não pode ser vazia")

    @staticmethod
    def check_name(name: str) -> None:
        if len(name) > MAX_USER_LEN or not NAME_RE.fullmatch(name):
            raise FSError(f"'{name}': nome inválido (letras minúsculas, dígitos e _, "
                          f"sem começar com dígito, até {MAX_USER_LEN} caracteres)")

    @staticmethod
    def _free_id(used: Iterable[int]) -> int:
        taken = set(used)
        n = FIRST_ID
        while n in taken:
            n += 1
        return n

    # ---- operacoes ----

    def initialize(self, root_password: str) -> None:
        """Contas que ja nascem na formatacao: o usuario root, os grupos root
        e sudo e o /etc/sudoers padrao."""
        self.users = {"root": User("root", ROOT_UID, ROOT_GID, "/root")}
        self.hashes = {"root": hash_password(root_password)}
        self.groups = {"root": Group("root", ROOT_GID), "sudo": Group("sudo", SUDO_GID)}
        for path in (SHADOW_PATH, GROUP_PATH, PASSWD_PATH):
            self._write_one(path)
        with self.fs.as_root():
            num = self.fs.write_file(SUDOERS_PATH, DEFAULT_SUDOERS.encode("utf-8"), append=False)
            self.fs.set_attrs(num, owner_uid=ROOT_UID, gid=ROOT_GID, perm=PERM_600)

    def authenticate(self, name: str, password: str) -> Optional[User]:
        """Confere usuario e senha. Devolve None se o usuario nao existe, se a
        senha ta errada ou se a conta ta bloqueada -- sem dizer qual dos tres,
        e demorando o mesmo tempo nos tres casos."""
        self.load()
        user, stored = self.users.get(name), self.hashes.get(name)
        if user is None or stored is None:
            waste_time(password)
            return None
        return user if verify_password(password, stored) else None

    def login(self, name: str, password: str) -> Optional[User]:
        user = self.authenticate(name, password)
        if user is not None:
            self.fs.set_credentials(user.uid, user.gid)
        return user

    def switch_user(self, name: str, password: Optional[str]) -> User:
        """su: troca o usuario atual. O root troca sem senha, igual no Linux."""
        if self.fs.uid == ROOT_UID:
            user = self.get_user(name)
        else:
            user = self.authenticate(name, password or "")
            if user is None:
                raise FSError("su: Falha de autenticação")
        self.fs.set_credentials(user.uid, user.gid)
        return user

    def check_useradd(self, name: str) -> None:
        """Tudo que o useradd confere antes de criar a conta. O shell chama
        isso antes de pedir a senha, pra pessoa nao digitar senha a toa."""
        self.require_root("useradd")
        self.check_name(name)
        if name in self.users or name in self.groups:
            raise FSError(f"useradd: '{name}' já existe")

    def useradd(self, name: str, password: str) -> User:
        self.check_useradd(name)
        self.check_password(password)
        uid = self._free_id(u.uid for u in self.users.values())
        group_ids = {g.gid for g in self.groups.values()}
        # grupo proprio com o mesmo numero do usuario, se esse numero tiver livre
        gid = uid if uid not in group_ids else self._free_id(group_ids)
        user = User(name, uid, gid, f"/home/{name}")
        hashed = hash_password(password)

        # a home vem primeiro: se ja existir alguma coisa com esse nome, falha
        # aqui, antes de mexer nas contas
        with self.fs.as_root():
            num = self.fs.mkdir(user.home)
            self.fs.set_attrs(num, owner_uid=uid, gid=gid, perm=PERM_600)

        backup = self._snapshot()
        self.users[name] = user
        self.hashes[name] = hashed
        self.groups[name] = Group(name, gid)
        try:
            # shadow antes do passwd: assim nunca fica um usuario no passwd
            # sem senha no shadow
            self._save([SHADOW_PATH, GROUP_PATH, PASSWD_PATH], backup)
        except FSError:
            with self.fs.as_root():
                self.fs.rmdir(user.home)
            raise
        return user

    def change_password(self, name: str, new_password: str,
                        current_password: Optional[str] = None) -> None:
        """passwd: o usuario troca a propria senha dizendo a atual; o root
        troca a de qualquer um sem precisar da atual."""
        user = self.get_user(name)
        if self.fs.uid != ROOT_UID:
            if user.uid != self.fs.uid:
                raise FSError("passwd: Permissão negada")
            stored = self.hashes.get(name, "")
            if current_password is None or not verify_password(current_password, stored):
                raise FSError("passwd: senha atual incorreta")
        self.check_password(new_password)
        hashed = hash_password(new_password)
        backup = self._snapshot()
        self.hashes[name] = hashed
        self._save([SHADOW_PATH], backup)

    def groupadd(self, name: str) -> Group:
        self.require_root("groupadd")
        self.check_name(name)
        if name in self.groups:
            raise FSError(f"groupadd: grupo '{name}' já existe")
        gid = self._free_id(g.gid for g in self.groups.values())
        backup = self._snapshot()
        group = Group(name, gid)
        self.groups[name] = group
        self._save([GROUP_PATH], backup)
        return group

    def add_to_groups(self, user_name: str, group_names: List[str]) -> None:
        """usermod -aG: coloca o usuario em um ou mais grupos."""
        self.require_root("usermod")
        self.get_user(user_name)
        # confere se TODOS os grupos existem antes de mexer em qualquer um:
        # "usermod -aG alunos,naoexiste ana" nao pode deixar a ana so no alunos
        groups = [self.get_group(g) for g in group_names]
        backup = self._snapshot()
        for group in groups:
            if user_name not in group.members:
                group.members.append(user_name)
        self._save([GROUP_PATH], backup)

    def remove_from_group(self, user_name: str, group_name: str) -> None:
        """gpasswd -d: tira o usuario de um grupo."""
        self.require_root("gpasswd")
        user = self.get_user(user_name)
        group = self.get_group(group_name)
        if group.gid == user.gid:
            # o grupo primario fica no passwd, nao na lista de membros -- e
            # sem ele os arquivos novos da pessoa iam ficar sem grupo dela
            raise FSError(f"gpasswd: '{group_name}' é o grupo primário de {user_name}, não dá pra tirar")
        if user_name not in group.members:
            raise FSError(f"gpasswd: {user_name} não é membro de '{group_name}'")
        backup = self._snapshot()
        group.members.remove(user_name)
        self._save([GROUP_PATH], backup)

    # ---- sudo ----

    def _sudoers_entries(self) -> List[str]:
        # uma entrada por linha: "ana" (usuario) ou "%sudo" (grupo). So a
        # primeira palavra conta, entao uma linha no formato do Linux
        # ("ana ALL=(ALL) ALL") tambem funciona
        with self.fs.as_root():
            try:
                text = self.fs.read_file(SUDOERS_PATH).decode("utf-8", errors="replace")
            except FSError:
                return []  # sem sudoers, ninguem usa sudo
        entries = []
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line.split()[0])
        return entries

    def can_sudo(self, user: User) -> bool:
        group_names = {self.group_name(g) for g in self.group_ids_of(user)}
        for entry in self._sudoers_entries():
            if entry == user.name:
                return True
            if entry.startswith("%") and entry[1:] in group_names:
                return True
        return False

    @contextmanager
    def sudo(self, password: Optional[str]) -> Iterator[None]:
        """Roda UM comando como root, se a pessoa provar quem e e estiver no
        sudoers. Uso: `with accounts.sudo(senha): <roda o comando>`.

        A ordem e a do Linux: primeiro a senha (da propria pessoa, nao a do
        root), depois o sudoers. O root nao precisa de nada.
        """
        if self.fs.uid != ROOT_UID:
            me = self.user_by_uid(self.fs.uid)
            # o authenticate e o mesmo do login, entao conta bloqueada tambem
            # nao passa aqui
            if me is None or self.authenticate(me.name, password or "") is None:
                raise FSError("sudo: senha incorreta")
            if not self.can_sudo(me):
                raise FSError(f"sudo: {me.name} não está no arquivo sudoers")

        saved = (self.fs.uid, self.fs.gid)
        changes = self.fs.cred_changes
        self.fs.uid, self.fs.gid = ROOT_UID, ROOT_GID
        try:
            yield
        finally:
            # volta a ser quem era, mesmo se o comando deu erro. A excecao e
            # quando o proprio comando trocou de usuario ("sudo su", "sudo su
            # bruno"): ai a troca era justamente o que a pessoa queria
            if self.fs.cred_changes == changes:
                self.fs.uid, self.fs.gid = saved

    def set_locked(self, name: str, locked: bool) -> None:
        """passwd -l / passwd -u: bloqueia ou desbloqueia a conta. O hash
        continua guardado (so ganha um "!" na frente), entao desbloquear volta
        a mesma senha de antes."""
        self.require_root("passwd -l" if locked else "passwd -u")
        self.get_user(name)
        if locked and name == "root":
            raise FSError("passwd: não é permitido bloquear o root")
        stored = self.hashes.get(name)
        if stored is None:
            raise FSError(f"passwd: '{name}' não tem senha no shadow")
        backup = self._snapshot()
        self.hashes[name] = lock(stored) if locked else unlock(stored)
        self._save([SHADOW_PATH], backup)
