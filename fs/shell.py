"""
Shell interativo (REPL) que expõe os comandos exigidos no trabalho:
touch, rm, echo (> e >>), cat, cp, mv, ln -s, mkdir, rmdir, ls, cd
Mais alguns comandos de apoio (pwd, stat, df, help, reset) uteis para
demonstrar persistencia e uso do disco, e os comandos de usuarios (login,
useradd, passwd, su, logout, whoami, id, users, groups).

O shell so conversa com o usuario (le comandos, pede senhas, imprime
resultados). Quem decide se algo e permitido e o "kernel" (FileSystem e
Accounts).
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import os
import shlex
import sys

from fs.accounts import Accounts
from fs.constants import ROOT_UID, TYPE_DIR, TYPE_FILE, TYPE_SYMLINK
from fs.filesystem import FileSystem, FSError
from fs.permissions import perm_string

DEFAULT_DISK_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "disco.img")
MAX_LOGIN_ATTEMPTS = 3

# o que _dispatch devolve para encerrar a sessao
EXIT, LOGOUT = "exit", "logout"


def _fmt_time(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _ask_password(prompt: str) -> str:
    # getpass nao mostra o que e digitado. Quando a entrada nao e um
    # terminal (comandos vindos de um arquivo, nos testes automatizados),
    # nao ha o que esconder e a senha e lida como uma linha comum.
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return input(prompt)


def _ask_new_password(user: str) -> str:
    """Pede a senha nova duas vezes (pega erro de digitacao) e recusa vazia."""
    for _ in range(MAX_LOGIN_ATTEMPTS):
        first = _ask_password(f"Nova senha para {user}: ")
        second = _ask_password("Repita a nova senha: ")
        if first != second:
            print("As senhas não conferem.")
            continue
        try:
            Accounts.check_password(first)  # mesma regra que o kernel aplica
        except FSError as exc:
            print(exc)
            continue
        return first
    raise FSError("senha não alterada (tentativas esgotadas)")


class Shell:
    def __init__(self, disk_path: str):
        self.disk_path = disk_path
        self.fs = self._open_disk()

    def _open_disk(self) -> FileSystem:
        if os.path.exists(self.disk_path):
            fs = FileSystem(self.disk_path)
            print(f"Disco existente montado em '{self.disk_path}'.")
            return fs
        print(f"Nenhum disco em '{self.disk_path}': um disco novo de 128 MB será criado.")
        print("Defina a senha do administrador (root).")
        password = _ask_new_password("root")
        fs = FileSystem(self.disk_path, root_password=password)
        print("Disco criado e formatado. Entre como root para criar os usuários.")
        return fs

    def run(self) -> None:
        print("Sistema de Arquivos baseado em i-nodes -- digite 'help' para ver os comandos.")
        while self._login():
            if self._session() == EXIT:
                break
        self.fs.close()
        print("Disco desmontado. Dados persistidos em", self.disk_path)

    def _login(self) -> bool:
        """Tela de login. Devolve False se a entrada acabou ou se as
        tentativas se esgotaram (o programa encerra)."""
        for _ in range(MAX_LOGIN_ATTEMPTS):
            try:
                name = input("login: ").strip()
                password = _ask_password("senha: ")
            except EOFError:
                print()
                return False
            except KeyboardInterrupt:
                print()
                continue
            # mesma mensagem para usuario inexistente, senha errada ou conta
            # bloqueada: quem tenta entrar nao descobre qual foi o caso
            user = self.fs.accounts.login(name, password)
            if user is None:
                print("Login incorreto.")
                continue
            self._go_home()
            return True
        print("Número máximo de tentativas atingido.")
        return False

    def _session(self) -> str:
        """Laço de comandos de um usuario logado. Devolve EXIT ou LOGOUT."""
        while True:
            try:
                line = input(self._prompt())
            except EOFError:
                print()
                return EXIT
            except KeyboardInterrupt:
                print()
                continue

            line = line.strip()
            if not line:
                continue
            try:
                lex = shlex.shlex(line, posix=True, punctuation_chars=">")
                lex.whitespace_split = True
                tokens = list(lex)
            except ValueError as exc:
                print(f"erro de sintaxe: {exc}")
                continue
            if not tokens:
                continue

            try:
                # o root pode ter editado /etc/passwd, /etc/group... a mao no
                # comando anterior; vale sempre o que esta no disco
                self.fs.accounts.load()
                result = self._dispatch(tokens[0], self._expand_tilde(tokens[1:]))
                if result in (EXIT, LOGOUT):
                    return result
            except FSError as exc:
                print(f"erro: {exc}")
            except Exception as exc:  # protecao extra durante demonstracao
                print(f"erro inesperado: {exc}")
            finally:
                self.fs.flush()

    def _current_user(self):
        return self.fs.accounts.user_by_uid(self.fs.uid)

    def _home(self) -> str:
        user = self._current_user()
        return user.home if user else "/"

    def _go_home(self) -> None:
        try:
            self.fs.cd(self._home())
        except FSError:
            print(f"aviso: home '{self._home()}' inacessível, iniciando em /")
            self.fs.cd("/")

    def _prompt(self) -> str:
        user = self.fs.accounts.user_name(self.fs.uid)
        path = self.fs.path_of(self.fs.cwd_inode)
        home = self._home()
        if home != "/" and (path == home or path.startswith(home + "/")):
            path = "~" + path[len(home):]
        sign = "#" if self.fs.uid == ROOT_UID else "$"
        return f"{user}@sofs:{path}{sign} "

    def _expand_tilde(self, args):
        # como no bash: "~" e "~/..." viram a home de quem esta logado
        home = self._home().rstrip("/")
        out = []
        for a in args:
            if a == "~":
                a = home or "/"
            elif a.startswith("~/"):
                a = home + a[1:]
            out.append(a)
        return out

    def _dispatch(self, cmd, args):
        fs = self.fs

        if cmd in ("exit", "quit"):
            return EXIT

        elif cmd == "logout":
            return LOGOUT

        elif cmd == "help":
            self._help()

        elif cmd == "touch":
            for p in args:
                fs.touch(p)

        elif cmd == "rm":
            for p in args:
                fs.rm(p)

        elif cmd == "echo":
            self._echo(args)

        elif cmd == "cat":
            if not args:
                raise FSError("uso: cat <arquivo>")
            for p in args:
                data = fs.read_file(p)
                text = data.decode("utf-8", errors="replace")
                sys.stdout.write(text)
                if not text.endswith("\n"):
                    sys.stdout.write("\n")

        elif cmd == "cp":
            if len(args) != 2:
                raise FSError("uso: cp <origem> <destino>")
            fs.cp(args[0], args[1])

        elif cmd == "mv":
            if len(args) != 2:
                raise FSError("uso: mv <origem> <destino>")
            fs.mv(args[0], args[1])

        elif cmd == "ln":
            if len(args) != 3 or args[0] != "-s":
                raise FSError("uso: ln -s <arquivo_original> <link>")
            fs.ln_s(args[1], args[2])

        elif cmd == "mkdir":
            for p in args:
                fs.mkdir(p)

        elif cmd == "rmdir":
            for p in args:
                fs.rmdir(p)

        elif cmd == "ls":
            paths = [a for a in args if not a.startswith("-")]  # ignora flags como -l
            self._ls(paths[0] if paths else None)

        elif cmd == "cd":
            fs.cd(args[0] if args else self._home())

        elif cmd == "pwd":
            print(fs.path_of(fs.cwd_inode))

        elif cmd == "stat":
            if not args:
                raise FSError("uso: stat <caminho>")
            self._stat(args[0])

        elif cmd in ("df", "info"):
            self._df()

        elif cmd == "reset":
            return self._reset()

        elif cmd == "useradd":
            if len(args) != 1:
                raise FSError("uso: useradd <usuário>")
            fs.accounts.check_useradd(args[0])  # antes de pedir a senha
            fs.accounts.useradd(args[0], _ask_new_password(args[0]))

        elif cmd == "passwd":
            self._passwd(args)

        elif cmd == "su":
            if len(args) > 1:
                raise FSError("uso: su [usuário]")
            target = args[0] if args else "root"
            # o root nao precisa de senha para virar outro usuario
            password = None if fs.uid == ROOT_UID else _ask_password("Senha: ")
            fs.accounts.switch_user(target, password)

        elif cmd == "whoami":
            print(fs.accounts.user_name(fs.uid))

        elif cmd == "id":
            self._id(args)

        elif cmd == "users":
            print(" ".join(fs.accounts.user_names()))

        elif cmd == "groups":
            user = fs.accounts.get_user(args[0]) if args else self._current_user()
            if user is None:
                raise FSError("usuário atual não tem conta")
            print(" ".join(fs.accounts.group_name(g) for g in fs.accounts.group_ids_of(user)))

        else:
            print(f"comando não reconhecido: {cmd} (digite 'help')")

        return None

    def _echo(self, args) -> None:
        fs = self.fs
        if ">>" in args:
            idx = args.index(">>")
            content = " ".join(args[:idx])
            if idx + 1 >= len(args):
                raise FSError("uso: echo \"texto\" >> <arquivo>")
            target = args[idx + 1]
            fs.write_file(target, (content + "\n").encode("utf-8"), append=True)
        elif ">" in args:
            idx = args.index(">")
            content = " ".join(args[:idx])
            if idx + 1 >= len(args):
                raise FSError("uso: echo \"texto\" > <arquivo>")
            target = args[idx + 1]
            fs.write_file(target, (content + "\n").encode("utf-8"), append=False)
        else:
            print(" ".join(args))

    def _passwd(self, args) -> None:
        acc = self.fs.accounts
        if args and args[0] in ("-l", "-u"):
            if len(args) != 2:
                raise FSError("uso: passwd -l <usuário>  |  passwd -u <usuário>")
            locking = args[0] == "-l"
            acc.set_locked(args[1], locking)
            print(f"passwd: conta '{args[1]}' {'bloqueada' if locking else 'desbloqueada'}")
            return
        if len(args) > 1:
            raise FSError("uso: passwd [usuário]")

        me = acc.user_name(self.fs.uid)
        target = args[0] if args else me
        current = None
        if self.fs.uid != ROOT_UID:
            # a regra vale no kernel (change_password); aqui so evita pedir
            # senhas a toa quando a resposta ja vai ser "nao"
            if target != me:
                raise FSError("passwd: Permissão negada")
            current = _ask_password("Senha atual: ")
            if acc.authenticate(me, current) is None:
                raise FSError("passwd: senha atual incorreta")
        acc.change_password(target, _ask_new_password(target), current)
        print("passwd: senha atualizada com sucesso")

    def _id(self, args) -> None:
        acc = self.fs.accounts
        user = acc.get_user(args[0]) if args else self._current_user()
        if user is None:
            raise FSError("usuário atual não tem conta")
        groups = ",".join(f"{g}({acc.group_name(g)})" for g in acc.group_ids_of(user))
        print(f"uid={user.uid}({user.name}) gid={user.gid}({acc.group_name(user.gid)}) grupos={groups}")

    def _ls(self, path) -> None:
        acc = self.fs.accounts
        entries = self.fs.ls(path)
        if not entries:
            return
        for name, inode, num in entries:
            perm = perm_string(inode.perm, inode.type)
            extra = ""
            if inode.type == TYPE_SYMLINK:
                target = self.fs.read_data(num).decode("utf-8", errors="replace")
                extra = f" -> {target}"
            owner = acc.user_name(inode.owner_uid)
            group = acc.group_name(inode.gid)
            print(f"{perm}  {owner:<10} {group:<10} {inode.size:>10}  "
                  f"{_fmt_time(inode.modified_at)}  {name}{extra}")

    def _stat(self, path) -> None:
        fs = self.fs
        acc = fs.accounts
        num = fs.resolve(path, follow_symlink=False)
        inode = fs.read_inode(num)
        type_name = {TYPE_FILE: "arquivo", TYPE_DIR: "diretório", TYPE_SYMLINK: "link simbólico"}[inode.type]
        blocks = fs._iter_blocks(num)  # noqa: SLF001 - uso interno para fins de diagnostico
        print(f"  i-node:        {num}")
        print(f"  nome:          {inode.name}")
        print(f"  tipo:          {type_name}")
        print(f"  dono:          {acc.user_name(inode.owner_uid)} ({inode.owner_uid})")
        print(f"  grupo:         {acc.group_name(inode.gid)} ({inode.gid})")
        print(f"  criador:       {acc.user_name(inode.creator_uid)} ({inode.creator_uid})")
        print(f"  permissões:    {perm_string(inode.perm, inode.type)}")
        print(f"  tamanho:       {inode.size} bytes")
        print(f"  criado em:     {_fmt_time(inode.created_at)}")
        print(f"  modificado em: {_fmt_time(inode.modified_at)}")
        print(f"  blocos usados: {len(blocks)} ({blocks})")

    def _df(self) -> None:
        u = self.fs.usage()
        used_bytes = u["used_data_blocks"] * u["block_size"]
        data_bytes = u["data_blocks"] * u["block_size"]
        meta_bytes = u["metadata_blocks"] * u["block_size"]
        print(f"  disco total:        {_fmt_size(u['disk_size_bytes'])} ({u['total_blocks']} blocos de {u['block_size']}B)")
        print(f"  metadados (SO):     {_fmt_size(meta_bytes)} ({u['metadata_blocks']} blocos)")
        print(f"  área de dados:      {_fmt_size(data_bytes)} ({u['data_blocks']} blocos)")
        print(f"  dados usados:       {_fmt_size(used_bytes)} ({u['used_data_blocks']} blocos, "
              f"{100*u['used_data_blocks']/u['data_blocks']:.2f}%)")
        print(f"  dados livres:       {_fmt_size(data_bytes - used_bytes)} ({u['free_blocks']} blocos)")
        print(f"  i-nodes:            {u['used_inodes']}/{u['total_inodes']} usados "
              f"({u['free_inodes']} livres)")

    def _reset(self):
        # apagar o disco de todos e tarefa de administrador (disponibilidade)
        self.fs.accounts.require_root("reset")
        answer = input("Isso apaga TODO o conteúdo do disco atual. Digite 'sim' para confirmar: ")
        if answer.strip().lower() != "sim":
            print("cancelado.")
            return None
        print("Defina a senha do root do disco novo.")
        password = _ask_new_password("root")
        self.fs.close()
        os.remove(self.disk_path)
        self.fs = FileSystem(self.disk_path, root_password=password)
        print("disco reformatado. Entre de novo.")
        return LOGOUT  # as contas antigas nao existem mais

    def _help(self) -> None:
        print("""Comandos disponíveis:
  Arquivos:
    touch <arquivo>                cria arquivo vazio
    rm <arquivo>                   remove arquivo
    echo "texto" > <arquivo>       cria/sobrescreve arquivo com conteúdo
    echo "texto" >> <arquivo>      adiciona conteúdo ao final do arquivo
    cat <arquivo>                  mostra conteúdo do arquivo
    cp <origem> <destino>          copia arquivo
    mv <origem> <destino>          move/renomeia arquivo ou diretório
    ln -s <original> <link>        cria link simbólico
  Diretórios:
    mkdir <dir>                    cria diretório
    rmdir <dir>                    remove diretório vazio
    ls [dir]                       lista conteúdo do diretório
    cd [dir]                       muda o diretório atual (sem argumento: home)
    pwd                            mostra o diretório atual
  Usuários:
    useradd <usuário>              cria usuário, grupo próprio e home (só root)
    passwd [usuário]               troca a senha (de outro usuário: só root)
    passwd -l|-u <usuário>         bloqueia/desbloqueia a conta (só root)
    su [usuário]                   troca de usuário (padrão: root)
    whoami / id [usuário]          mostra o usuário atual / UID, GID e grupos
    users / groups [usuário]       lista os usuários / grupos de um usuário
    logout                         volta para a tela de login
  Outros:
    stat <caminho>                 mostra os campos do i-node
    df / info                      mostra uso do disco (128 MB)
    reset                          reformata o disco (só root, pede confirmação)
    help                           esta mensagem
    exit / quit                    sai do shell
  Caminhos aceitam ~ (sua home), . e ..""")


def _force_utf8() -> None:
    """Evita mojibake de acentos no console do Windows, que por padrão usa cp1252."""
    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, stream_name)
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main() -> None:
    _force_utf8()
    parser = argparse.ArgumentParser(description="Sistema de Arquivos baseado em i-nodes")
    parser.add_argument("--disk", default=DEFAULT_DISK_PATH, help="caminho do arquivo de disco (imagem de 128MB)")
    args = parser.parse_args()

    try:
        shell = Shell(args.disk)
    except (FSError, EOFError, KeyboardInterrupt) as exc:
        print(f"erro: {exc}" if str(exc) else "cancelado.")
        sys.exit(1)
    shell.run()


if __name__ == "__main__":
    main()
