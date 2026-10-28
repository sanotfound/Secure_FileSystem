"""
Shell interativo (REPL) que expõe os comandos exigidos no trabalho:
touch, rm, echo (> e >>), cat, cp, mv, ln -s, mkdir, rmdir, ls, cd
Mais alguns comandos de apoio (pwd, stat, df, help, reset) uteis para
demonstrar persistencia e uso do disco, os comandos de usuarios (login,
useradd, passwd, su, logout, whoami, id, users, groups), os de permissao
(chmod, chown, chgrp) e os de grupo e administracao (groupadd, usermod,
gpasswd, sudo).

O shell so conversa com a pessoa (le comando, pede senha, mostra o
resultado). Quem decide se pode ou nao e o "kernel" (FileSystem e
Accounts) -- o shell nunca libera nada sozinho.
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
from fs.permissions import GROUP, OTHER, OWNER, ROOT, bits_string, perm_string

DEFAULT_DISK_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "disco.img")
MAX_LOGIN_ATTEMPTS = 3

# o que o _dispatch devolve quando a sessao tem que acabar
EXIT, LOGOUT = "exit", "logout"


def _fmt_time(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


# Pede uma senha.
def _ask_password(prompt: str) -> str:
    # Num terminal de vdd, usa o getpass: o q a pessoa digita ñ aparece na
    # tela. Qd os comandos vêm de um arquivo (testes automatizados), lê como
    # linha normal.
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return input(prompt)


# Pede uma senha NOVA (useradd, passwd, formatação do disco).
def _ask_new_password(user: str) -> str:
    for _ in range(MAX_LOGIN_ATTEMPTS):
        # Pede 2x, pra pegar erro de digitação.
        first = _ask_password(f"Nova senha para {user}: ")
        second = _ask_password("Repita a nova senha: ")
        # As duas ñ batem -> tenta de novo (até 3x).
        if first != second:
            print("As senhas não conferem.")
            continue
        try:
            # Usa a msm regra do kernel (ñ aceita senha vazia).
            Accounts.check_password(first)
        except FSError as exc:
            print(exc)
            continue
        return first
    raise FSError("senha não definida (tentativas esgotadas)")


class Shell:
    def __init__(self, disk_path: str):
        self.disk_path = disk_path
        self.fs = self._open_disk()

    # Abre o disco: se o arquivo existe, monta; se ñ, pede a senha do root e
    # formata um disco novo de 128 MB.
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

    # O ciclo do programa inteiro: tela de login -> sessão de comandos.
    # 'logout' volta pro login; 'exit' fecha o programa.
    def run(self) -> None:
        print("Sistema de Arquivos baseado em i-nodes -- digite 'help' para ver os comandos.")
        while self._login():
            if self._session() == EXIT:
                break
        self.fs.close()
        print("Disco desmontado. Dados persistidos em", self.disk_path)

    # A tela de login.
    def _login(self) -> bool:
        # Até 3 tentativas. O limite é por execução do programa, ñ por conta:
        # reabrindo, ganha mais 3.
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
            # Manda conferir nome e senha (cada conferência leva ~0,5 s por
            # causa do scrypt).
            user = self.fs.accounts.login(name, password)
            if user is None:
                # A msm msg pra usuário q ñ existe, senha errada ou conta
                # bloqueada.
                print("Login incorreto.")
                continue
            # Entrou: vai pra pasta pessoal.
            self._go_home()
            return True
        # Errou 3x: o programa fecha.
        print("Número máximo de tentativas atingido.")
        return False

    # A sessão de quem tá logado: um laço infinito q lê um comando, executa e
    # volta a esperar o próximo. O shell ñ decide nada sozinho: só repassa pro
    # kernel.
    def _session(self) -> str:
        while True:
            try:
                # Mostra o prompt (ex.: ana@sofs:~$) e espera a pessoa digitar.
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
                # Quebra a linha em pedaços como um terminal faz (respeitando
                # aspas): 'chmod 600 notas.txt' -> ['chmod', '600',
                # 'notas.txt'].
                lex = shlex.shlex(line, posix=True, punctuation_chars=">")
                lex.whitespace_split = True
                tokens = list(lex)
            except ValueError as exc:
                print(f"erro de sintaxe: {exc}")
                continue
            if not tokens:
                continue

            try:
                # Relê as contas do disco (o root pode ter mudado algo no
                # comando anterior).
                self.fs.accounts.load()
                # Manda o comando pro roteador (_dispatch), já trocando ~ pela
                # home.
                result = self._dispatch(tokens[0], self._expand_tilde(tokens[1:]))
                if result in (EXIT, LOGOUT):
                    return result
            # Se o kernel recusou (ex.: Permissão negada), mostra o erro e
            # segue.
            except FSError as exc:
                print(f"erro: {exc}")
            except KeyboardInterrupt:
                # Ctrl+C no meio de um comando (ex.: pedindo senha no sudo ou
                # no useradd): cancela so esse comando, nao o programa todo.
                # Se tava no sudo, o finally dele ja devolveu as credenciais
                print("\ncancelado.")
            except EOFError:
                # a entrada acabou no meio de um comando (ex.: arquivo de
                # comandos terminou bem na hora de pedir uma senha)
                print()
                return EXIT
            except Exception as exc:  # protecao extra durante demonstracao
                print(f"erro inesperado: {exc}")
            finally:
                # No fim de TODO comando, força a gravação no disco de vdd.
                self.fs.flush()

    # Quem tá logado agora (procura a conta pelo uid).
    def _current_user(self):
        return self.fs.accounts.user_by_uid(self.fs.uid)

    # A pasta pessoal de quem tá logado ('/' se ñ achar a conta).
    def _home(self) -> str:
        user = self._current_user()
        return user.home if user else "/"

    # 'Vai pra home': usado logo depois do login.
    def _go_home(self) -> None:
        try:
            self.fs.cd(self._home())
        except FSError:
            print(f"aviso: home '{self._home()}' inacessível, iniciando em /")
            self.fs.cd("/")

    # Monta o texto do prompt, tipo 'ana@sofs:~$'. Só lê informação, ñ muda
    # nada.
    def _prompt(self) -> str:
        # Quem: traduz o uid (número) pro nome.
        user = self.fs.accounts.user_name(self.fs.uid)
        # Onde: transforma a pasta atual (guardada como nº de i-node) no
        # caminho em texto.
        path = self.fs.path_of(self.fs.cwd_inode)
        home = self._home()
        # Se tá na própria pasta pessoal ou dentro dela, troca esse começo por
        # ~.
        if home != "/" and (path == home or path.startswith(home + "/")):
            path = "~" + path[len(home):]
        # # pro root, $ pro resto.
        sign = "#" if self.fs.uid == ROOT_UID else "$"
        return f"{user}@sofs:{path}{sign} "

    # Troca ~ e ~/... pelo caminho da home, pq o kernel ñ entende ~ (igual o
    # bash faz).
    def _expand_tilde(self, args):
        home = self._home().rstrip("/")
        out = []
        for a in args:
            if a == "~":
                a = home or "/"
            elif a.startswith("~/"):
                a = home + a[1:]
            out.append(a)
        return out

    # O 'roteador': olha o nome do comando e chama a função certa do kernel. Ñ
    # confere permissão nenhuma: quem decide é sempre o kernel.
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
            flags = "".join(a[1:] for a in args if a.startswith("-"))
            paths = [a for a in args if not a.startswith("-")]
            self._ls(paths[0] if paths else None, long="l" in flags)

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

        # chmod <modo> <arquivos...> -> chama o fs.chmod p/ cada arquivo.
        elif cmd == "chmod":
            if len(args) < 2:
                raise FSError("uso: chmod <modo> <arquivo...>  (ex.: chmod 640 a.txt, chmod o-r a.txt)")
            for p in args[1:]:
                fs.chmod(p, args[0])

        # 'ana' = só dono, 'ana:alunos' = dono e grupo, ':alunos' = só grupo.
        elif cmd == "chown":
            if len(args) < 2:
                raise FSError("uso: chown <dono>[:<grupo>] <arquivo...>  ou  chown :<grupo> <arquivo...>")
            owner, sep, group = args[0].partition(":")
            if (sep and not group) or not (owner or group):
                raise FSError("uso: chown <dono>[:<grupo>] <arquivo...>  ou  chown :<grupo> <arquivo...>")
            for p in args[1:]:
                fs.chown(p, owner or None, group or None)

        elif cmd == "chgrp":
            if len(args) < 2:
                raise FSError("uso: chgrp <grupo> <arquivo...>")
            for p in args[1:]:
                fs.chgrp(p, args[0])

        elif cmd == "useradd":
            if len(args) != 1:
                raise FSError("uso: useradd <usuário>")
            fs.accounts.check_useradd(args[0])  # confere tudo antes, pra nao pedir senha a toa
            fs.accounts.useradd(args[0], _ask_new_password(args[0]))

        elif cmd == "passwd":
            self._passwd(args)

        elif cmd == "su":
            if len(args) > 1:
                raise FSError("uso: su [usuário]")
            target = args[0] if args else "root"
            # o root nao precisa de senha pra virar outro usuario
            password = None if fs.uid == ROOT_UID else _ask_password("Senha: ")
            fs.accounts.switch_user(target, password)

        elif cmd == "groupadd":
            if len(args) != 1:
                raise FSError("uso: groupadd <grupo>")
            fs.accounts.groupadd(args[0])

        elif cmd == "usermod":
            # so a forma "usermod -aG grupo1,grupo2 usuario" (o -G sem o -a
            # do Linux SUBSTITUI os grupos, e isso a gente nao tem)
            if len(args) != 3 or args[0] != "-aG":
                raise FSError("uso: usermod -aG <grupo[,grupo...]> <usuário>")
            fs.accounts.add_to_groups(args[2], [g for g in args[1].split(",") if g])

        elif cmd == "gpasswd":
            if len(args) != 3 or args[0] != "-d":
                raise FSError("uso: gpasswd -d <usuário> <grupo>")
            fs.accounts.remove_from_group(args[1], args[2])
            print(f"Removendo {args[1]} do grupo {args[2]}")

        # sudo: pede a senha de quem tá logado e abre o 'with
        # accounts.sudo(...)'. Lá dentro chama o próprio _dispatch c/ o resto
        # do comando, agora como root.
        elif cmd == "sudo":
            if not args:
                raise FSError("uso: sudo <comando> [argumentos]")
            # a senha e sempre a de quem ta logado (nao a do root), e e
            # pedida toda vez -- o root nem precisa digitar
            password = None
            if fs.uid != ROOT_UID:
                password = _ask_password(f"[sudo] senha para {fs.accounts.user_name(fs.uid)}: ")
            with fs.accounts.sudo(password):
                return self._dispatch(args[0], args[1:])

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

    # Monta o fluxo do passwd na tela: -l/-u (bloquear/desbloquear), trocar a
    # própria senha ou a de outra pessoa (só root). Quem decide de vdd é o
    # change_password (accounts.py); aqui é só pra ñ pedir senha à toa.
    def _passwd(self, args) -> None:
        acc = self.fs.accounts
        # passwd -l / -u: bloquear ou desbloquear uma conta.
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
            if target != me:
                raise FSError("passwd: Permissão negada")
            # Usuário comum: pede a senha atual e confere antes de pedir a
            # nova.
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

    def _ls(self, path, long: bool) -> None:
        acc = self.fs.accounts
        entries = self.fs.ls(path)
        if not entries:
            return
        if not long:
            print("  ".join(name for name, _, _ in entries))
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
        print(f"  seu acesso:    {self._my_access(inode)}")
        print(f"  tamanho:       {inode.size} bytes")
        print(f"  criado em:     {_fmt_time(inode.created_at)}")
        print(f"  modificado em: {_fmt_time(inode.modified_at)}")
        print(f"  blocos usados: {len(blocks)} ({blocks})")

    # Gera a linha 'seu acesso' do stat: o q quem tá logado pode fazer c/ esse
    # arquivo e por quê. Usa o msm access_of do kernel, então mostra exatamente
    # a regra q vale. É didático: o Linux ñ tem essa linha.
    def _my_access(self, inode) -> str:
        if inode.type == TYPE_SYMLINK:
            return "vale a permissão do alvo (link não tem permissão própria)"
        cls, bits = self.fs.access_of(inode)
        reason = {
            ROOT: "você é root: as permissões não se aplicam",
            OWNER: "você é o dono",
            GROUP: f"você é membro do grupo {self.fs.accounts.group_name(inode.gid)}",
            OTHER: "você não é o dono nem está no grupo: vale 'outros'",
        }[cls]
        return f"{bits_string(bits)}  ({reason})"

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

    # O reset: apaga td e formata um disco novo.
    def _reset(self):
        # Só o root pode (apagar o disco de td mundo é coisa de administrador,
        # é o 'A' da CIA: disponibilidade).
        self.fs.accounts.require_root("reset")
        # Pede confirmação: tem q digitar 'sim'.
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
        return LOGOUT  # as contas antigas sumiram junto, entao volta pro login

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
    ls [-l] [dir]                  lista o diretório (-l: permissões, dono, grupo...)
    cd [dir]                       muda o diretório atual (sem argumento: home)
    pwd                            mostra o diretório atual
  Permissões:
    chmod <modo> <arquivo...>      muda as permissões (dono ou root)
                                   modo: 640 (r=4, w=2) ou u+w, o-r, g=r, u=rw,o=
    chown <dono>[:<grupo>] <arq..> muda o dono e/ou o grupo (só root)
    chown :<grupo> <arquivo...>    muda só o grupo (só root)
    chgrp <grupo> <arquivo...>     muda o grupo (root, ou dono que é do grupo)
  Usuários:
    useradd <usuário>              cria usuário, grupo próprio e home (só root)
    passwd [usuário]               troca a senha (de outro usuário: só root)
    passwd -l|-u <usuário>         bloqueia/desbloqueia a conta (só root)
    su [usuário]                   troca de usuário (padrão: root)
    whoami / id [usuário]          mostra o usuário atual / UID, GID e grupos
    users / groups [usuário]       lista os usuários / grupos de um usuário
    logout                         volta para a tela de login
  Grupos e administração:
    groupadd <grupo>               cria um grupo (só root)
    usermod -aG <grupo,...> <usu>  coloca o usuário em um ou mais grupos (só root)
    gpasswd -d <usuário> <grupo>   tira o usuário do grupo (só root)
    sudo <comando>                 roda um comando como root, com a SUA senha
                                   (só quem está no /etc/sudoers, ex.: grupo sudo)
  Outros:
    stat <caminho>                 mostra os campos do i-node e o seu acesso
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
