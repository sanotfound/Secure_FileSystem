"""
Shell interativo (REPL) que expõe os comandos exigidos no trabalho:
touch, rm, echo (> e >>), cat, cp, mv, ln -s, mkdir, rmdir, ls, cd
Mais alguns comandos de apoio (pwd, stat, df, help, reset) uteis para
demonstrar persistencia e uso do disco.
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import os
import shlex
import sys

from fs.constants import TYPE_DIR, TYPE_FILE, TYPE_SYMLINK
from fs.filesystem import FileSystem, FSError

DEFAULT_DISK_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "disco.img")


def _fmt_time(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


class Shell:
    def __init__(self, disk_path: str, user: str):
        self.disk_path = disk_path
        first_time = not os.path.exists(disk_path)
        self.fs = FileSystem(disk_path, current_user=user)
        if first_time:
            print(f"Disco novo criado em '{disk_path}' (128 MB) e formatado.")
        else:
            print(f"Disco existente montado em '{disk_path}'.")

    def run(self) -> None:
        print("Sistema de Arquivos baseado em i-nodes -- digite 'help' para ver os comandos.")
        while True:
            try:
                prompt = f"{self.fs.current_user}@sofs:{self.fs.path_of(self.fs.cwd_inode)}$ "
                line = input(prompt)
            except EOFError:
                print()
                break
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
                if self._dispatch(tokens):
                    break
            except FSError as exc:
                print(f"erro: {exc}")
            except Exception as exc:  # protecao extra durante demonstracao
                print(f"erro inesperado: {exc}")
            finally:
                self.fs.flush()

        self.fs.close()
        print("Disco desmontado. Dados persistidos em", self.disk_path)

    def _dispatch(self, tokens) -> bool:
        cmd, args = tokens[0], tokens[1:]
        fs = self.fs

        if cmd in ("exit", "quit"):
            return True

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
            fs.cd(args[0] if args else "/")

        elif cmd == "pwd":
            print(fs.path_of(fs.cwd_inode))

        elif cmd == "stat":
            if not args:
                raise FSError("uso: stat <caminho>")
            self._stat(args[0])

        elif cmd in ("df", "info"):
            self._df()

        elif cmd == "reset":
            self._reset()

        else:
            print(f"comando não reconhecido: {cmd} (digite 'help')")

        return False

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

    def _ls(self, path) -> None:
        entries = self.fs.ls(path)
        if not entries:
            return
        for name, inode, num in entries:
            perm = self.fs.perm_string(inode.perm, inode.type)
            extra = ""
            if inode.type == TYPE_SYMLINK:
                target = self.fs.read_data(num).decode("utf-8", errors="replace")
                extra = f" -> {target}"
            print(f"{perm}  {inode.owner:<12} {inode.size:>10}  {_fmt_time(inode.modified_at)}  {name}{extra}")

    def _stat(self, path) -> None:
        fs = self.fs
        num = fs.resolve(path, follow_symlink=False)
        inode = fs.read_inode(num)
        type_name = {TYPE_FILE: "arquivo", TYPE_DIR: "diretório", TYPE_SYMLINK: "link simbólico"}[inode.type]
        blocks = fs._iter_blocks(num)  # noqa: SLF001 - uso interno para fins de diagnostico
        print(f"  i-node:        {num}")
        print(f"  nome:          {inode.name}")
        print(f"  tipo:          {type_name}")
        print(f"  criador:       {inode.creator}")
        print(f"  dono:          {inode.owner}")
        print(f"  permissões:    {fs.perm_string(inode.perm, inode.type)}")
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

    def _reset(self) -> None:
        answer = input("Isso apaga TODO o conteúdo do disco atual. Digite 'sim' para confirmar: ")
        if answer.strip().lower() != "sim":
            print("cancelado.")
            return
        user = self.fs.current_user
        self.fs.close()
        os.remove(self.disk_path)
        self.fs = FileSystem(self.disk_path, current_user=user)
        print("disco reformatado.")

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
    cd <dir>                       muda o diretório atual
    pwd                            mostra o diretório atual
  Outros:
    stat <caminho>                 mostra os campos do i-node
    df / info                      mostra uso do disco (128 MB)
    reset                          reformata o disco (apaga tudo, pede confirmação)
    help                           esta mensagem
    exit / quit                    sai do shell""")


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
    parser.add_argument("--user", default=None, help="usuário atual (padrão: usuário do sistema operacional)")
    args = parser.parse_args()

    user = args.user or getpass.getuser()
    shell = Shell(args.disk, user)
    shell.run()


if __name__ == "__main__":
    main()
