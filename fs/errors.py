"""
Excecao usada por todo o sistema de arquivos. Fica num modulo proprio para
que filesystem.py e accounts.py possam importa-la sem um importar o outro
em ciclo (filesystem.py usa accounts.py e vice-versa).
"""


class FSError(Exception):
    """Erro de operacao do sistema de arquivos (mostrado ao usuario no shell)."""
