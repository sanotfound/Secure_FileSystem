"""
A excecao que o sistema de arquivos inteiro usa. Ficou num arquivo so dela
porque o filesystem.py importa o accounts.py e o accounts.py tambem precisa
do erro: se um importasse o outro, o Python travava no import (import
circular).
"""


class FSError(Exception):
    """Erro de operacao do sistema de arquivos (mostrado ao usuario no shell)."""
