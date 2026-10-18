"""
Hash de senhas com scrypt (hashlib, biblioteca padrao).

A senha nunca e guardada: guardamos so um salt aleatorio e o resultado do
scrypt(senha, salt). No login, o scrypt e recalculado com a senha digitada e
o mesmo salt, e os dois resultados sao comparados.

Formato guardado no /etc/shadow (os parametros vao junto, entao da pra mudar
o custo no futuro sem invalidar as senhas que ja existem):

    scrypt$<log2 de N>$<r>$<p>$<salt em hex>$<hash em hex>

Conta bloqueada (passwd -l) e o mesmo texto com "!" na frente, como no Linux.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from fs.constants import HASH_SIZE, SALT_SIZE, SCRYPT_LOG2_N, SCRYPT_P, SCRYPT_R

LOCK_PREFIX = "!"


def _scrypt(password: str, salt: bytes, log2_n: int, r: int, p: int) -> bytes:
    n = 1 << log2_n
    # o scrypt precisa de ~128*r*N bytes (128 MiB nos parametros padrao) e o
    # OpenSSL recusa passar de 32 MiB se nao liberarmos mais; damos o dobro
    maxmem = 2 * 128 * r * n
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          maxmem=maxmem, dklen=HASH_SIZE)


def hash_password(password: str) -> str:
    # secrets usa o gerador aleatorio do sistema operacional, proprio pra
    # criptografia (o modulo random e previsivel e nao serve pra salt)
    salt = secrets.token_bytes(SALT_SIZE)
    digest = _scrypt(password, salt, SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P)
    return f"scrypt${SCRYPT_LOG2_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    locked = is_locked(stored)
    if locked:
        stored = stored[len(LOCK_PREFIX):]
    try:
        algo, log2_n, r, p, salt_hex, hash_hex = stored.split("$")
        if algo != "scrypt":
            raise ValueError(algo)
        salt, expected = bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
        log2_n, r, p = int(log2_n), int(r), int(p)
    except ValueError:
        waste_time(password)  # registro corrompido: falha no mesmo tempo
        return False
    digest = _scrypt(password, salt, log2_n, r, p)
    # compare_digest leva o mesmo tempo acertando ou errando; um == comum
    # para no primeiro byte diferente e o tempo de resposta vazaria quantos
    # bytes do hash bateram
    ok = hmac.compare_digest(digest, expected)
    # conta bloqueada faz a conta inteira mesmo assim, pra nao responder
    # mais rapido (e revelar que esta bloqueada), e so entao recusa
    return ok and not locked


def waste_time(password: str) -> None:
    """Gasta o mesmo tempo de uma verificacao de verdade, sem comparar nada.

    Usado no login quando o usuario nao existe: sem isso a resposta viria na
    hora (em vez de ~0,6 s) e daria pra descobrir quais contas existem so
    medindo o tempo.
    """
    _scrypt(password, bytes(SALT_SIZE), SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P)


def is_locked(stored: str) -> bool:
    return stored.startswith(LOCK_PREFIX)


def lock(stored: str) -> str:
    return stored if is_locked(stored) else LOCK_PREFIX + stored


def unlock(stored: str) -> str:
    return stored[len(LOCK_PREFIX):] if is_locked(stored) else stored
