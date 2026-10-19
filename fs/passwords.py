"""
Hash das senhas com scrypt (vem no hashlib, biblioteca padrao).

A senha em si nunca e guardada: so vai pro disco um salt aleatorio e o
resultado do scrypt(senha, salt). No login a gente recalcula o scrypt com a
senha que a pessoa digitou e o mesmo salt, e compara os dois resultados.

O que fica no /etc/shadow (os parametros vao junto, entao da pra aumentar o
custo um dia sem quebrar as senhas que ja existem -- cada hash diz como foi
calculado):

    scrypt$<log2 de N>$<r>$<p>$<salt em hex>$<hash em hex>

Conta bloqueada (passwd -l) e esse mesmo texto com um "!" na frente, igual
no Linux.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from fs.constants import HASH_SIZE, SALT_SIZE, SCRYPT_LOG2_N, SCRYPT_P, SCRYPT_R

LOCK_PREFIX = "!"


def _scrypt(password: str, salt: bytes, log2_n: int, r: int, p: int) -> bytes:
    n = 1 << log2_n
    # o scrypt usa uns 128*r*N bytes de memoria (128 MiB com os nossos
    # parametros), so que o OpenSSL trava em 32 MiB se a gente nao liberar
    # mais. Liberamos o dobro do necessario pra ter folga
    maxmem = 2 * 128 * r * n
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          maxmem=maxmem, dklen=HASH_SIZE)


def hash_password(password: str) -> str:
    # o secrets usa o gerador aleatorio do sistema operacional, que serve pra
    # criptografia. O modulo random nao serve pra salt: ele e previsivel
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
        waste_time(password)  # linha corrompida: falha, mas no mesmo tempo de sempre
        return False
    digest = _scrypt(password, salt, log2_n, r, p)
    # o compare_digest leva sempre o mesmo tempo, acertando ou errando. Um ==
    # normal para no primeiro byte diferente, e ai medindo o tempo daria pra
    # descobrir quantos bytes do hash bateram
    ok = hmac.compare_digest(digest, expected)
    # conta bloqueada: faz a conta inteira mesmo assim e so recusa no final.
    # Se recusasse logo de cara, a resposta rapida entregaria que ela ta
    # bloqueada
    return ok and not locked


def waste_time(password: str) -> None:
    """Gasta o mesmo tempo de uma verificacao de verdade, sem comparar nada.

    Serve pro login de usuario que nao existe: sem isso a resposta vinha na
    hora (em vez de ~0,6 s) e dava pra descobrir quais contas existem so
    olhando o tempo.
    """
    _scrypt(password, bytes(SALT_SIZE), SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P)


def is_locked(stored: str) -> bool:
    return stored.startswith(LOCK_PREFIX)


def lock(stored: str) -> str:
    return stored if is_locked(stored) else LOCK_PREFIX + stored


def unlock(stored: str) -> str:
    return stored[len(LOCK_PREFIX):] if is_locked(stored) else stored
