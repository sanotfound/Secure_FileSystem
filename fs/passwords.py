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


# Esta é a função q faz a conta pesada (o 'scrypt'). Ela recebe a senha e o
# salt (um código aleatório q cada usuário tem) e devolve 32 bytes
# embaralhados: o hash. É de mão única: ñ dá pra voltar do hash pra senha. É
# aqui q vão os ~0,6 s de cada login; o resto do sistema é rapidinho.
def _scrypt(password: str, salt: bytes, log2_n: int, r: int, p: int) -> bytes:
    # O shadow guarda só o expoente (17). Aqui vira o número de vdd: 2^17 =
    # 131.072 blocos q o scrypt vai montar na memória.
    n = 1 << log2_n
    # Cada bloco tem 128*r = 1024 bytes, então a tabela inteira dá 128 MiB. O
    # OpenSSL (q faz o scrypt por baixo) trava em 32 MiB por padrão, por isso a
    # gente libera o dobro do necessário.
    maxmem = 2 * 128 * r * n
    # A conta em si: monta a tabela de 128 MiB, embaralha consultando ela fora
    # de ordem e reduz td a 32 bytes (dklen). Td o custo de tempo e memória tá
    # nesta linha.
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          maxmem=maxmem, dklen=HASH_SIZE)


# Usada qd uma senha é CRIADA ou TROCADA (useradd, passwd). Transforma a senha
# num texto q pode ser guardado no /etc/shadow sem revelar a senha.
def hash_password(password: str) -> str:
    # Sorteia 16 bytes aleatórios: o salt. Cada usuário ganha um diferente,
    # então duas pessoas c/ a msm senha ficam c/ hashes diferentes. Usa
    # 'secrets' (ñ 'random') pq o random dá pra prever.
    salt = secrets.token_bytes(SALT_SIZE)
    # Calcula o hash da senha junto c/ o salt (~0,6 s).
    digest = _scrypt(password, salt, SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P)
    # Monta o texto q vai pro shadow: algoritmo, parâmetros, salt e hash,
    # separados por $. Ex.: scrypt$17$8$1$<salt>$<hash>. A senha ñ aparece em
    # lugar nenhum.
    return f"scrypt${SCRYPT_LOG2_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


# Usada qd uma senha é CONFERIDA (login, su, sudo, passwd). Ñ tem como 'abrir'
# o hash; o q ela faz é repetir a msm conta c/ a senha digitada e ver se o
# resultado é igual ao guardado.
def verify_password(password: str, stored: str) -> bool:
    # Conta bloqueada tem um ! na frente do texto. Anota isso e tira o ! pra
    # conseguir ler o resto.
    locked = is_locked(stored)
    if locked:
        stored = stored[len(LOCK_PREFIX):]
    try:
        # Quebra a linha do shadow nas 6 partes. Os parâmetros e o salt vêm DA
        # PRÓPRIA LINHA, por isso dá pra mudar o custo no futuro sem estragar
        # as senhas antigas.
        algo, log2_n, r, p, salt_hex, hash_hex = stored.split("$")
        if algo != "scrypt":
            raise ValueError(algo)
        salt, expected = bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
        log2_n, r, p = int(log2_n), int(r), int(p)
    # Linha corrompida: recusa, mas gastando o msm tempo de sempre.
    except ValueError:
        waste_time(password)
        return False
    # Refaz a conta c/ a senha digitada e o salt guardado. Se a senha for a
    # certa, sai exatamente o msm hash.
    digest = _scrypt(password, salt, log2_n, r, p)
    # o compare_digest leva sempre o mesmo tempo, acertando ou errando. Um ==
    # normal para no primeiro byte diferente, e ai medindo o tempo daria pra
    # descobrir quantos bytes do hash bateram
    ok = hmac.compare_digest(digest, expected)
    # conta bloqueada: faz a conta inteira mesmo assim e so recusa no final.
    # Se recusasse logo de cara, a resposta rapida entregaria que ela ta
    # bloqueada
    return ok and not locked


# Gasta o msm tempo de um login de vdd sem conferir nada. Usada qd o usuário
# digitado ñ existe: se a resposta viesse na hora, dava pra descobrir quais
# contas existem só medindo o tempo.
def waste_time(password: str) -> None:
    # Um scrypt c/ salt de zeros, só pra gastar tempo; o resultado é jogado
    # fora.
    _scrypt(password, bytes(SALT_SIZE), SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P)


# Vê se o hash tem o ! na frente (= conta bloqueada).
def is_locked(stored: str) -> bool:
    return stored.startswith(LOCK_PREFIX)


# Bloqueia a conta: põe o ! na frente do hash. O hash continua lá, só fica
# 'desligado'.
def lock(stored: str) -> str:
    return stored if is_locked(stored) else LOCK_PREFIX + stored


# Desbloqueia: tira o ! da frente. Como o hash ñ mudou, volta a valer a msm
# senha de antes.
def unlock(stored: str) -> str:
    return stored[len(LOCK_PREFIX):] if is_locked(stored) else stored
