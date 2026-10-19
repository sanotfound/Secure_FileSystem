# Sistema de arquivos baseado em i-nodes, com usuários e permissões

Trabalho de Sistemas Operacionais. O "disco" é um arquivo de exatamente
128 MiB (`disco.img`), criado e formatado na primeira execução. Nas execuções
seguintes o disco é montado e todo o conteúdo anterior continua lá
(persistência).

O sistema é multiusuário: cada usuário tem senha e uma home própria, todo
arquivo e diretório tem dono, grupo e permissões de leitura e escrita (para o
dono, o grupo e os outros), e há `chmod`, `chown`, `chgrp` e `sudo`. As
decisões de projeto, os motivos de cada uma, as limitações e os testes de
cada etapa estão no [Relatório.md](Relatório.md).

Só usa a biblioteca padrão do Python (3.10 ou mais novo, por causa do
`hashlib.scrypt`).

## Como executar

```
python3 main.py                       # usa ./disco.img
python3 main.py --disk outro.img      # outro arquivo de disco
```

- **Primeira execução:** o disco é criado e formatado, e o programa pede a
  senha do administrador (`root`) duas vezes.
- **Depois:** aparece a tela de login (3 tentativas). Entre como `root` para
  criar os usuários com `useradd`.
- **Disco da versão antiga** (sem usuários): não é montado. O programa avisa;
  renomeie ou apague o arquivo para criar um disco novo.
- Digite `help` dentro do shell para ver os comandos.

Exemplo de sessão (as senhas não aparecem na tela):

```
login: root
senha:
root@sofs:~# useradd ana
Nova senha para ana:
Repita a nova senha:
root@sofs:~# usermod -aG sudo ana
root@sofs:~# su ana
ana@sofs:/root$ cd
ana@sofs:~$ echo "minhas notas" > notas.txt
ana@sofs:~$ ls -l
-rwr---  ana        ana                13  2026-10-19 14:00:00  notas.txt
ana@sofs:~$ cat /etc/shadow
erro: /etc/shadow: Permissão negada
ana@sofs:~$ sudo cat /etc/shadow
[sudo] senha para ana:
root:scrypt$17$8$1$...
ana:scrypt$17$8$1$...
```

## Comandos

Todos aceitam caminho absoluto e relativo; `.`, `..` e `~` (a sua home)
funcionam em qualquer caminho.

| Arquivos e diretórios | O que faz |
|---|---|
| `touch`, `rm`, `cat`, `cp`, `mv` | criar, apagar, ler, copiar e mover/renomear |
| `echo "x" > arq` / `echo "x" >> arq` | criar ou sobrescrever / acrescentar |
| `ln -s alvo link` | link simbólico (também para diretórios) |
| `mkdir`, `rmdir` (só se vazio), `cd` (sem argumento: home), `pwd` | diretórios |
| `ls [-l] [dir]` | só os nomes; com `-l`, permissões, dono, grupo, tamanho e data |
| `stat <caminho>` | campos do i-node, incluindo "seu acesso" |

| Permissões | Quem pode |
|---|---|
| `chmod <modo> <arq...>` — modo numérico (`640`, com r = 4 e w = 2) ou simbólico (`u+w`, `o-r`, `g=r`, `u=rw,o=`) | o dono ou o root |
| `chown <dono>[:<grupo>] <arq...>`, `chown :<grupo> <arq...>` | só o root |
| `chgrp <grupo> <arq...>` | o root, ou o dono se for membro do grupo |

| Usuários, grupos e administração | Quem pode |
|---|---|
| `useradd <usuário>` (cria também o grupo próprio e a home) | só o root |
| `passwd` (a própria senha, pedindo a atual) | todos |
| `passwd <usuário>`, `passwd -l/-u <usuário>` (bloquear/desbloquear) | só o root |
| `su [usuário]` (sem argumento: root) | todos (o root não digita senha) |
| `logout`, `whoami`, `id [usuário]`, `users`, `groups [usuário]` | todos |
| `groupadd <grupo>`, `usermod -aG <grupo[,grupo...]> <usuário>`, `gpasswd -d <usuário> <grupo>` | só o root |
| `sudo <comando>` (pede a senha **do próprio usuário**, sempre) | quem está no `/etc/sudoers` |
| `reset` (reformata o disco, pede confirmação) | só o root |

Extras: `df`, `help`, `exit`.

## Modelo de segurança (resumo)

- **Contas** ficam em arquivos de texto dentro do próprio disco, como no
  Linux: `/etc/passwd` e `/etc/group` (todos leem), `/etc/shadow` e
  `/etc/sudoers` (só o root).
- **Senhas** nunca são guardadas: o shadow tem só o salt aleatório e o hash
  `scrypt` (N = 2^17, r = 8, p = 1), comparado em tempo constante. O login dá
  a mesma resposta, no mesmo tempo, para usuário inexistente, senha errada e
  conta bloqueada.
- **Permissões:** `r` e `w` para dono, grupo e outros (não existe `x`). O
  `ls -l` mostra no formato `drwr-r-` (tipo + 2 letras por classe). Para
  decidir, o sistema vê em qual classe a pessoa cai, nesta ordem, e para na
  primeira: root (pode tudo) → dono → grupo → outros.
- **Atravessar um diretório exige `r`** nele. Por isso uma home `drw----` é
  realmente privada.
- **Arquivos e diretórios novos** nascem com 640 (`-rwr---`), com o grupo
  primário de quem criou. Cada usuário tem um grupo próprio, então tudo nasce
  privado; para compartilhar, basta um `chgrp` para um grupo de verdade.
- **Links:** as permissões do próprio link são ignoradas; vale a do alvo.
- **As checagens ficam no "kernel"** (`FileSystem` e `Accounts`), e não no
  shell.

Estrutura criada na formatação:

```
/              root:root  drwr-r-
/etc           root:root  drwr-r-
/etc/passwd    root:root  -rwr-r-
/etc/shadow    root:root  -rw----
/etc/group     root:root  -rwr-r-
/etc/sudoers   root:root  -rw----   (já vem com %sudo: membros do grupo sudo)
/home          root:root  drwr-r-
/home/<u>      u:u        drw----   (criada pelo useradd)
/root          root:root  drw----
```

## Arquivos do projeto

| Arquivo | Papel |
|---|---|
| `main.py` | ponto de entrada |
| `fs/shell.py` | o shell: lê comandos, pede senhas, mostra resultados |
| `fs/filesystem.py` | o "kernel": i-nodes, blocos, diretórios, caminhos, checagens de permissão, `chmod`/`chown`/`chgrp` |
| `fs/accounts.py` | usuários, grupos, login, `su`, `sudo` e os arquivos de `/etc` |
| `fs/passwords.py` | hash e verificação de senhas (scrypt) |
| `fs/permissions.py` | a regra de permissão, o formato `drwr-r-` e a leitura do modo do `chmod` |
| `fs/structs.py`, `fs/constants.py` | formatos binários (superbloco, i-node, entrada de diretório) e constantes |
| `fs/disk.py`, `fs/bitmap.py` | leitura/escrita de blocos e controle de livres/ocupados |
| `fs/errors.py` | a exceção usada pelo sistema |
| `tests/` | testes automatizados (ver abaixo) |

## Testes

Da pasta do projeto, sem instalar nada:

```
python -m unittest -v
```

São 91 testes, que levam cerca de 25 segundos. Cada um mostra na tela uma
frase dizendo o que confere. Os discos de teste ficam numa pasta temporária,
que é apagada no fim; o `disco.img` do projeto nunca é usado.

| Arquivo | O que confere |
|---|---|
| `tests/test_passwords.py` | hash scrypt com os parâmetros reais, salt diferente a cada vez, bloqueio de conta |
| `tests/test_permissions.py` | formato `drwr-r-`, modos do `chmod`, regra dono → grupo → outros |
| `tests/test_accounts.py` | arquivos de `/etc`, `useradd`, login, `passwd`, `su`, comandos de grupo |
| `tests/test_access_control.py` | ataques ao `/etc/shadow`, homes privadas, pasta compartilhada, `cp`, links |
| `tests/test_chmod_chown.py` | quem pode usar `chmod`, `chown` e `chgrp` |
| `tests/test_sudo.py` | senha, sudoers, volta das credenciais, `sudo su`, revogação |
| `tests/test_disk.py` | i-node de 128 bytes, disco antigo recusado, persistência |
| `tests/test_shell.py` | o programa rodando de verdade, incluindo a sessão de exemplo acima |

Para rodar só um arquivo: `python -m unittest -v tests.test_sudo`.

Para os testes não demorarem minutos, o custo do scrypt cai para N = 2^10
durante a execução (um teste específico confere os parâmetros reais), e cada
teste recebe a cópia de um disco-modelo já formatado, em vez de formatar um
disco novo.

## Layout do disco

Segue o esquema visto em aula (superbloco, controle de espaço livre, i-nodes,
diretório raiz, dados):

| Blocos | Conteúdo |
|---|---|
| 0 | Superbloco (magic `SOF2`, tamanhos, onde começa cada região, contadores de livres) |
| 1 | Bitmap de i-nodes (8192 bits) |
| 2–5 | Bitmap de blocos (65.536 bits) |
| 6–517 | Tabela de i-nodes (8192 × 128 B = 1 MiB) |
| 518–65.535 | Área de dados (65.018 blocos de 2048 B) |

Os 518 primeiros blocos (1036 KiB) são o espaço de gerenciamento; o restante
é para dados de arquivos e diretórios. O i-node 0 é sempre o diretório raiz.

## I-node (128 bytes)

Nome, UID do dono, GID do grupo, UID do criador, tamanho, data de criação,
data de modificação, permissões, 8 ponteiros diretos para blocos e
`next_inode`, o apontador para outro i-node (o "eventual outro i-node" do
enunciado). Além disso há um byte de "em uso", um de tipo (arquivo, diretório
ou link simbólico) e 20 bytes reservados.

O byte de permissões usa 2 bits por classe: `00 rw rw rw` (dono, grupo,
outros, a partir do bit mais alto).

Os 8 ponteiros diretos cobrem 16 KiB. Quando o arquivo passa disso, é alocado
um **i-node de continuação** (mesma estrutura, com mais 8 ponteiros) e o
`next_inode` do anterior passa a apontar para ele, formando uma cadeia. Não há
bloco de ponteiros indiretos. O tamanho máximo de um arquivo só é limitado
pelos blocos e i-nodes livres do disco. Diretórios usam a mesma estrutura
de blocos e de cadeia.

O i-node 0 é sempre a raiz e nunca é continuação de outro i-node, então
`next_inode <= 0` (-1 = fim normal) encerra a cadeia.

## Diretórios e links

- Cada entrada de diretório tem 32 B (nome de até 28 B + número do i-node),
  ou seja, 64 entradas por bloco. Entradas livres são marcadas com
  `0xFFFFFFFF`.
- Todo diretório tem as entradas `.` e `..`.
- Link simbólico é um i-node do tipo link cujo conteúdo é o caminho de destino.
  Um destino relativo é resolvido a partir do diretório onde o link está (como
  no UNIX). Há proteção contra ciclos de links.
- Os atributos ficam no i-node, não na entrada do diretório.

## Persistência

Toda alteração vai direto para o arquivo de disco (bitmaps, superbloco e
i-nodes incluídos) e é sincronizada (`fsync`) ao fim de cada comando. Os dados
são gravados em binário com o módulo `struct`; não há JSON nem pickle. Os
arquivos de contas em `/etc` são arquivos comuns dentro do disco, em texto.

## Decisões e limitações

- **Nomes:** arquivos e diretórios até 27 bytes em UTF-8 (limite da entrada
  de diretório); usuários e grupos com letras minúsculas, dígitos e `_`, sem
  começar com dígito, até 15 caracteres.
- **A proteção vale dentro do sistema:** quem abrir o `disco.img` direto no
  sistema operacional lê e altera os bytes sem passar pelas permissões. As
  senhas continuam protegidas pelo hash, mas o conteúdo dos arquivos não é
  cifrado (seção 3.1 do relatório).
- **Pasta compartilhada sem sticky bit:** quem tem `w` numa pasta pode apagar
  ou mover arquivos de outras pessoas dentro dela, como no Linux sem o sticky
  bit (seção 3.4 do relatório).
- **`sudo`:** a senha tem uma tentativa só (o Linux dá três); e
  `sudo echo x > arq` grava como root, enquanto no bash o `>` seria feito sem
  privilégio.
- **`~` entre aspas** também vira a home (o shell não guarda as aspas).
- **`mv` para um nome que já existe** retorna erro (não sobrescreve).
- **`cp`** copia apenas arquivos, não diretórios.
- **Número máximo de i-nodes:** 8192. Os i-nodes de continuação (1 a cada 8
  blocos de um arquivo ou diretório grande) saem dessa mesma tabela.
- **Disco cheio:** aumentar um arquivo ou diretório é "tudo ou nada". Se não
  houver blocos ou i-nodes suficientes, o comando falha com erro e nada é
  alterado (o arquivo continua com o conteúdo antigo, sem blocos ou i-nodes
  perdidos). O mesmo vale para `touch`, `mkdir`, `ln -s`, `mv` e para a
  gravação dos arquivos de contas (`useradd`, `passwd`, comandos de grupo).
- **Diretório atual:** não é gravado no disco; cada login começa na home do
  usuário. `rmdir` recusa remover o diretório em que o shell está.
