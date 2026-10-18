# Relatório — Mecanismos de segurança no sistema de arquivos

Documento de acompanhamento do trabalho. Antes de cada etapa, ele recebe o
que será implementado, alterado ou removido e o motivo; ao final da etapa,
recebe o que foi feito de fato, o que mudou em relação ao planejado e como
foi testado.

---

## 1. Objetivo

### 1.1 O que o enunciado pede

- O sistema de arquivos passa a ter **vários usuários**, cada um com sua
  área de armazenamento (home) e sua própria **senha**.
- Todo arquivo e diretório tem um **dono** e **permissões de leitura e
  escrita**, em dois conjuntos: as do dono e as dos demais usuários.
- Implementar `chmod` (alterar permissões) e `chown` (alterar o dono).
- As senhas **não podem ficar em texto plano**, e o arquivo de senhas **não
  pode estar disponível aos usuários comuns**.

### 1.2 Como o trabalho foi conduzido

- O objetivo é aproximar o **comportamento geral de um sistema Linux**, sem
  reproduzi-lo por completo.
- O projeto continua usando **apenas a biblioteca padrão do Python**.
- O foco da proteção é **dentro do sistema simulado** (ver limitações na
  seção 3). Por ser um trabalho acadêmico, não há criptografia do disco.
- As decisões foram avaliadas por quatro critérios: **CIA**
  (confidencialidade, integridade, disponibilidade), **menor privilégio**,
  **separação de tarefas** e **simplicidade**.

---

## 2. Decisões de projeto

### 2.1 Senhas: hash com salt (scrypt)

**Decisão:** scrypt (`hashlib.scrypt`) com N = 2^17, r = 8, p = 1, salt
aleatório de 16 bytes por usuário e hash de 32 bytes. A comparação é feita
com `hmac.compare_digest`.

**Hash, e não criptografia.** Criptografia é reversível: exigiria guardar
uma chave em algum lugar, e quem achasse a chave descobriria todas as
senhas. O hash é uma função de mão única. No login, o sistema calcula o hash
da senha digitada e compara com o guardado. A senha original nunca é
armazenada e não pode ser recuperada, apenas adivinhada (uma tentativa por
vez).

**Por que um algoritmo lento.** O ataque relevante é o de quem obtém uma
cópia do arquivo de senhas e testa senhas no próprio computador, sem limite
de tentativas. Para isso, o custo de cada tentativa precisa ser alto. Um
hash rápido como o SHA-256 permite bilhões de tentativas por segundo numa
GPU.

| Alternativa | Por que não (ou por que sim) |
|---|---|
| SHA-256 puro | senhas iguais geram hashes iguais; vulnerável a tabelas pré-calculadas; rápido demais |
| SHA-256 + salt | resolve as tabelas, mas continua rápido demais |
| PBKDF2-HMAC-SHA256 | biblioteca padrão e padrão NIST, mas só gasta tempo (não memória), então GPUs levam vantagem |
| **scrypt** | biblioteca padrão (Python ≥ 3.10); gasta tempo **e** memória; 2º colocado no ranking da OWASP |
| bcrypt / Argon2id | exigem instalar bibliotecas externas |

Medição na máquina de desenvolvimento (Python 3.11.9, OpenSSL 3.0.13):

| Algoritmo | Tempo por hash | Memória |
|---|---|---|
| PBKDF2-SHA256, 600 mil iterações | 0,29 s | desprezível |
| scrypt N = 2^15 | 0,22 s | 32 MiB |
| scrypt N = 2^17 (escolhido) | 0,60 s | 128 MiB |

**Por que a memória importa.** Uma GPU de ponta tem milhares de núcleos, mas
uma quantidade limitada de memória (por exemplo, 24 GB). Com o scrypt, cada
tentativa precisa de 128 MiB próprios, então a GPU roda no máximo cerca de
190 tentativas ao mesmo tempo, e a maior parte dos núcleos fica parada. Os
128 MiB são memória RAM temporária, usada só durante o cálculo; no arquivo
de senhas ficam apenas o salt e o hash.

**Salt.** 16 bytes por usuário, gerados com o módulo `secrets` (gerador do
sistema operacional, próprio para criptografia; o módulo `random` é
previsível). O salt não é segredo e fica ao lado do hash. Ele faz duas
pessoas com a mesma senha terem hashes diferentes e obriga o atacante a
atacar cada usuário separadamente.

**Pepper (rejeitado).** Um segredo extra misturado em todas as senhas só
ajuda se ficar onde o atacante não alcança. Aqui, o único lugar possível
seria o código-fonte, que é público no GitHub.

**Proteções no login:**
- mesma mensagem ("Login incorreto.") para usuário inexistente, senha
  errada ou conta bloqueada;
- quando o usuário não existe, o sistema calcula um hash do mesmo jeito,
  para que o tempo de resposta não revele quais contas existem;
- depois de 3 tentativas erradas, o programa encerra.

**Política de senha.** Não há exigência de tamanho mínimo, símbolos ou
números: num ambiente controlado e sem simulação de ataques, isso não muda
nada. Ficam apenas a confirmação (digitar a senha duas vezes) e a recusa de
senha vazia.

### 2.2 Arquivos de contas: `/etc/passwd` e `/etc/shadow`

**Decisão:** os arquivos de contas ficam **dentro do próprio sistema de
arquivos**, como no Linux, e são protegidos pelas mesmas permissões que o
trabalho implementa.

| Alternativa | Por que não (ou por que sim) |
|---|---|
| **Arquivos dentro do sistema de arquivos** | modelo do Linux; a proteção vem das próprias permissões, o que permite demonstrar o mecanismo |
| Área reservada do disco | nenhum comando alcançaria esses blocos, mas mudaria o layout do disco, limitaria o número de usuários e não usaria as permissões |
| Arquivo fora do disco | ficaria fora do sistema simulado; a exigência perderia o sentido |

Os dados ficam separados em dois arquivos, como no Linux: o que é público
fica no `passwd`, o que é secreto fica no `shadow`. Isso também rende uma
demonstração direta: na mesma pasta, `cat /etc/passwd` funciona e
`cat /etc/shadow` dá "Permissão negada". Os arquivos são texto, uma linha
por usuário:

| Arquivo | Formato | Permissão |
|---|---|---|
| `/etc/passwd` | `nome:x:uid:gid:home` | `-rwr-r-` (todos leem) |
| `/etc/shadow` | `nome:hash` | `-rw----` (só o root) |
| `/etc/group` | `nome:x:gid:membro1,membro2` | `-rwr-r-` (todos leem) |
| `/etc/sudoers` | um usuário ou `%grupo` por linha | `-rw----` (só o root) |

O `x` no passwd e no group indica que a senha não fica ali. Nomes de
usuário e de grupo aceitam apenas letras minúsculas, dígitos e `_`, sem
começar com dígito, até 15 caracteres; assim nunca contêm `:` nem quebra de
linha e não quebram o formato.

Formato do hash guardado no shadow (os parâmetros vão junto, então o custo
pode ser aumentado no futuro sem invalidar senhas antigas):

```
scrypt$17$8$1$<salt em hex>$<hash em hex>
```

Conta bloqueada é o mesmo texto com `!` na frente, como no Linux.

### 2.3 Dono identificado por número (UID/GID)

**Decisão:** o i-node guarda o UID do dono, o GID e o UID do criador, em vez
dos nomes.

- **Vantagens:** é o modelo do Linux; ocupa menos espaço (12 bytes em vez de
  32); o dono não depende do nome. Se um usuário fosse apagado e outro fosse
  criado com o mesmo nome, por nome ele herdaria os arquivos do antigo.
- **Custo:** o `ls` e o `stat` traduzem número em nome consultando os
  arquivos de contas. O formato do i-node mudou, o que exigiu reformatar o
  disco (ver 2.9).
- **Números:** root = 0, grupo `sudo` = 27, usuários e grupos comuns a
  partir de 1000 (os mesmos do Ubuntu).

### 2.4 Permissões: leitura e escrita, três classes

**Só leitura (r) e escrita (w), sem o x.** O enunciado pede apenas leitura e
escrita, e o sistema só tem arquivos de texto. Num diretório, o x do Linux
significa "atravessar" (entrar e acessar os itens pelo nome); aqui, o `r`
cumpre esse papel (ver abaixo).

**Três classes: dono, grupo e outros.** O enunciado define dois conjuntos
(dono e demais usuários). O trabalho implementa grupos de verdade para
aproximar o comportamento do Linux. Os dois conjuntos do enunciado continuam
existindo: "dono" e "outros" ("outros" é o que o enunciado chama de "demais
usuários"). O grupo é uma classe intermediária. Como cada usuário tem um
grupo próprio que só contém ele mesmo (ver 2.6), o sistema se comporta
exatamente como o modelo de dois conjuntos até que o root crie um grupo
compartilhado.

**Como a classe é escolhida (classes exclusivas, como no Linux).** O
sistema pergunta, nesta ordem, e para na primeira resposta "sim":

1. É root? → pode tudo.
2. É o dono do arquivo? → valem só os bits do dono.
3. Está no grupo do arquivo? → valem só os bits do grupo.
4. Senão → valem os bits de outros.

A classe não é uma característica da pessoa: é decidida arquivo por
arquivo. Exemplos:

- `politica.txt`, dona ana, grupo `estagiarios`, `-rw--r-`: um estagiário
  **não** lê (a checagem para no grupo, que não tem nada), enquanto os demais
  usuários leem. Somando as classes, essa exceção seria impossível.
- `rascunho.txt`, dono bruno, grupo `rh`, `-r-rw--`: o bruno não escreve,
  mesmo estando no `rh`, porque como dono só valem os bits do dono. Ele pode
  rodar `chmod u+w` quando quiser; na prática, o dono usa isso para se
  proteger de sobrescrever o próprio arquivo.

**Diretórios: atravessar exige `r`.** Para acessar `/home/ana/notas.txt`, é
preciso `r` em `/`, `/home` e `/home/ana`. Sem essa regra, quem soubesse o
nome abriria o arquivo e o diretório só esconderia a listagem. Com ela, uma
home `drw----` fica realmente privada.

**Permissão exigida por comando** (além de `r` nos diretórios do caminho;
o root ignora as checagens):

| Comando | Precisa de |
|---|---|
| `cat`, `cp` (origem) | `r` no arquivo |
| `echo >`, `echo >>` | `w` no arquivo, ou `w` no diretório se o arquivo for criado |
| `touch` em arquivo que já existe | `w` no arquivo |
| `ls`, `cd` | `r` no diretório |
| `touch`, `mkdir`, `ln -s`, `cp` (destino novo) | `w` no diretório pai |
| `rm`, `rmdir` | `w` no diretório pai (apagar é alterar o diretório) |
| `mv` | `w` no pai de origem e no pai de destino |
| `stat` | só conseguir atravessar o caminho |
| `reset` | ser root |
| link simbólico | vale a permissão do alvo |

**Exibição.** Formato do `ls -l` sem a coluna do x: tipo e 2 caracteres por
classe (dono, grupo, outros). Exemplos: `-rwr---` (640), `drw----` (600),
`drwr-r-` (644), `lrwrwrw` (link).

**Representação no i-node.** 6 bits do byte de permissões, 2 por classe:
`00 rw rw rw` (dono, grupo, outros, do bit mais alto para o mais baixo).

### 2.5 `chmod`, `chown` e `chgrp`

| Comando | Quem pode | Sintaxe |
|---|---|---|
| `chmod` | o dono ou o root | numérica com 3 dígitos (r = 4, w = 2; cada dígito é 0, 2, 4 ou 6), ex.: `chmod 640 arq`; ou simbólica: `u`/`g`/`o`/`a`, `+ - =`, `r`/`w`, várias mudanças separadas por vírgula, ex.: `chmod o-r arq`, `chmod u=rw,g=r,o= arq` |
| `chown` | só o root | `chown usuario arq`, `chown usuario:grupo arq`, `chown :grupo arq` |
| `chgrp` | o root, ou o dono se for membro do grupo de destino | `chgrp grupo arq` |

- **Por que só o root usa `chown`** (como no Linux): impede que um usuário
  "dê" um arquivo a outro para incriminá-lo ou para deixar com ele algo que
  ele não controla.
- **Números do `chmod`:** iguais aos do Linux sem o x (644, 640, 600).
  Dígitos ímpares (que incluiriam o x) são recusados.
- **Sudo e `chmod`:** como no Linux, o dono usa `chmod` nos próprios arquivos
  sem `sudo`. O `sudo` só é necessário para arquivos de outra pessoa e, sempre,
  para o `chown`.

### 2.6 Usuários, root e grupos

**Root e criação de usuários.** A senha do root é definida na formatação do
disco, e só o root cria usuários. A alternativa (qualquer pessoa se
cadastrar na tela de login) deixaria qualquer um criar contas.

| Comando | O que faz | Quem pode |
|---|---|---|
| `useradd <nome>` | cria o usuário, o grupo próprio e a home | root |
| `passwd` | troca a própria senha (pede a atual) | todos |
| `passwd <nome>` | troca a senha de outro usuário | root |
| `passwd -l/-u <nome>` | bloqueia/desbloqueia a conta | root |
| `su [usuário]` | troca de usuário (o root não precisa de senha) | todos |
| `logout`, `whoami`, `id`, `users`, `groups` | sessão e consultas | todos |
| `groupadd`, `usermod -aG`, `gpasswd -d` | criar grupo, adicionar e remover membros | root |

**Grupo próprio por usuário** (padrão do Ubuntu, Debian e Fedora): o
`useradd ana` cria também o grupo `ana`, que só tem a ana. Três decisões
funcionam juntas:

1. cada usuário tem um grupo próprio;
2. um arquivo novo recebe o grupo primário de quem o cria (regra do Linux);
3. a permissão padrão de arquivos e diretórios novos é 640 (`-rwr---`).

Resultado: tudo nasce privado (o "grupo" de um arquivo novo é só o próprio
dono), e compartilhar exige um único `chgrp` para um grupo de verdade.

Sem o grupo próprio, um grupo comum `users` com todos os usuários faria a
permissão de grupo virar outro nome para "outros". Por exemplo, se a ana
abrisse a home para leitura (`chmod 644 ~`) querendo compartilhar um
arquivo, todos os arquivos dela ficariam legíveis por todos.

A regra 2 (grupo de quem cria, e não o grupo do diretório, como no BSD) foi
escolhida por menor privilégio: compartilhar passa a ser um ato explícito
(`chgrp`), nunca automático.

**Bloqueio de contas** (`passwd -l`): como não há `userdel`, é a forma de
cortar o acesso de alguém. O hash continua guardado com `!` na frente, então
desbloquear devolve a senha anterior. Bloquear o root é recusado, para o
sistema não ficar sem administrador.

**Sem `userdel` e `groupdel`:** apagar usuários ou grupos deixaria arquivos
apontando para números que não existem mais.

**Mudanças de grupo valem na hora.** No Linux, só valem no próximo login.
Aqui é mais simples, e tirar alguém de um grupo corta o acesso
imediatamente (menor privilégio).

### 2.7 `sudo`

| | `su root` | `sudo comando` |
|---|---|---|
| Senha pedida | a do root | a do próprio usuário |
| Duração | até sair | só aquele comando |
| Quem pode | quem souber a senha do root | só quem está no `/etc/sudoers` |

**Por que existe o sudo:**
- a senha do root não precisa ser compartilhada;
- para tirar o acesso de alguém, basta removê-lo do sudoers, sem trocar a
  senha do root;
- o usuário só vira root no instante em que precisa, o que reduz acidentes.

**Decisões:**
- **Quem pode usar:** quem estiver no `/etc/sudoers`, que aceita usuários e
  `%grupos`. A formatação cria o grupo `sudo` (GID 27) e a linha `%sudo`,
  então tornar alguém administrador é `usermod -aG sudo <usuário>`, como no
  Ubuntu.
- **A senha é pedida sempre, sem lembrar por alguns minutos.** Os quatro
  critérios apontam para isso: o usuário só tem privilégio durante o comando
  (menor privilégio), não há janela para alguém usar um terminal deixado
  aberto (CIA), e não há estado para guardar nem invalidar (simplicidade).
  Isso também elimina o risco de o `su` herdar a janela de outro usuário.
- **A ordem é a do Linux:** primeiro a senha, depois a consulta ao sudoers.
- **O sudo vale para todos os comandos, sem restrição por comando.** A
  separação de tarefas sugeriria restringir (por exemplo, o "suporte" só
  troca senhas), mas isso é muito fácil de errar:
  - quem pode rodar `passwd` troca a senha do root;
  - quem pode rodar `chown` ou `chmod` toma o `/etc/shadow`;
  - quem pode rodar `echo` se coloca no `/etc/sudoers`.

  Cada comando aparentemente inofensivo vira um caminho para virar root. A
  separação de tarefas vem dos papéis: root, administradores (grupo `sudo`)
  e usuários comuns.

### 2.8 Estrutura inicial e permissões padrão

```
/              root:root  drwr-r-   todos leem e atravessam; só o root cria na raiz
/etc           root:root  drwr-r-
/etc/passwd    root:root  -rwr-r-
/etc/shadow    root:root  -rw----   só o root
/etc/group     root:root  -rwr-r-
/etc/sudoers   root:root  -rw----   só o root
/home          root:root  drwr-r-   só o root cria homes
/home/<u>      u:u        drw----   home privada
/root          root:root  drw----   home do root
```

Arquivos e diretórios novos: 640 (`-rwr---` / `drwr---`). Os arquivos do
sistema recebem permissões explícitas na formatação.

### 2.9 Onde ficam as checagens e o formato do disco

- **As checagens ficam no "kernel"** (classes `FileSystem` e `Accounts`), e
  não no shell. O shell é só uma interface. Se as checagens ficassem no
  shell, ficariam espalhadas e poderiam ser contornadas por caminhos internos
  (por exemplo, o `cp` chama `write_file` por dentro).
- **Modo kernel (`as_root`):** o código do próprio sistema que precisa mexer
  em arquivos protegidos (o login lendo o shadow, o `useradd` gravando em
  `/etc`) roda temporariamente com as credenciais do root e depois volta às
  originais, mesmo em caso de erro. Nenhum comando digitado entra nesse modo.
- **Formato do disco:** a identificação gravada no início do disco passou de
  `SOFS` para `SOF2`. Um disco no formato antigo é recusado com uma mensagem
  pedindo para renomeá-lo ou apagá-lo; o programa nunca apaga nada sozinho.

### 2.10 Outros comportamentos

- **`cp`:** a cópia pertence a quem copiou, com o grupo primário dele e as
  permissões do original limitadas pelo padrão 640 (a cópia nunca fica mais
  aberta que o original). A cópia **não pode** manter o dono original: se
  pudesse, qualquer usuário criaria arquivos em nome de outra pessoa, que é
  justamente o que o `chown` restrito ao root impede.
- **`mv`:** mantém dono, grupo e permissões.
- **Links simbólicos:** as permissões do próprio link são ignoradas (ele
  aparece como `lrwrwrw`) e vale a permissão do alvo; `chmod`, `chown` e
  `chgrp` aplicados a um link agem no alvo. Motivo: um link é só uma placa
  com um caminho. Se as permissões dele pudessem liberar acesso, seriam uma
  brecha (um link `rwrwrw` para `/etc/shadow` daria acesso ao shadow). Se
  só pudessem restringir, seriam inúteis (quem vê para onde o link aponta usa
  o caminho do alvo direto). Ou seja, **as permissões do link ou seriam
  perigosas ou não serviriam para nada**. Por isso o Linux as ignora e mostra
  sempre `lrwxrwxrwx`. O que protege o link é o diretório onde ele está:
  criar, apagar ou renomear o link exige `w` no diretório.
- **`su`:** troca o usuário atual e mantém o diretório atual, como o `su` do
  Linux. Não há pilha de sessões: `logout` volta para a tela de login e
  `exit` encerra o programa.
- **Estilo Linux:** `~` significa a home nos caminhos; `cd` sem argumento
  volta para a home; o prompt fica `ana@sofs:~$` (com `#` para o root); o
  comando `id` mostra UID, GID e grupos; o erro de acesso é
  "Permissão negada".
- **GID do grupo próprio:** igual ao UID quando o número está livre; senão,
  o próximo livre a partir de 1000.
- **`gpasswd -d`** não remove ninguém do próprio grupo primário.

### 2.11 O que foi decidido não implementar

| Item | Motivo |
|---|---|
| Criptografia do disco | fora do foco (proteção dentro do sistema); exigiria biblioteca externa e uma senha mestra separada |
| Registro de auditoria (log) | fora do escopo pedido; seria mais uma parte a apresentar sem ser exigida |
| Sticky bit | simplicidade; comportamento padrão do Linux (ver 3.4) |
| Regras de complexidade de senha | ambiente controlado, sem simulação de ataques |
| Sudo restrito por comando | fácil de errar e de escalar para root (ver 2.7) |
| `userdel` e `groupdel` | deixariam arquivos com dono ou grupo inexistente |
| Bit x | só há arquivos de texto; atravessar diretório é controlado pelo `r` |

---

## 3. Limitações conhecidas

### 3.1 A proteção vale dentro do sistema, não fora dele

Dentro do sistema, toda operação passa pelo kernel, que confere as
permissões. Fora dele, o `disco.img` é um arquivo comum do Windows: quem
conseguir abri-lo (um script, um editor hexadecimal) lê e altera os bytes
diretamente, sem que nenhuma permissão seja conferida. É o mesmo que retirar
o HD de um computador com Linux e ligá-lo em outro.

| Situação | O que a pessoa obtém | O que protege |
|---|---|---|
| Lê o `/etc/shadow` direto dos bytes | nomes, UIDs, salts e hashes | o hash: não dá para reverter, só tentar senha por senha (0,6 s e 128 MiB cada) |
| Lê os arquivos das homes | o conteúdo de todos os arquivos | nada (o conteúdo não é cifrado) |
| Altera o `disco.img` | pode trocar o hash do root ou o dono de um i-node e virar root | nada (o hash impede ler a senha, não trocá-la) |

O hash protege uma coisa específica: as senhas em si, que muitas pessoas
reutilizam em outros serviços. A defesa real para o resto seria criptografar
o disco inteiro (como BitLocker ou LUKS), o que ficou fora do escopo.

### 3.2 Restos de arquivos apagados

Blocos liberados continuam com o conteúdo antigo dentro do `disco.img` (o
sistema só os marca como livres no bitmap). Pelo shell ninguém consegue ler
esses restos: a leitura de um arquivo para no tamanho dele, e blocos novos
são gravados completos, preenchidos com zeros. Só quem abre o `disco.img`
diretamente os veria.

### 3.3 O root pode tudo

Por definição, como no Linux. Quem tem a senha do root (ou está no
sudoers) tem acesso total.

### 3.4 Pasta compartilhada sem sticky bit

Numa pasta compartilhada com escrita para o grupo (por exemplo,
`/home/projeto`, `drwrw--`, grupo `alunos`), um membro pode apagar arquivos
de outro, porque apagar exige `w` no diretório. Cenário:

```
bruno$ cp relatorio.txt copia.txt   (relatorio.txt é da ana; precisa de r, que ele tem pelo grupo)
bruno$ rm relatorio.txt             (precisa de w na pasta, que ele tem pelo grupo)
bruno$ mv copia.txt relatorio.txt   (agora existe um relatorio.txt cujo dono é o bruno)
```

- **O que ele não ganhou:** acesso novo (para copiar, já precisava ler), nem
  a falsificação do dono (o arquivo novo registra dono bruno, criador bruno
  e data de criação nova).
- **O que ele fez:** destruiu o arquivo da ana e pôs a versão dele no lugar,
  um problema de integridade e disponibilidade.
- **Onde isso não acontece:** nas homes privadas e em pastas onde o grupo só
  tem `r`.

O Linux tem o mesmo comportamento; o sticky bit é o que impediria isso. Ele
não foi implementado por simplicidade: pastas compartilhadas com escrita são
criadas de propósito pelo root para pessoas de confiança. É um exemplo do
equilíbrio entre simplicidade e integridade.

### 3.5 `~` entre aspas

O shell remove as aspas antes de examinar os argumentos, então `echo "~"`
também é trocado pela home (no bash, `~` entre aspas não seria trocado).

---

## 4. Etapas

| Etapa | Conteúdo | Situação |
|---|---|---|
| 1 | Usuários, senhas e login | concluída |
| 2 | Controle de acesso (checagem de r/w em todas as operações) | planejada |
| 3 | `chmod`, `chown` e `chgrp` | planejada |
| 4 | Grupos (`groupadd`, `usermod -aG`, `gpasswd -d`) e `sudo` | planejada |
| 5 | README e verificação completa | planejada |
| 6 | Pasta `tests/` com testes automatizados | planejada |

### Etapa 1 — Usuários, senhas e login (concluída)

**Objetivo:** criar a base de usuários: formato novo do i-node, contas
guardadas em `/etc`, senhas com scrypt, login e comandos de usuário. Nesta
etapa ainda **não** há conferência de `r`/`w` nas operações de arquivo; só
as regras de quem pode administrar (por exemplo, `useradd` só para o root).

#### O que foi implementado

**`fs/constants.py`**
- Formato novo do i-node, mantendo 128 bytes (16 i-nodes por bloco de 2048
  bytes): `owner_uid`, `gid` e `creator_uid` (4 bytes cada) e 20 bytes
  reservados.
- Byte de permissões com 2 bits por classe e constantes com os números do
  `chmod` (`PERM_644`, `PERM_640`, `PERM_600`, `PERM_666`); padrão 640 para
  arquivos e diretórios novos.
- Números fixos (root = 0, `sudo` = 27, usuários a partir de 1000),
  caminhos dos arquivos de contas e parâmetros do scrypt.
- Identificação do disco `SOF2`; `SOFS` guardado só para reconhecer e recusar
  discos antigos.

**`fs/structs.py`**
- `pack()`/`unpack()` do i-node com os três números no lugar dos dois
  textos; os 20 bytes reservados são gravados como zeros.

**`fs/errors.py`** (novo)
- A exceção `FSError` saiu de `filesystem.py`. Agora `filesystem.py` usa
  `accounts.py` e `accounts.py` também precisa do erro; se um importasse o
  outro, o Python falharia ao carregar (importação circular).

**`fs/passwords.py`** (novo)
- `hash_password`: gera o salt com `secrets`, calcula o scrypt e monta o
  texto `scrypt$17$8$1$<salt>$<hash>`.
- `verify_password`: recalcula o scrypt com o mesmo salt e compara com
  `hmac.compare_digest`. Uma comparação comum (`==`) para no primeiro byte
  diferente e o tempo revelaria quantos bytes acertaram. Para conta
  bloqueada, faz o cálculo inteiro e só depois recusa, para não responder
  mais rápido.
- `waste_time`: calcula um scrypt "falso" quando o usuário não existe.
- `lock`/`unlock`: põem ou tiram o `!` na frente do hash.
- O OpenSSL limita o scrypt a 32 MiB de memória por padrão; o código libera
  o dobro do necessário (256 MiB).

**`fs/permissions.py`** (novo)
- `perm_string`: transforma o byte de permissões no texto do `ls`
  (`-rwr---`, `drw----`, `lrwrwrw`).

**`fs/accounts.py`** (novo) — contas de usuários e grupos, parte do kernel
- Leitura dos arquivos para tabelas em memória (`load`). O shell chama
  `load` antes de cada comando, porque o root pode editar esses arquivos à
  mão e o que vale é sempre o que está no disco. Linhas malformadas são
  ignoradas.
- Gravação sempre em modo root, devolvendo o arquivo para `root:root` com a
  permissão padrão dele. Se alguém apagar o shadow, o kernel o recria já
  fechado.
- Gravação tudo ou nada (`_save`): se o disco encher no meio de uma
  gravação de vários arquivos, os já gravados voltam ao conteúdo antigo e as
  tabelas voltam ao estado anterior.
- Regras: `require_root`, `check_password` (recusa senha vazia),
  `check_name` (formato dos nomes).
- `initialize`: contas iniciais na formatação (usuário root; grupos root e
  sudo; sudoers com `%sudo`).
- `authenticate`, `login` e `switch_user` (`su`; o root troca sem senha).
- `check_useradd` e `useradd`, nesta ordem:
  1. confere se é root, se o nome é válido e se já existe;
  2. escolhe o UID (primeiro livre a partir de 1000) e o GID (igual ao UID
     se livre);
  3. calcula o hash;
  4. cria a home (`drw----`, dona a própria pessoa) — se já existir algo com
     esse nome, falha aqui, sem ter mexido nas contas;
  5. grava shadow, group e passwd, nessa ordem (o shadow antes do passwd
     garante que nunca exista um usuário no passwd sem senha);
  6. se a gravação falhar, remove a home criada.
- `change_password`: o usuário comum troca só a própria senha, informando
  a atual; o root troca qualquer uma.
- `set_locked`: `passwd -l`/`-u`, só root; bloquear o root é recusado.

**`fs/filesystem.py`** — o kernel
- Credenciais `uid`/`gid` de quem está usando o sistema (como as de um
  processo no Linux); começam como root para montar/formatar e são trocadas
  pelo login e pelo `su`.
- `as_root`: modo kernel (ver 2.9), com `finally` para sempre devolver as
  credenciais originais.
- `set_attrs`: muda dono, grupo e permissões sem checagem (uso interno).
- Abertura do disco: para um disco novo, confere a senha do root **antes**
  de criar o arquivo de 128 MB (não deixa disco pela metade); para um disco
  existente, se a montagem falhar, fecha o arquivo antes de mostrar o erro
  (no Windows, arquivo aberto não pode ser renomeado).
- Formatação: cria a raiz (`root:root`, 644), `/etc`, `/home`, `/root` e as
  contas iniciais (estrutura da seção 2.8).
- Montagem: recusa discos `SOFS` com mensagem explicativa.
- `_new_inode`: quem cria vira dono e criador; o grupo é o grupo primário
  de quem cria; permissão padrão 640.

**`fs/shell.py`** — a interface
- Fluxo: abre o disco (pedindo a senha do root se for novo) → tela de login
  (3 tentativas, mensagem única) → sessão de comandos → `logout` volta ao
  login, `exit` encerra.
- Leitura de senhas: `getpass` no terminal (não mostra o que é digitado);
  quando a entrada vem de um arquivo, lê como linha comum, o que permite
  testes automatizados (Etapa 6).
- Senha nova pedida duas vezes; a recusa de senha vazia usa a mesma regra
  do kernel (`Accounts.check_password`).
- Antes de cada comando: recarrega as contas e troca `~` e `~/...` pela
  home.
- Prompt `usuario@sofs:caminho$` (`#` para o root), com a home exibida
  como `~`.
- Comandos novos: `useradd`, `passwd` (própria, de outro usuário, `-l`,
  `-u`), `su`, `logout`, `whoami`, `id`, `users`, `groups`.
- `cd` sem argumento vai para a home; `ls` e `stat` mostram dono e grupo
  pelo nome (o `stat` mostra também o criador); `reset` só para o root,
  pedindo a senha do root do disco novo.

#### O que foi alterado

- I-node: dono e criador passaram de texto para número; entrou o GID.
- Permissões: de 3 bits (rwx) para dono e outros para 2 bits (rw) para dono,
  grupo e outros; padrão de arquivos novos de `rw-r--` para 640.
- Raiz do disco: passou a ser `root:root` com 644 (antes, o dono era o
  usuário do sistema operacional).
- `FileSystem.__init__`: recebe a senha do root (para formatar) em vez do
  nome do usuário atual.
- `reset`: agora só o root pode usar, e o disco novo recebe uma senha de
  root.

#### O que foi removido

- Os campos `creator` e `owner` como texto no i-node.
- O bit x e o layout antigo das permissões.
- A opção `--user` da linha de comando (o login a substitui).
- A classe `FSError` dentro de `filesystem.py` (movida para `errors.py`).
- O método `FileSystem.perm_string` (movido para `permissions.py`).
- A montagem de discos no formato antigo (`SOFS`).

#### Mudanças em relação ao plano

1. O formato `drwrwrw`, os nomes de dono e grupo no `ls`/`stat` e o padrão
   640 para arquivos novos estavam previstos para a Etapa 2, mas entraram
   aqui: como o i-node mudou, o `ls` antigo exibiria as permissões erradas e
   não teria mais o nome do dono.
2. O `reset` restrito ao root entrou aqui por ser uma regra de "quem pode
   administrar".
3. Encontrado nos testes: o `useradd` pedia a senha antes de conferir o
   nome. Foi criado o `check_useradd`, que o shell chama antes de pedir a
   senha.
4. Bug encontrado nos testes: a formatação passou a criar diretórios e usava
   o diretório atual antes de ele ser definido. O diretório atual passou a
   ser definido no início do `__init__`.

#### Testes realizados

Feitos com discos de teste separados, rodando o programa de verdade (a
entrada vinha de um arquivo) e chamando o kernel diretamente.

| Cenário | Resultado |
|---|---|
| Disco novo: senha vazia e senhas diferentes recusadas; estrutura e arquivos de `/etc` criados com as permissões da seção 2.8 | ok |
| `useradd`: home `drw----` da própria pessoa, grupo próprio, linhas no passwd, shadow e group; nome repetido e nome inválido recusados | ok |
| Usuário comum tentando `useradd`, `passwd bruno`, `passwd -l` e `reset` | as quatro tentativas deram "Permissão negada" |
| `passwd` com senha atual errada recusado; após a troca, a senha velha deixa de funcionar e a nova funciona | ok |
| `su` com senha errada recusado; root faz `su` sem senha; `su root` com senha | ok |
| Bloqueio: `!` no shadow, login recusado, root não pode ser bloqueado, desbloqueio devolve a senha antiga | ok |
| 3 logins errados encerram o programa; disco antigo recusado com mensagem | ok |
| Persistência após desmontar e montar; comandos antigos (`mkdir`, `echo`, `cp`, `mv`, `ln -s`, `rm`, `rmdir`, `df`) funcionando | ok |
| Tempo de login: senha certa 0,484 s, senha errada 0,462 s, usuário inexistente 0,448 s, conta bloqueada 0,468 s | tempos equivalentes |
| Rollback do `useradd` com falha simulada ao gravar o passwd: arquivos idênticos aos de antes, nada na memória, home removida; novo `useradd` funciona | ok |
| `reset` pelo root | ok |

#### Situação ao final da etapa

- As permissões **ainda não são conferidas** nas operações de arquivo: um
  usuário comum ainda consegue, por exemplo, ler o `/etc/shadow`. Isso é a
  Etapa 2.
- O README ainda menciona a opção `--user`; será atualizado na Etapa 5.

### Etapas 2 a 6 (planejadas)

- **Etapa 2 — Controle de acesso:** função central que decide a classe (root
  → dono → grupo → outros) e confere `r`/`w`; atravessar diretório exige
  `r`; checagens em todos os comandos (tabela da seção 2.4); `ls` só com
  nomes e `ls -l` completo; "seu acesso" no `stat`; permissões da cópia no
  `cp`; mensagem "Permissão negada".
- **Etapa 3 — `chmod`, `chown` e `chgrp`:** regras e sintaxes da seção 2.5;
  aplicados a links, agem no alvo.
- **Etapa 4 — Grupos e `sudo`:** `groupadd`, `usermod -aG`, `gpasswd -d`;
  `sudo` conforme a seção 2.7.
- **Etapa 5 — Fechamento:** README atualizado e verificação completa
  (tentativas contra o `/etc/shadow`, pasta compartilhada, sudo, bloqueio de
  conta).
- **Etapa 6 — Testes automatizados:** pasta `tests/` com testes que qualquer
  pessoa possa rodar, e instruções no README.

---

## 5. Pontos para a apresentação

- **Mapeamento da tríade CIA:**
  - **confidencialidade:** permissão `r`, `/etc/shadow` só para o root, hash
    com salt;
  - **integridade:** permissão `w`, `chown` só para o root, `chmod` só para o
    dono;
  - **disponibilidade:** `reset` só para o root, gravações "tudo ou nada"
    quando o disco enche.
- O hash protege as senhas mesmo se o arquivo vazar, mas não o conteúdo dos
  arquivos nem a integridade do disco fora do sistema (seção 3.1).
- Os grupos vão além do enunciado, mas contêm o modelo pedido (seção 2.4).
- As permissões de um link "ou seriam perigosas ou não serviriam para nada"
  (seção 2.10).
- O cenário de copiar e apagar o original numa pasta compartilhada (seção
  3.4).
- Por que o sudo não é restrito por comando (seção 2.7).
