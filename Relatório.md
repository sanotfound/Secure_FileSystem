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

**Permissão exigida por comando** (além de `r` nos diretórios do caminho,
incluindo o diretório pai do item; o root ignora as checagens):

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
| 2 | Controle de acesso (checagem de r/w em todas as operações) | concluída |
| 3 | `chmod`, `chown` e `chgrp` | concluída |
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

### Etapa 2 — Controle de acesso (concluída)

**Objetivo:** fazer o sistema passar a conferir as permissões. Ao fim desta
etapa, um usuário comum não consegue mais ler o `/etc/shadow`, entrar na
home de outro usuário nem criar arquivos fora dos lugares onde tem `w`.

#### Planejamento (anotado antes da implementação)

**O que será implementado:**
- **`fs/permissions.py`:** função `effective_access`, que decide em qual
  classe a pessoa cai para um i-node (root → dono → grupo → outros, parando
  na primeira; ver seção 2.4) e devolve os bits `r`/`w` que valem para ela.
  É a única regra de permissão do sistema; tudo o mais a usa.
- **`fs/filesystem.py`:**
  - método `_require` que chama `effective_access` com as credenciais atuais
    e, se faltar a permissão, gera o erro "`<caminho>`: Permissão negada";
  - os grupos de quem está logado são consultados a cada checagem (grupo
    primário + grupos em que foi adicionado), para que mudanças de grupo
    valham na hora (seção 2.6).
- **Atravessar diretórios exige `r`:** a resolução de caminhos confere `r`
  em cada diretório antes de procurar um nome dentro dele, **inclusive no
  diretório pai** do item final. Isso detalha a regra "em todos os casos
  também é preciso `r` nos diretórios do caminho": o pai faz parte do
  caminho, então criar ou apagar algo exige `r` (para entrar) e `w` (para
  alterar) nele.
- **Checagens em cada operação** (tabela da seção 2.4):

  | Operação | Checagem nova |
  |---|---|
  | `cat` | `r` no arquivo |
  | `echo >`, `echo >>` | `w` no arquivo; se o arquivo não existe, `w` no diretório pai |
  | `touch` | arquivo existente: `w` nele; arquivo novo: `w` no pai |
  | `cp` | `r` na origem; no destino, igual ao `echo >` |
  | `mkdir`, `ln -s` | `w` no pai |
  | `rm`, `rmdir` | `w` no pai |
  | `mv` | `w` no pai de origem e no pai de destino |
  | `ls`, `cd` | `r` no diretório listado ou de destino |
  | `stat` | nenhuma além de atravessar o caminho |

- **Permissões da cópia no `cp`:** quando o destino é criado, recebe as
  permissões do original limitadas pelo padrão 640 (seção 2.10).
- **`fs/shell.py`:**
  - `ls` passa a mostrar só os nomes; `ls -l` mostra a lista completa
    (permissões, dono, grupo, tamanho, data);
  - o `stat` ganha a linha "seu acesso", que mostra os bits que valem para
    quem está logado e o motivo (é o dono, está no grupo X, cai em "outros"
    ou é root). Para um link, informa que vale a permissão do alvo.

**O que será alterado:**
- `resolve` e `split_parent` (conferência de `r` ao atravessar);
- `touch`, `write_file`, `read_file`, `rm`, `cp`, `mv`, `ln_s`, `mkdir`,
  `rmdir`, `ls`, `cd` (checagens);
- `touch` em um link existente passa a atualizar o alvo, como no Linux
  (antes atualizava o próprio link);
- o comentário do topo de `filesystem.py`, que hoje diz que o controle de
  acesso ainda não é aplicado.

**O que será removido:**
- o `ls` sempre no formato longo (passa a depender de `-l`).

**Por quê:** é o núcleo do que o enunciado pede (leitura e escrita
controladas por permissões) e o que torna efetiva a proteção do
`/etc/shadow` (seção 2.2). As checagens ficam no kernel e não no shell
(seção 2.9). O código interno do sistema (login lendo o shadow, `useradd`
gravando em `/etc`) continua funcionando porque roda em modo kernel, como
root.

**Testes planejados:**
- todas as tentativas de um usuário comum contra o `/etc/shadow` que já
  são possíveis nesta etapa: `cat`, `cp`, link + `cat`, `rm`, `mv`,
  `echo >` e criar um arquivo novo em `/etc` (`chmod` e `chown` ficam para a
  Etapa 3);
- privacidade das homes: outro usuário não lista, não lê, não cria e não
  apaga nada dentro de uma home `drw----`;
- `/etc/passwd` e `/etc/group` continuam legíveis por todos;
- o root continua podendo tudo;
- o login, o `passwd` e o `su` continuam funcionando com um usuário comum
  logado (o kernel lê e grava o shadow em modo root);
- permissões da cópia no `cp` (original 600 → cópia 600; 644 → 640);
- `ls`/`ls -l` e a linha "seu acesso" nos casos de dono, grupo, outros,
  root e link.

#### O que foi implementado

**`fs/permissions.py`**
- `effective_access(inode, uid, gids)`: devolve a classe (`root`, `dono`,
  `grupo` ou `outros`) e os bits `r`/`w` que valem. Root ganha `rw` direto;
  depois a função compara o UID com o dono do i-node; depois procura o grupo
  do i-node entre os grupos da pessoa; senão, usa os bits de outros. Para na
  primeira classe que se encaixar (classes exclusivas).
- `bits_string`: bits de uma classe como texto (`rw`, `r-`, `--`), usada
  pelo `perm_string` e pela linha "seu acesso".

**`fs/filesystem.py`**
- `group_ids()`: grupos de quem está logado (primário + grupos em que foi
  adicionado), consultados nas tabelas de contas a cada checagem.
- `access_of(inode)`: aplica `effective_access` com as credenciais atuais;
  usada pelas checagens e pelo `stat`.
- `_require(inode, bits, rótulo)`: o ponto único de checagem. Se faltar
  algum dos bits pedidos, a operação para com "`<rótulo>`: Permissão
  negada", antes de qualquer alteração no disco.
- `resolve()`: antes de procurar cada nome dentro de um diretório, exige
  `r` nele. A mensagem de erro informa em qual diretório a resolução parou
  (ex.: `/home/bruno: Permissão negada` ao tentar `/home/bruno/b.txt`).
- `split_parent()`: exige `r` também no diretório pai, que é onde a
  operação vai procurar ou criar o nome.
- Checagens adicionadas nas operações:

  | Operação | Checagem | Onde |
  |---|---|---|
  | `read_file` (`cat`) | `r` no arquivo | depois de resolver o caminho |
  | `write_file` (`echo`) | `w` no arquivo existente; arquivo novo passa pelo `touch` | antes de gravar |
  | `touch` | `w` no arquivo existente (se for link, no alvo); `w` no pai para criar | antes de alocar o i-node |
  | `cp` | `r` na origem; destino pelo `write_file` | antes de ler a origem |
  | `rm` | `w` no pai | antes de tirar a entrada do diretório |
  | `mkdir`, `ln_s` | `w` no pai | antes de alocar o i-node |
  | `rmdir` | `w` no pai | antes de conferir se está vazio |
  | `mv` | `w` no pai de origem; `r` e `w` no pai de destino | antes de conferir se o destino já existe |
  | `ls` | `r` no diretório listado | depois de resolver |
  | `cd` | `r` no diretório de destino | antes de trocar o diretório atual |

- `cp`: quando o destino é criado, recebe `permissão do original & 640`
  (operação E bit a bit); dono, grupo e criador são de quem copiou. Se o
  destino já existia, mantém as permissões dele, como no Linux.
- Comentário do topo atualizado: as checagens ficam nas operações públicas
  e na resolução de caminhos; as funções de baixo nível (`read_data`,
  `write_data`, `add_dir_entry`...) não conferem nada, porque são usadas
  depois que a operação já foi autorizada.

**`fs/shell.py`**
- `ls` mostra só os nomes; `ls -l` (ou qualquer opção que contenha `l`)
  mostra a lista completa.
- `stat` ganhou a linha "seu acesso", com os bits e o motivo: "você é o
  dono", "você é membro do grupo X", "você não é o dono nem está no grupo:
  vale 'outros'" ou "você é root: as permissões não se aplicam". Para um
  link: "vale a permissão do alvo".
- Texto do `help` atualizado.

#### Detalhes definidos durante a implementação

1. **`mv` confere permissão antes de dizer "já existe".** Se a checagem viesse
   depois, `mv arq /home/bruno` responderia "já existe" ou não, revelando o
   conteúdo de um diretório que a pessoa não pode ler.
2. **`mv` exige `r` e `w` no diretório de destino.** O `w` é para alterar o
   diretório; o `r` é para procurar o nome dentro dele. Quando o destino é um
   diretório existente (`mv arq pasta/`), esse diretório não passa pelo
   `split_parent`, então o `r` precisa ser conferido aqui.
3. **`cp` sobre um destino que já existe mantém as permissões do destino**
   (as do original só valem quando a cópia é criada), como no Linux.
4. **O rótulo do erro é o caminho digitado.** `cat ~/atalho` (link para
   `/etc/shadow`) responde `/home/ana/atalho: Permissão negada`, como o
   Linux faz.

Não houve mudanças em relação ao planejamento.

#### Testes realizados

Pelo shell, com um disco novo, os usuários ana e bruno e um arquivo em
`/root`:

| Tentativa (usuário comum) | Resultado |
|---|---|
| `cat /etc/shadow` | Permissão negada |
| `cp /etc/shadow ~/copia` | Permissão negada |
| `ln -s /etc/shadow ~/atalho` e depois `cat ~/atalho` | link criado na própria home; leitura negada |
| `rm /etc/shadow`, `mv /etc/shadow ~/x` | Permissão negada |
| `echo hack > /etc/shadow`, `echo hack >> /etc/shadow`, `touch /etc/shadow` | Permissão negada |
| `touch /etc/novo`, `mkdir /x` | Permissão negada |
| `ls /root`, `cat /root/nota.txt` | Permissão negada |
| `ls`, `cd`, `cat`, `touch` e `rm` na home de outro usuário | Permissão negada |
| `mv ~/atalho /home/bruno` | Permissão negada (e não "já existe") |
| `cat /etc/passwd`, `cat /etc/group`, `ls -l /etc`, `stat /etc/shadow` | permitidos |
| Na própria home: `echo`, `mkdir`, `cp`, `ls`, `ls -l`, `stat` | permitidos |
| `passwd` e `su` com usuário comum logado (o kernel grava e lê o shadow) | funcionam |
| Root: `cat /etc/shadow`, ler a home da ana | permitidos; `stat` mostra "você é root" |

Chamando o kernel diretamente (grupos e permissões montados com
`set_attrs`, já que `chmod`/`chgrp` são da Etapa 3):

| Caso | Resultado |
|---|---|
| Pasta `/home/projeto` `drwrw--` do grupo alunos (ana, bruno): bruno cria arquivo | permitido; o arquivo nasce `-rwr---` com o grupo `bruno` |
| ana lê o arquivo do bruno antes do "chgrp alunos" | negado (o grupo do arquivo é `bruno`; ana cai em "outros") |
| ana lê o mesmo arquivo depois do "chgrp alunos" | permitido; escrever continua negado (o grupo só tem `r`) |
| carla (fora do grupo) lista a pasta ou lê o arquivo | negado |
| Classes exclusivas: `-r-rw--`, dono bruno, grupo alunos | bruno (dono) não escreve; ana (grupo) escreve |
| "Todos leem, menos estagiários": `-rw--r-`, grupo estagiarios | carla lê; diego (estagiário) não lê |
| bruno lê um arquivo da ana pelo grupo; root o tira do grupo | a leitura seguinte já é negada |
| `cp` de original 600 / 644 | cópia 600 / 640 |
| `cp` sobre destino existente com 600 | destino continua 600 |
| carla copia um arquivo legível da ana | cópia com dono, grupo e criador `carla` |
| Diretório com `-w` para outros (escrita sem leitura) | criar arquivo negado: atravessar exige `r` |

Os testes da Etapa 1 foram repetidos e continuam passando.

#### Situação ao final da etapa

- O `/etc/shadow` está protegido contra todas as tentativas possíveis até
  aqui. As tentativas por `chmod` e `chown` serão testadas na Etapa 3.
- Ainda não há comandos para mudar permissões, dono e grupo (Etapa 3) nem
  para criar grupos e usar `sudo` (Etapa 4).

### Ajuste entre as Etapas 2 e 3: comentários no código

**O que mudou:** os comentários e as docstrings escritos nas Etapas 1 e 2
foram reescritos em tom informal, explicando o raciocínio do jeito que o
código original do projeto já fazia (por exemplo: "sem isso, ...", "pra
nao ficar nada pela metade"). Os comentários do código original não foram
alterados. Arquivos afetados: `accounts.py`, `constants.py`, `errors.py`,
`filesystem.py`, `passwords.py`, `permissions.py`, `shell.py` e
`structs.py`.

**Por quê:** comentários informais tornam o raciocínio mais simples e mais
fácil de qualquer pessoa entender. Esse passa a ser o padrão das próximas
etapas.

**Como foi garantido que o código não mudou:** antes da revisão foi
guardada uma cópia de todos os arquivos. Depois, a árvore sintática (AST)
de cada arquivo foi comparada com a da cópia, ignorando as docstrings
(comentários com `#` nem entram na AST). Todos os arquivos tiveram AST
idêntica. Os testes das Etapas 1 e 2 foram repetidos e deram os mesmos
resultados.

### Etapa 3 — `chmod`, `chown` e `chgrp` (concluída)

**Objetivo:** dar aos usuários os comandos para mudar permissões, dono e
grupo, seguindo as regras da seção 2.5. É a parte do enunciado que pede
`chmod` e `chown` explicitamente.

#### Planejamento (anotado antes da implementação)

**O que será implementado:**
- **`fs/permissions.py`** — leitura do modo do `chmod`, devolvendo o byte de
  permissões novo:
  - **numérico:** exatamente 3 dígitos (dono, grupo, outros), cada um 0, 2,
    4 ou 6 (r = 4, w = 2). Ex.: `640` → `rwr---`. Dígito ímpar (que teria o
    x) ou maior que 7 é recusado com mensagem explicando o motivo;
  - **simbólico:** uma ou mais cláusulas separadas por vírgula, cada uma com
    quem (`u` dono, `g` grupo, `o` outros, `a` todos; vazio = todos), uma
    operação (`+` acrescenta, `-` tira, `=` define exatamente) e as letras
    (`r`, `w`). Ex.: `o-r`, `u+w`, `g=r`, `u=rw,g=r,o=`. A letra `x` é
    recusada.
- **`fs/accounts.py`:** consulta de grupo pelo nome (`get_group`), com
  erro se o grupo não existir.
- **`fs/filesystem.py`** — três operações do kernel:

  | Operação | Quem pode | O que muda |
  |---|---|---|
  | `chmod(caminho, modo)` | o dono ou o root | só as permissões |
  | `chown(caminho, dono, grupo)` | só o root | o dono e/ou o grupo |
  | `chgrp(caminho, grupo)` | o root, ou o dono se for membro do grupo de destino | só o grupo |

  As três seguem links (agem no alvo, seção 2.10) e passam pela resolução
  de caminhos normal (atravessar exige `r`). O campo "criador" nunca muda.
- **`fs/shell.py`:** os comandos `chmod <modo> <arquivo...>`,
  `chown <dono>[:<grupo>] <arquivo...>` (também `chown :<grupo>`) e
  `chgrp <grupo> <arquivo...>`, aceitando vários arquivos de uma vez, como
  no Linux; e o texto do `help`.

**Mensagens de erro (como no Linux):**
- "Permissão negada" continua sendo quando faltam os bits `r`/`w`;
- **"Operação não permitida"** é quando a operação exige ser o dono ou o root
  e a pessoa não é (ex.: `chmod` no arquivo de outra pessoa). O Linux faz a
  mesma distinção.

**O que será alterado:** nada do que já existe muda de comportamento; a
etapa só acrescenta operações.

**O que será removido:** nada.

**Por quê:** é exigência direta do enunciado. As regras de quem pode usar
cada comando foram decididas na seção 2.5:
- `chown` só para o root, para impedir que alguém "dê" um arquivo a outra
  pessoa;
- `chgrp` só para grupos de que o dono participa, para ninguém "jogar"
  arquivos num grupo do qual não faz parte;
- `chmod` para o dono, que é quem controla o próprio arquivo.

**Testes planejados:**
- todas as formas do `chmod` (numérico, simbólico, várias cláusulas, `=`
  vazio, sem "quem") e os modos inválidos (`755`, `7`, `999`, `u+x`, `abc`);
- usuário comum tentando `chmod`, `chown` e `chgrp` no `/etc/shadow` e no
  `/etc/passwd` (fecha as tentativas da seção 2.2 que faltavam);
- `chown` e `chgrp` em arquivo próprio para outro usuário ou para um grupo
  do qual a pessoa não faz parte;
- `chmod` em um link mudando o alvo;
- depois de um `chown`, o antigo dono deixa de poder usar `chmod`, e o
  "criador" continua o mesmo;
- o cenário completo de pasta compartilhada pelo shell: o root cria o grupo
  (editando o `/etc/group`, já que o `groupadd` é da Etapa 4), cria a pasta,
  faz `chown ana:alunos` e `chmod 660`; o bruno cria um arquivo e faz
  `chgrp alunos`; a ana lê;
- a limitação da seção 3.4 (um membro apaga o arquivo de outro numa pasta
  compartilhada), para confirmar que o comportamento é o documentado;
- grupo próprio + padrão 640: a ana abre a home (`chmod 644 ~`); os outros
  passam a listar a home, mas continuam sem ler os arquivos.

#### O que foi implementado

**`fs/permissions.py`**
- `parse_mode(modo, permissão_atual)`: decide se o modo é numérico (só
  dígitos) ou simbólico e devolve o byte de permissões novo.
- `_numeric_mode`: exige 3 dígitos. Cada dígito é convertido nos 2 bits da
  classe com `dígito >> 1` (6 → `11` rw, 4 → `10` r, 2 → `01` w, 0 → `00`)
  e posicionado no lugar da classe (dono, grupo, outros). Dígitos ímpares
  (que no Linux incluiriam o x) e maiores que 7 são recusados, cada um com
  sua mensagem.
- `_symbolic_mode`: separa as cláusulas pela vírgula e aplica cada uma em
  cima do resultado da anterior, começando da permissão atual. Cada cláusula
  é validada por uma expressão regular (quem, operação, letras):
  - **`+`** liga os bits pedidos (OU bit a bit);
  - **`-`** desliga os bits pedidos (E com a negação);
  - **`=`** zera os 2 bits da classe e liga só os pedidos (`o=` sozinho tira
    tudo dos outros).

  Sem "quem", a cláusula vale para todas as classes (`+w` = `a+w`). A letra
  `x` é aceita pela expressão regular só para poder ser recusada com uma
  mensagem clara.
- Tabelas `WHO_SHIFTS` (letra de quem → posição da classe no byte) e
  `LETTER_BITS` (letra de permissão → bit).

**`fs/accounts.py`**
- `get_group(nome)`: devolve o grupo ou dá o erro "grupo 'x' não existe".

**`fs/filesystem.py`**
- `chmod(caminho, modo)`: resolve o caminho (seguindo links), calcula a
  permissão nova (um modo inválido dá erro antes de qualquer outra coisa),
  confere se quem pede é o dono ou o root e grava.
- `chown(caminho, dono, grupo)`: converte os nomes em UID/GID antes de
  tudo (um nome inexistente dá erro sem mexer em nada), resolve o caminho,
  exige root e grava dono e/ou grupo.
- `chgrp(caminho, grupo)`: converte o nome em GID, resolve o caminho e
  aceita se quem pede é root, ou se é o dono **e** faz parte do grupo de
  destino.
- Nenhum dos três altera o campo "criador" nem a data de modificação (o
  conteúdo do arquivo não muda).

**`fs/shell.py`**
- `chmod <modo> <arquivo...>`, `chown <dono>[:<grupo>] <arquivo...>`,
  `chown :<grupo> <arquivo...>` e `chgrp <grupo> <arquivo...>`, todos
  aceitando vários arquivos.
- O argumento do `chown` é separado no `:`: `ana` muda só o dono,
  `ana:alunos` muda os dois, `:alunos` muda só o grupo. `ana:` (dois-pontos
  sem grupo) é recusado com a mensagem de uso.
- Nova seção "Permissões" no `help`.

#### Detalhes definidos durante a implementação

1. **`chown ana:` não é aceito.** No Linux, isso significaria "dono ana e o
   grupo de login dela". Foi deixado de fora por simplicidade, e a forma
   recusada mostra a mensagem de uso.
2. **O `chmod` numérico exige exatamente 3 dígitos.** O Linux aceita menos
   (`chmod 6` = `006`), mas aqui a regra fixa evita ambiguidade.
3. **Ordem das conferências:** primeiro a validação do pedido (modo, nomes de
   usuário e de grupo), depois a resolução do caminho e por último quem pode
   fazer. Assim, um erro de digitação aparece como erro de digitação, e nada
   é alterado antes de todas as conferências passarem.

Não houve mudanças em relação ao planejamento.

#### Testes realizados

Leitura do modo (25 casos, a partir de `-rwr---`):

| Modo | Resultado |
|---|---|
| `640`, `644`, `600`, `666`, `000`, `062` | `-rwr---`, `-rwr-r-`, `-rw----`, `-rwrwrw`, `-------`, `---rw-w` |
| `o-r`, `o+r`, `u-w`, `g=rw`, `a=r` | `-rwr---`, `-rwr-r-`, `-r-r---`, `-rwrw--`, `-r-r-r-` |
| `u=rw,g=r,o=`, `+w`, `-r`, `ug+w`, `a-rw`, `go=` | `-rwr---`, `-rwrw-w`, `--w----`, `-rwrw--`, `-------`, `-rw----` |
| `755`, `u+x` | recusados: "aqui não existe x" |
| `7`, `6400`, `999`, `abc`, vazio, `u=rw,x` | recusados: modo inválido |

Pelo shell:

| Caso | Resultado |
|---|---|
| A ana usa `chmod` nos próprios arquivos (numérico, simbólico, vários arquivos de uma vez) | funciona; `ls -l` mostra cada mudança |
| Depois de `chmod u=r,g=,o=`, a ana tenta escrever | Permissão negada; depois de `chmod u+w`, volta a escrever |
| `chmod 640 link` | o alvo muda; o link continua `lrwrwrw` |
| A ana usa `chmod` no `/etc/shadow` (`666`, `o+r`) e no `/etc/passwd` | Operação não permitida |
| A ana usa `chown ana`, `chown ana:ana` e `chgrp ana` no `/etc/shadow` | Operação não permitida; o shadow continua ilegível |
| A ana tenta `chown bruno` no próprio arquivo | Operação não permitida (só root) |
| A ana tenta `chgrp sudo` (não é membro) / `chgrp ana` (é membro) no próprio arquivo | negado / permitido |
| Grupo ou usuário inexistente; `chown ana:` | mensagens "não existe" / uso |
| A ana faz `chmod 644 ~` | o bruno lista a home dela, mas `cat` no arquivo `-rwr---` dá Permissão negada ("seu acesso: --") |
| O root faz `chown bruno` num arquivo da ana | o dono vira bruno, o criador continua ana; a ana perde o `chmod` (Operação não permitida) |
| Pasta compartilhada: o root acrescenta `alunos:x:1100:ana,bruno` ao `/etc/group`, cria `/home/projeto`, faz `chown ana:alunos` e `chmod 660` | `id` do bruno já mostra o grupo `alunos` |
| O bruno cria `b.txt` na pasta (nasce com o grupo `bruno`) e faz `chgrp alunos` | a ana lê o arquivo ("seu acesso: r-, membro do grupo alunos") |
| A carla (fora do grupo) lista a pasta / faz `chgrp alunos` na própria home | Permissão negada / Operação não permitida |
| Limitação 3.4: o bruno copia o `a.txt` da ana, apaga o original e põe a cópia no lugar | acontece, como documentado; o `stat` mostra dono e criador `bruno` |

Os testes das Etapas 1 e 2 foram repetidos e continuam passando.

#### Situação ao final da etapa

- O `/etc/shadow` está protegido contra todas as tentativas listadas na
  seção 2.2, incluindo `chmod`, `chown` e `chgrp`.
- Por enquanto, criar grupos exige editar o `/etc/group` à mão (como root);
  os comandos `groupadd`, `usermod -aG` e `gpasswd -d`, e o `sudo`, são da
  Etapa 4.

### Etapas 4 a 6 (planejadas)

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
