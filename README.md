# Sistema de arquivos baseado em i-nodes

Trabalho de Sistemas Operacionais. O "disco" é um arquivo de exatamente
128 MiB (`disco.img`), criado e formatado na primeira execução. Nas execuções
seguintes o disco é montado e todo o conteúdo anterior continua lá
(persistência).

## Como executar

```
python3 main.py                       # usa ./disco.img
python3 main.py --disk outro.img      # outro arquivo de disco
python3 main.py --user maria          # usuário gravado como criador/dono
```

Digite `help` dentro do shell para ver os comandos.

## Comandos

| Arquivos | Diretórios |
|---|---|
| `touch`, `rm`, `cat`, `cp`, `mv` | `mkdir`, `rmdir` (só se vazio), `ls`, `cd`, `mv` |
| `echo "x" > arq` (cria/sobrescreve) | `ln -s alvo link` (também para diretórios) |
| `echo "x" >> arq` (acrescenta ou cria) | `.` e `..` funcionam em qualquer caminho |
| `ln -s alvo link` | |

Todos aceitam caminho absoluto e relativo. Extras de apoio: `pwd`, `stat`,
`df`, `reset`, `help`, `exit`.

## Layout do disco

Segue o esquema visto em aula (superbloco, controle de espaço livre, i-nodes,
diretório raiz, dados):

| Blocos | Conteúdo |
|---|---|
| 0 | Superbloco (magic `SOFS`, tamanhos, onde começa cada região, contadores de livres) |
| 1 | Bitmap de i-nodes (8192 bits) |
| 2–5 | Bitmap de blocos (65.536 bits) |
| 6–517 | Tabela de i-nodes (8192 × 128 B = 1 MiB) |
| 518–65.535 | Área de dados (65.018 blocos de 2048 B) |

Os 518 primeiros blocos (1036 KiB) são o espaço de gerenciamento; o restante
é para dados de arquivos e diretórios. O i-node 0 é sempre o diretório raiz.

## I-node (128 bytes)

Nome, criador, dono, tamanho, data de criação, data de modificação,
permissões (3 bits do dono + 3 bits dos outros: r/w/x), 8 ponteiros diretos
para blocos e `next_inode`, o apontador para outro i-node (o "eventual outro
i-node" do enunciado). Além disso há um byte de "em uso" e um de tipo
(arquivo, diretório ou link simbólico).

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
são gravados em binário com o módulo `struct`; não há JSON nem pickle.

## Decisões e limitações

- **Nomes:** até 27 bytes em UTF-8 (limite da entrada de diretório).
- **Permissões:** o i-node guarda e o `ls`/`stat` mostram as permissões do
  dono e de outros usuários (r/w/x), como o enunciado pede, mas **nenhuma
  operação verifica essas permissões** (não há controle de acesso) e não há
  `chmod`.
- **`mv` para um nome que já existe** retorna erro (não sobrescreve).
- **`cp`** copia apenas arquivos, não diretórios.
- **Número máximo de i-nodes:** 8192. Os i-nodes de continuação (1 a cada 8
  blocos de um arquivo ou diretório grande) saem dessa mesma tabela.
- **Disco cheio:** aumentar um arquivo ou diretório é "tudo ou nada". Se não
  houver blocos ou i-nodes suficientes, o comando falha com erro e nada é
  alterado (o arquivo continua com o conteúdo antigo, sem blocos ou i-nodes
  perdidos). O mesmo vale para `touch`, `mkdir`, `ln -s` e `mv`.
- **Diretório atual:** não é gravado no disco; cada execução começa em `/`.
  `rmdir` recusa remover o diretório em que o shell está.
