# PBL 1 — Normalização de Eventos de Segurança em C

Projeto desenvolvido para a disciplina de Nivelamento em Segurança da Informação.

## Objetivo

Ler um arquivo bruto de eventos de segurança, tratar inconsistências, normalizar os campos válidos e gerar um novo arquivo padronizado.

## Tecnologias

- Linguagem C
- GCC
- Make
- Git

## Conteúdos aplicados

- Ponteiros e acesso à memória
- Alocação dinâmica
- Structs e vetores de structs
- fopen, fgets, fprintf e manipulação de arquivos texto

## Estrutura

- `src/main.c`: código principal
- `data/raw_security_events.txt`: base bruta
- `data/security_events_cleaned.txt`: saída gerada
- `docs/relatorio.md`: decisões de implementação

## Como executar

```bash
make
./pbl1