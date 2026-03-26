# Relatório curto - PBL 1: Normalização de Eventos de Segurança em C

## Regras adotadas para validação

Para que um registro fosse considerado válido, foi exigida a presença dos campos `event_id`, `device`, `severity` e `status`, conforme consta no PBL. Registros com algum desses campos ausente, vazio ou inválido foram descartados. Também foi adotada a regra de que linhas delimitadas deveriam conter exatamente seis campos úteis após o tratamento, o que corresponde a `event_id`, `device`, `severity`, `status`, `failed_logins` e `source`.

No caso do campo `severity`, os únicos valores aceitos ao final da normalização foram `LOW`, `MEDIUM`, `HIGH` e `CRITICAL`. Para o campo `status`, os únicos valores aceitos ao final foram `OPEN`, `CLOSED` e `INVESTIGATING`.

## Como os dados foram tratados

A base foi lida linha por linha com `fgets`, para que o programa tivesse controle sobre cada registro antes de interpretá-lo. Essa decisão foi adotada porque o arquivo de entrada possuía diversas inconsistências, como espaços excedentes, delimitadores diferentes, mistura de maiúsculas e minúsculas, campos ausentes e formatos no estilo `campo=valor`.

O tratamento foi feito em etapas. Primeiro, a linha era capturada e os espaços excedentes eram removidos. Em seguida, os delimitadores `,` e `|` eram convertidos para `;`, para permitir uma tokenização. Depois disso, os campos eram extraídos e copiados para uma `struct`, que passou a representar o evento já organizado em memória. Ao final, os campos textuais foram padronizados: `severity`, `status`, `event_id` e `source`.

## Como registros inválidos foram resolvidos

Linhas vazias foram ignoradas. Linhas incompletas, corrompidas ou com quantidade irregular de campos foram descartadas. Registros que, após a normalização, continuavam sem `event_id`, `device`, `severity` ou `status` válidos também foram descartados.

Para o campo `failed_logins`, foi adotada a política de manter o registro com valor `0` quando o conteúdo estivesse ausente ou inválido, desde que os demais campos obrigatórios estivessem corretos. Essa decisão foi tomada porque o próprio PBL permite essa abordagem, desde que explicitada no relatório, e porque ela preserva registros úteis sem comprometer a base.

## Principais dificuldades técnicas encontradas

A principal dificuldade foi tratar diferentes formatos de entrada dentro do mesmo arquivo, já que nem todas as linhas seguiam a mesma convenção. Também houve dificuldade inicial na manipulação de strings em C, especialmente com funções como `strcmp`, `strcpy` e `strtok`, além da necessidade de cuidado com o tamanho dos vetores de caracteres para evitar sobrescrita de memória.

Outra dificuldade  foi entender melhor o fluxo entre leitura, interpretação e persistência: primeiro capturar a linha, depois validar, depois transformar e só então gravar a saída. Além disso, o uso de memória dinâmica exigiu bastante atenção, principalmente no redimensionamento com `realloc` e na liberação correta com `free`, para evitar perda de referência e vazamento de memória.

## Consideração final

O desenvolvimento do PBL ajudou a consolidar, de forma prática, os conteúdos de ponteiros, `struct`, manipulação de strings, leitura de arquivos e alocação dinâmica em C.