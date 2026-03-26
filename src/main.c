#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


typedef struct{
    char event_id[32];
    char device[64];
    char severity[16];
    char status[20];
    int failed_logins;
    char source[32];
    int is_valid;
} SecurityEvent;

// --- Função para inicializar a struct
// Importante para não ficar com memória suja no início 
void init_event(SecurityEvent *event){
    event -> event_id[0] = '\0'; // identificador do evento - string vazia
    event -> device[0] = '\0'; // nome do dispositivo
    event -> severity[0] = '\0'; //serveridade padronizada
    event -> status[0] = '\0'; //status padronizado
    event -> source[0] = '\0'; //origem do evento
    event -> failed_logins = 0; // quantidade de falhas de login; zero é padrão
    event -> is_valid = 0; // marca lógica: 1 se válid, 0 se inválido; começa inválido até provar o contrário
}

// --- Função para limpar os espaços do texto ---

// remove espaços do começo e do fim da string

void trim_whitespace(char *text){
    // 'start' vai caminhar até encontrar o primeiro caractere que não seja um espaço vazio
    char *start = text;
    //enquanto houver caractere e ele for espaço, vai avançando
    while(*start && isspace((unsigned char)*start)){
        start++;
    }

    /* Se o primeiro caractere não estiver no começo original da string,
    o conteúdo é movido para a esquerda.*/

    if (start != text){
        memmove(text, start, strlen(start) +1); 
        //memmove move o conteúdo da string para a esquerda
    }

    /* Agora remove os espaços do final.
    
    strlen(text) devolve o tamanho atual da string.
    O último caractere(útil) está em len -1*/

    int len = (int)strlen(text);
    while(len > 0 && isspace((unsigned char) text[len -1])){
        text[len - 1] = '\0';
        len --;
    }
}

/* to_uppercase converte todos os caracteres da string para maiúsculo.
auth_module = AUTH_MODULE

Como o arquivo mistura maiúscula e minúsculas, é preciso padronizar antes de se fazer
a comparação e gravação*/


// --- Função para converter letras maiúsculas ---


void to_uppercase(char *text){
    while(*text){
        *text = (char)toupper((unsigned char)*text);
        text ++;
    }
}

// --- Função para normalizar severity

void normalize_severity(char *severity){
    // Primeiro limpa a string
    trim_whitespace(severity);
    // Depois padroniza para maiúsculo
    to_uppercase(severity);

    /* strcmp compara strings.
    Ele retorna 0 quando as strings são iguais
    strcmp("MED", "MED") == 0 -> verdadeiro*/

    if (strcmp(severity, "MED")== 0){

        /* strcpy copia uma string para outra.
        Aqui estamos sobrescrevendo o conteúdo de severity com "MEDIUM"
        strcpy não checa tamanho, por isso o vetor de destino precisa ter espaço suficiente*/
        strcpy(severity, "MEDIUM");
    } else if (strcmp(severity, "CRIT")== 0){
        strcpy(severity, "CRITICAL");
    } else if(
        strcmp(severity, "LOW")!= 0 &&
        strcmp(severity, "MEDIUM")!= 0 &&
        strcmp(severity, "HIGH")!= 0 &&
        strcmp(severity, "CRITICAL")!=0
    ){
        /* Se não bate com nenhum valor aceito, o campo é invalidado*/
        severity[0] = '\0'; 
        // Zera quando for inválido, assim a validação final fica simples: campo vazio = inválido.
    }
}

/* normalize_severity recebe uma string de severidade e tenta converter para um dos valores
aceitos pelo pbl: LOW, MEDIUM, HIGH, CRITICAL.

med = MEDIUM
crit = CRITICAL

Se o valor não for reconhecido, a estratégia que será adotada posteriormente será a de tornar o campo inválido
transformando-o em uma string vazia*/

/*normalize_status faz o mesmo raciocício, mas agora para status.
O valor finais aceitos são: OPEN, CLOSED, INVESTIGATING.
done -> CLOSED
resolved -> CLOSED
analysis -> INVESTIGATING
in_progress -> INVESTIGATING*/

// --- Função para normalizar status
void normalize_status(char *status){
    trim_whitespace(status);
    to_uppercase(status);

    if (strcmp(status, "DONE") == 0 || strcmp(status, "RESOLVED") == 0){
        strcpy(status, "CLOSED");
    } else if (strcmp(status, "ANALYSIS") == 0 || strcmp(status, "IN_PROGRESS") == 0){
        strcpy(status, "INVESTIGATING");
    } else if (
        strcmp(status, "OPEN") != 0 &&
        strcmp(status, "CLOSED") !=0 &&
        strcmp(status, "INVESTIGATING") != 0
    ) {
        status[0] = '\0';
    }
}

/* is_number verifica se a string inteira é composta de apenas dígitos.

5 -> válido
08 -> válido
x -> inválido
"" -> inválido 

O pbl exige que failed_logins seja numérico*/

int is_number(const char *text){
    // string vazia não conta como um número válido
    if(*text == '\0'){
        return 0;
    }

    while(*text){
        /* isdigit verifica se um aractere é um dígito.
        Se qualquer caractere não for umdígito, a string então não representa um inteiro*/
        if(!isdigit((unsigned char)*text)){
            return 0;
        }

        text++;
    }

    return 1;
}

/*is_blank_line verifica se a linha é vazia ou contém apenas espaços ou quebras de linhas.
O pbl manda ignorar linhas vazias*/

int is_blank_line(const char *line){
    while(*line){
        if(!isspace((unsigned char)*line)){
            return 0; // encontrou algo, então não é linha em branco
        }
        line++;
    }

    return 1; // só tinha espaços brancos ou quebras

}

/*parse_delimited_line trata linhas do formato posicional como:

EVT - 001 / ThinkPAD-T14 . high ; open ; 5 ; auth_module

Ela padroniza delimitadores para ';'
quebra a linha em partes com strtok
verifica se veio exatamente 6 campos
copia os dados para a struct
normaliza os campos
valida*/

int parse_delimited_line(char *line, SecurityEvent *event){
    /* Aqui percorremos a linha, caractere por caractere.
    Se encontrar ',' ou '|', substituti por ';'
    Assim, o restante da lógica tranalha com um único delimitador*/
    for (int i = 0; line[i] != '\0'; i++){
        if(line[i] == ',' || line[i] == '|'){
            line[i] = ';';
        }
    }
     /*fields é um vetor de ponteiros para char
     Cada posição vai apontar para o início de um campo dentro da linha
     Ponteiros para dados textuais também são ponteiros*/

    char *fields[10];
    int count = 0;

    /* strtok quebra a string usando ';' como separador.
    
    Funcionamento:
    
    - Na primeira chamada é passada a string original;
    - Nas próximas chamadas, passamos NULL para continuar de onde parou.
    
    strtok(line, ";") -> primeiro campo
    strtok(NULL, ";") -> segundo campo
    
    strtok modifica a string original
    por isso recebemos 'char *line' e não const char *line*/

    char *token = strtok(line, ";");
    while(token != NULL && count < 10){
        trim_whitespace(token); // limpa espaços do token atual
        fields[count++] = token; // guarda o ponteiro desse campo
        token = strtok(NULL, ";"); // vai para o próximo campo
    }

    /* para este formato foram separados 6 campos:
    
    0 -> event_id
    1 -> device
    2 -> severity
    3 -> status
    4 -> failed_logins
    5 -> source
    
    Se vierem mais ou menos campos, são descartados.*/

    if(count != 6){
        return 0;
    }

    /* Agora os campos são copiados para a struct.
    Isso é feito porque os ponteiross em fields apontam para pedaços da linha original,
    e essa linha não é o local definitivo de armazenamento*/

    strcpy(event -> event_id, fields[0]);
    strcpy(event -> device, fields[1]);
    strcpy(event -> severity, fields[2]);
    strcpy(event -> status, fields[3]);

    /*O campo failed_login é um campo numérico.
    Então, primeiro é preciso validar como texto numérico e só depois fazer a conversão para inteiro
    
    O atoi converte texto para inteiro.
    
    "5" -> 5*/

    if(is_number(fields[4])){
        event -> failed_logins = atoi(fields[4]);
    } else{

        /*se failed_logins vier válido, mantém 0.
        O pbl permite isso, basta relatar.*/
        event -> failed_logins = 0;
    }

    strcpy(event -> source, fields[5]);

    return 1;
}

/*parse_key_value_line trata linhas do tipo
id=EVT-1014 ; device=ThinkCentre-M70s ; severity=critical ; status=analysis ; failed=9 ; source=soc_pipeline

Em vez de assumir posições fixas, cada pedaço nem no formato chave=valor*/


int parse_key_value_line(char *line, SecurityEvent *event){
    char *fields[10];
    int count = 0;
    // Primeiro qubra a linha em espaços separados por ';'
    char *token = strtok(line, ";");
    while(token != NULL && count < 10){
        trim_whitespace(token);
        fields[count++] = token;
        token = strtok(NULL, ";");
    }

    /*Agora cada campo é percorrido em busca do caractere '='.
    strchr procura a primeira ocorrência de um caractere numa string
    
    strch("id=EVT-1001", '=') -> ponteiro para '='*/

    for(int i = 0; i < count ; i++){
        char *equal = strchr(fields[i], '=');
        if(equal == NULL){
            continue;
        }

        /* Transformamos a string "chave=valor" em duas strings separadas.
        
        "id=EVT-1001
        Ao fazer *equal = '\0', a memória fica assim: "id\0EVT-1001"
        
        Então:
        
        fields[i] ->  "id"
        equal + 1 -> EVT-1001*/

        *equal = '\0';

        //buffers auxiliares para chave e valor
        char key[32];
        char value[128];
        //Copia a chave e o valor
        strcpy(key, fields[i]);
        strcpy(value, equal +1);

        trim_whitespace(key);
        trim_whitespace(value);
        to_uppercase(key);

        /* AGora testa qual chave apareceu e salva no campo certo da struct*/

        if(strcmp(key, "ID") == 0){
            strcpy(event -> event_id, value);
        } else if(strcmp(key, "DEVICE")== 0){
            strcpy(event -> device, value);
        } else if(strcmp(key, "SEVERITY")== 0){
            strcpy(event -> severity, value);
        } else if(strcmp(key, "STATUS") == 0){
            strcpy(event -> status, value);
        } else if(strcmp(key, "FAILED")== 0|| strcmp(key, "FAILED_LOGINS") == 0){
            if(is_number(value)){
                event -> failed_logins = atoi(value);
            } else {
                event -> failed_logins = 0;
            }
        } else if (strcmp(key, "SOURCE")== 0){
            strcpy(event -> source, value);
        }
    }

    /*

    trim_whitespace(event -> event_id);
    trim_whitespace(event -> device);
    trim_whitespace(event -> severity);
    trim_whitespace(event -> status);
    trim_whitespace(event -> source);

    to_uppercase(event -> event_id);
    to_uppercase(event -> source);

    normalize_severity(event -> severity);
    normalize_status(event -> status);

    if(
        event -> event_id[0] == '\0' ||
        event -> device[0] == '\0' ||
        event -> severity[0] == '\0' ||
        event -> status[0] == '\0' 

    ) {
        return 0;
    }

    

    event -> is_valid = 1;

    */

    return 1;
    
    
}

/*parse_line_to_event é a função que decide qual parser usar.

Ela recebe a linha original lida do arquivo e decide:
- se a linha é vazia, rejeita
- se tem '=', trata como chave-valor
- caso contrário, trata como linha delimitada*/

int parse_line_to_event(const char *line, SecurityEvent *event){

    /* buffer é uma cópia mutável da linha original.
    
    Ela é copiada porque o strtok modifica a string que é recebida. 
    Como a função recebe const char *line, não se deve alterar diretamente a linha original*/
    char buffer[512];

    //copia a linha para o buffer local
    strcpy(buffer, line);

    /* strcspn(buffer, "\r\n") encontra a posição da primeira quebra de linha
    Então susbtituímos esse ponto pot '\0'.
    
    Como resultado, rmeovemos o '\' que o fgets costuma trazer.*/
    buffer[strcspn(buffer, "\r\n")] = '\0';
    //limpa espaços de sobra
    trim_whitespace(buffer);

    //se a linha ficou vazia depois da limpeza, então não tem nada "útil"
    if(buffer[0] == '\0'){
        return 0;
    }

    init_event(event);

    int parsed = 0;

    /* Se existir '=' na linha, entedemos que ela está no formato chave=valor.
    Caso contrário, usamos o parser delimitado.*/

    if(strchr(buffer, '=')!= NULL){
        parsed = parse_key_value_line(buffer, event);
    } else{
        parsed = parse_delimited_line(buffer, event);
    }

    //Se o parser falhou, devolve inválido
    if(!parsed){
        return 0;
    }

    trim_whitespace(event -> event_id);
    trim_whitespace(event -> device);
    trim_whitespace(event -> severity);
    trim_whitespace(event -> status);
    trim_whitespace(event -> source);

    to_uppercase(event -> event_id);
    to_uppercase(event -> source);
    normalize_severity(event -> severity);
    normalize_status(event -> status);

    if(
        event -> event_id[0] == '\0' ||
        event -> device[0] == '\0' ||
        event -> severity[0] == '\0' ||
        event -> status[0] == '\0' 
    ) {
        return 0;
    }

    event -> is_valid = 1;
    return 1;
}

/* write_clean_file grava o arquivo final

O pbl pede escrita com fprint e formato final como:
EVENT_ID;DEVICE;SEVERITY;STATUS;FAILED_LOGINS;SOURCE*/
void write_clean_file(const char *filename, SecurityEvent *events, int count){

    /*fopen com "w" abre arquivo para escrita
    Se o arquivo já existir, ele vai ser sobrescrito.*/
    FILE *out = fopen(filename, "w");
    if(out == NULL){
        printf("Erro na criação do arquivo de saída!\n");
        return;
    }
    //Cabeçalho do arquivo limpo
    fprintf(out, "EVENT_ID;DEVICE;SEVERITY;STATUS;FAILED_LOGINS;SOURCE\n");

    /* Agora o vetor de eventos é percorrido e gravados.
    events[i] acessa o elemnto de posição i do vetor dinâmico*/

    for(int i = 0; i < count; i++){
        fprintf(out, "%s;%s;%s;%s;%d;%s\n",
                events[i].event_id,
                events[i].device,
                events[i].severity,
                events[i].status,
                events[i].failed_logins,
                events[i].source);
    }
    // fecha o arquivo para liberar o recursos
    fclose(out);
}

/*main: coordena todo o fluxo do pbl
1. abre o arquivo
2. aloca memória dinâmica para armazenar os eventos validos
3; lê cada linha com fgets
4. ignora as linhas vazias
5. transforma cada linha em struct válida ou inválida
6. guarda os válidos na memória
7. no final grava o arquivo
8. exibe um resumo*/

int main(void) {




    /*char line[] = "id=EVT-1014 ; device=ThinkCentre-M70s ; severity=critical ; status=analysis ; failed=9 ; source=soc_pipeline";
    SecurityEvent event;

    init_event(&event);

    if(parse_key_value_line(line, &event)){
        printf("%s | %s | %s | %s | %d | %s\n",
        event.event_id, event.device, event.severity,
        event.status, event.failed_logins, event.source);
    } else {
        printf("Linha inválida\n");
    }

    return 0;
    */


    /*
    char line1[] = "EVT-1001 ; ThinkPad-T14 ; high ; open ; 5 ; auth_module";
    char line2[] = "EVT-1003 | Yoga-7i | CRIT | analysis | 8 | lsbd_collector";
    char line3[] = "EVT-1008 ; ; high ; open ; 3 ; auth_module";

    SecurityEvent event;

    init_event(&event);
    if (parse_delimited_line(line1, &event)) {
        printf("%s | %s | %s | %s | %d | %s\n",
               event.event_id, event.device, event.severity,
               event.status, event.failed_logins, event.source);
    }

    init_event(&event);
    if (parse_delimited_line(line2, &event)) {
        printf("%s | %s | %s | %s | %d | %s\n",
               event.event_id, event.device, event.severity,
               event.status, event.failed_logins, event.source);
    }

    init_event(&event);
    printf("Linha 3 valida? %d\n", parse_delimited_line(line3, &event));

    return 0;
    *\
}


    /*

    char severity1[16] = " high";
    char severity2[16] = "crit";
    char status1[20] = " resolved";
    char status2[20] = "analysis";

    normalize_severity(severity1);
    normalize_severity(severity2);
    normalize_status(status1);
    normalize_status(status2);

    printf("severity1 = %s\n", severity1);
    printf("severity2 = %s\n", severity2);
    printf("status1 = %s\n", status1);
    printf("status2 = %s\n", status2);

    return 0;

    */

    
    /* fopen abre o arquivo em modo leitura ("r")
    Se der erro, retorna NULL
    O pbl exige que esse erro não seja ignorado*/
    FILE *file = fopen("data/raw_security_events.txt", "r");

    if(file == NULL){
        printf("Erro ao abrir o arquivo data/raw_security_events.txt\n");
        return 1;
    }

    /*capacity representa quantos eventos cabem no vetor no momento
    começamos só com o valor 10*/

    int capacity = 10;
    // quantos registros válidos já foram guardados
    int valid_count = 0;
    // quantas linhas totais o arquivo tinha
    int total_lines = 0;
    // quantos registros acabaram sendo inválidos
    int invalid_count = 0;

    /* malloc reserva memória dinâmica para 'capacity' structs.
    
    -sizeof(SecurityEvent) = tamanho de uma struct em bytes
    - capacity * sizeof(SecurityEvent) = espaço para várias structs
    - malloc(...) = pede esse espaço ao sistema e devolve um ponteiro*/

    SecurityEvent *events = malloc(capacity * sizeof(SecurityEvent));
    if(events == NULL){
        printf("Problema de alocação de memória!\n");
        fclose(file);
        return 1;
    }

    /*line é o buffer onde cada linha lida com fgets será armazenada.
    Primeiro é preciso capturar a linha e depois interpretar*/

    char line[512];

    /*fgets lê uma linha do arquivo.
    
    Enquanto fgets conseguir ler uma nova linha, o laço continua.
    
    fgets(line, sizeof(line), file)
    
    - line: buffer de destino
    - sizeof(line): tamanho máximo que cabe no buffer
    - file: arquivo de onde vem a leitura*/

    while(fgets(line, sizeof(line), file) != NULL){
        total_lines ++;
        // printf("Linha %d: %s", total_lines, line);  
        if(is_blank_line(line)){
            continue;
        }

        SecurityEvent event;
        init_event(&event);

        if(parse_line_to_event(line, &event)){

            /* Se o vetor já estiver cheio, é preciso aumentá-lo.
            
            realloc tenta redimensionar a memória já alocada*/
            if(valid_count == capacity){
                // dobra a capacidade
                capacity = capacity * 2;

                /*Foi feito o uso de um ponteiro temporário.
                
                Porque o realloc pode:
                - manter o bloco no mesmo lugar ou mover o bloco para outro endereço.
                
                Se der o erro e retornar NULL, não se pode perder a antiga referência de 'events'
                
                Para isso faz:
                
                temp = realloc...
                e só depois
                events = temp
                
                Ter muito cuidado com o uso do realloc!!!*/
                SecurityEvent *temp = realloc(events, capacity *sizeof(SecurityEvent));

                if(temp == NULL){
                    printf("Problema de redimensionamento de memória!\n");
                    free(events);
                    fclose(file);
                    return 1;
                }
                // Só aqui susbtitui o ponteiro principal
                events = temp;
            }

            /*Guarda a struct válida na próxima posição livre do vetor.
            Isso é cópia de struct em C.*/

            events[valid_count] = event;
            valid_count++;
        } else{

            invalid_count++;
            
        }
    }

    fclose(file); // Desconecta e devolve o recurso ao sistema

    // Gera o arquivo final padronizado
    write_clean_file("data/security_events_cleaned.txt", events, valid_count);

    // Resumo finak pedido no pbl
    printf("\nTotal de linhas lidas: %d\n", total_lines);
    printf("Registros válidos: %d\n", valid_count);
    printf("Registros inválidos: %d\n", invalid_count);

    /* free liebra a memória dinâmica que foi usada pelo vetor*/

    free(events);

    /*boa prática: zerar o ponteiro depois do free, para evitar um uso posterior*/
    events = NULL;

    return 0;

}

