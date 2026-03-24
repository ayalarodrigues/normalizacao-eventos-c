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
    event -> event_id[0] = '\0';
    event -> device[0] = '\0';
    event -> severity[0] = '\0';
    event -> status[0] = '\0';
    event -> source[0] = '\0';
    event -> failed_logins = 0;
    event -> is_valid = 0;
}

// --- Função para limpar os espaços do texto ---

// remove espaços do começo e do fim

void trim_whitespace(char *text){
    char *start = text;
    while(*start && isspace((unsigned char)*start)){
        start++;
    }

    if (start != text){
        memmove(text, start, strlen(start) +1); 
        //memmove move o conteúdo da string para a esquerda
    }

    int len = (int)strlen(text);
    while(len > 0 && isspace((unsigned char) text[len -1])){
        text[len - 1] = '\0';
        len --;
    }
}


// --- Função para converter letras maiúsculas ---


void to_uppercase(char *text){
    while(*text){
        *text = (char)toupper((unsigned char)*text);
        text ++;
    }
}

// --- Função para normalizar severity

void normalize_severity(char *severity){
    trim_whitespace(severity);
    to_uppercase(severity);

    if (strcmp(severity, "MED")== 0){
        strcpy(severity, "MEDIUM");
    } else if (strcmp(severity, "CRIT")== 0){
        strcpy(severity, "CRITICAL");
    } else if(
        strcmp(severity, "LOW")!= 0 &&
        strcmp(severity, "MEDIUM")!= 0 &&
        strcmp(severity, "HIGH")!= 0 &&
        strcmp(severity, "CRITICAL")!=0
    ){
        severity[0] = '\0'; 
        // Zera quando for inválido, assim a validação final fica simples: campo vazio = inválido.
    }
}

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

int is_number(const char *text){
    if(*text == '\0'){
        return 0;
    }

    while(*text){
        if(!isdigit((unsigned char)*text)){
            return 0;
        }

        text++;
    }

    return 1;
}

int parse_delimited_line(char *line, SecurityEvent *event){
    for (int i = 0; line[i] != '\0'; i++){
        if(line[i] == ',' || line[i] == '|'){
            line[i] = ';';
        }
    }

    char *fields[10];
    int count = 0;

    char *token = strtok(line, ";");
    while(token != NULL && count < 10){
        trim_whitespace(token);
        fields[count++] = token;
        token = strtok(NULL, ";");
    }

    if(count != 6){
        return 0;
    }

    strcpy(event -> event_id, fields[0]);
    strcpy(event -> device, fields[1]);
    strcpy(event -> severity, fields[2]);
    strcpy(event -> status, fields[3]);

    if(is_number(fields[4])){
        event -> failed_logins = atoi(fields[4]);
    } else{
        event -> failed_logins = 0;
    }

    strcpy(event -> source, fields[5]);

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


int parse_key_value_line(char *line, SecurityEvent *event){
    char *fields[10];
    int count = 0;

    char *token = strtok(line, ";");
    while(token != NULL && count < 10){
        trim_whitespace(token);
        fields[count++] = token;
        token = strtok(NULL, ";");
    }

    for(int i = 0; i < count ; i++){
        char *equal = strchr(fields[i], '=');
        if(equal == NULL){
            continue;
        }

        *equal = '\0';

        char key[32];
        char value[128];

        strcpy(key, fields[i]);
        strcpy(value, equal +1);

        trim_whitespace(key);
        trim_whitespace(value);
        to_uppercase(key);

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


int main(void) {
    char line[] = "id=EVT-1014 ; device=ThinkCentre-M70s ; severity=critical ; status=analysis ; failed=9 ; source=soc_pipeline";
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
}

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

    /*
     //Abrir o arquivo e ler linha por linha
    FILE *file = fopen("data/raw_security_events.txt", "r");

    if(file == NULL){
        printf("Erro ao abrir o arquivo data/raw_security_events.txt\n");
        return 1;
    }

    char line[512];
    int total_lines = 0;

    while(fgets(line, sizeof(line), file) != NULL){
        total_lines ++;
        printf("Linha %d: %s", total_lines, line);   
    }

    fclose(file); // Desconecta e devolve o recurso ao sistema

    printf("\nTotal de linhas lidas: %d\n", total_lines);

    return 0;

    */

