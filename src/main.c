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



int main(void) {

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

    /*
     //Abrir o arquivo e ler linha por linha
    FILE *file = fopen("data/raw_security_events.txt", "r");

    if(file == NULL){
        printf("Não foi possível abrir data/raw_security_events.txt\n");
        return 1;
    }

    char line[512];
    int total_lines = 0;

    while(fgets(line, sizeof(line), file) != NULL){
        total_lines ++;
        printf("Linha %d: %s", total_lines, line);   
    }

    fclose(file);

    printf("\nTotal de linhas lidas: %d\n", total_lines);

    return 0;

    */

}