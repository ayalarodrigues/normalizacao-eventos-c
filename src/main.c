#include <stdio.h>
#include <stdlib.h>

typedef struct{
    char event_id[32];
    char device[64];
    char severity[16];
    char status[20];
    int failed_logins;
    char source[32];
    int is_valid;
} SecurityEvent;


int main(void) {
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
}