#include <stdio.h>
#include <stdlib.h>
#include "file_handler.h"
#include "deduplication.h"
#include "backup_manager.h"
#include "network.h"
#include <getopt.h>

int main(int argc, char *argv[]) {
    // Analyse des arguments de la ligne de commande

    // Implémentation de la logique de sauvegarde et restauration
    // Exemples : gestion des options --backup, --restore, etc.

	int opt = 0;
	struct option my_opts[] = {
		{.name="backup",.has_arg=0,.flag=0,.val='b'},
		{.name="restore",.has_arg=0,.flag=0,.val='r'},
        {.name="list-backups",.has_arg=1,.flag=0,.val='l'},
        {.name="dry-run",.has_arg=0,.flag=0,.val='d'},
        {.name="d-server",.has_arg=0,.flag=0,.val='1'},
        {.name="d-port",.has_arg=0,.flag=0,.val='2'},
        {.name="s-server",.has_arg=0,.flag=0,.val='3'},
        {.name="s-port",.has_arg=0,.flag=0,.val='4'},
        {.name="dest",.has_arg=1,.flag=0,.val='5'},
        {.name="source",.has_arg=1,.flag=0,.val='s'},
        {.name="verbose",.has_arg=0,.flag=0,.val='v'},
		{.name=0,.has_arg=0,.flag=0,.val=0}, // last element must be zero
	};
	char dest[256] = "";
	char source[256] = "";
	char list_backups_char[256] = "";
    int backup = 0, restore = 0, verbose = 0, list_backups_use = 0;
	while((opt = getopt_long(argc, argv, "v", my_opts, NULL)) != -1) {
		switch (opt) {
			case 'b':
				printf("--backup\n");
                backup = 1;
				break;
				
			case 'r':
				printf("--restore\n");
                restore = 1;
				break;
				
			case 'l':
                if (optarg) {
                    strncpy(list_backups_char, optarg, sizeof(list_backups_char) - 1);
                } else {
                    fprintf(stderr, "Erreur : --list-backups nécessite un argument.\n");
                    exit(EXIT_FAILURE);
                }
				break;
            case 'd':
				printf("--dry-run\n");
				break;
            case '1':
				printf("--d-server\n");
				break;
            case '2':
				printf("--d-port\n");
				break;
            case '3':
				printf("--s-server\n");
				break;
            case '4':
				printf("--s-port\n");
				break;
            case '5':
				if (optarg) {
                    strncpy(dest, optarg, sizeof(dest) - 1);
                } else {
                    fprintf(stderr, "Erreur : --dest nécessite un argument.\n");
                    exit(EXIT_FAILURE);
                }
				break;
            case 's':
				if (optarg) {
                    strncpy(source, optarg, sizeof(source) - 1);
                } else {
                    fprintf(stderr, "Erreur : --source nécessite un argument.\n");
                    exit(EXIT_FAILURE);
                }
				break;
            case 'v':
				printf("Mode verbose activé !\n");
				verbose = 1;
				break;
		}
	}
    if (((backup == 1) && (restore == 1 || list_backups_use == 1)) || ((restore == 1) && (backup == 1 || list_backups_use == 1)) || ((list_backups_use == 1) && (restore == 1 || backup == 1))) {
        perror("Vous devez n'avoir que l'un de ces 3 paramètres suivants: --backup, --restore, --list_backups.\nS'il y en a au moins deux, la commande est mal utilisée !\n");
        return EXIT_FAILURE;
    } else {
		if (backup) {
			if (strlen(source) == 0) {
				fprintf(stderr, "Erreur : vous devez définir l'argument --source !\n");
                exit(EXIT_FAILURE);
			} else if (strlen(dest) == 0) {
				fprintf(stderr, "Erreur : vous devez définir l'argument --dest !\n");
                exit(EXIT_FAILURE);
			} else {
				create_backup(source,dest,verbose);
			}
		} else if (restore) {
			if (strlen(source) == 0) {
				fprintf(stderr, "Erreur : vous devez définir l'argument --source !\n");
                exit(EXIT_FAILURE);
			} else if (strlen(dest) == 0) {
				fprintf(stderr, "Erreur : vous devez définir l'argument --dest !\n");
                exit(EXIT_FAILURE);
			} else {
				restore_backup(source, dest);
			}
		} else if (list_backups_use) {
			list_backups(list_backups_char);
		}
        return EXIT_SUCCESS;
    }
    
}

