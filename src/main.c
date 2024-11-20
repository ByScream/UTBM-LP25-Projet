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
        {.name="list-backups",.has_arg=0,.flag=0,.val='l'},
        {.name="dry-run",.has_arg=0,.flag=0,.val='d'},
        {.name="d-server",.has_arg=0,.flag=0,.val='1'},
        {.name="d-port",.has_arg=0,.flag=0,.val='2'},
        {.name="s-server",.has_arg=0,.flag=0,.val='3'},
        {.name="s-port",.has_arg=0,.flag=0,.val='4'},
        {.name="dest",.has_arg=0,.flag=0,.val='5'},
        {.name="source",.has_arg=0,.flag=0,.val='s'},
        {.name="verbose",.has_arg=0,.flag=0,.val='v'},
		{.name=0,.has_arg=0,.flag=0,.val=0}, // last element must be zero
	};
	while((opt = getopt_long(argc, argv, "v", my_opts, NULL)) != -1) {
		switch (opt) {
			case 'b':
				printf("--backup\n");
				break;
				
			case 'r':
				printf("--restore\n");
				break;
				
			case 'l':
				printf("--list-backups\nNe s'utilise pas avec les options --restore et --backup\n");
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
				printf("--dest\n");
				break;
            case 's':
				printf("--source\n");
				break;
            case 'v':
				printf("--verbose ou -v\n");
				break;
		}
	}
    return EXIT_SUCCESS;
}

