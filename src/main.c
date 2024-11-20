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

    /*--backup : crée une nouvelle sauvegarde du répertoire source, localement ou sur le serveur distant. Ne s'utilise pas avec les options --restore et --list-backups
--restore : restaure une sauvegarde à partir du chemin, localement ou depuis le serveur. Ne s'utilise pas avec les options --backup et --list-backups
--list-backups : liste toutes les sauvegardes existantes, localement ou sur le serveur. Ne s'utilise pas avec les options --restore et --backup
--dry-run : test une sauvegarde ou une restauration sans effectuer de réelles copies
--d-server : spécifie l'adresse IP du serveur à utiliser comme destination
--d-port : spécifie le port du serveur de destination
--s-server : spécifie l'adresse IP du serveur à utiliser comme source
--s-port : spécifie le port du serveur source
--dest : spécifie le chemin de destination de la sauvegarde ou de la restauration
--source : spécifie le chemin source de la sauvegarde ou de la restauration
--verbose ou v : affiche plus d'informations sur l'exécution du programme*/
	int opt = 0;
	struct option my_opts[] = {
		{.name="--backup",.has_arg=0,.flag=0,.val='b'},
		{.name="--restore",.has_arg=1,.flag=0,.val='a'},
		{.name="--binary",.has_arg=2,.flag=0,.val='bi'},
		{.name=0,.has_arg=0,.flag=0,.val=0}, // last element must be zero
	};
	while((opt = getopt_long(argc, argv, "", my_opts, NULL)) != -1) {
		switch (opt) {
			case 'b':
				printf("Backup");
				break;
				
			case 'a':
				printf("restore");
				break;
				
			case 'bi':
				printf("binary");
				break;
		}
	}
    return EXIT_SUCCESS;
}

