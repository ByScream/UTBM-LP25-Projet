#include "backup_manager.h"
#include "deduplication.h"
#include "file_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>

#include <unistd.h>

// Fonction pour créer une nouvelle sauvegarde complète puis incrémentale
void create_backup(const char *source_dir, const char *backup_dir) {
    /* @param: source_dir est le chemin vers le répertoire à sauvegarder
    *          backup_dir est le chemin vers le répertoire de sauvegarde
    */

   
    // Vérifie si les répertoires source et de sauvegarde existent
    if (access(source_dir, F_OK) != 0) {
        fprintf(stderr, "Le répertoire source n'existe pas : %s\n", source_dir);
        return;
    }
    if (access(backup_dir, F_OK) != 0) {
        fprintf(stderr, "Le répertoire de sauvegarde n'existe pas : %s\n", backup_dir);
        return;
    }

    // Génération du nom du répertoire de sauvegarde avec timestamp
    char timestamp[32];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *local_time = localtime(&tv.tv_sec);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d-%H:%M:%S", local_time);

    char new_backup_path[PATH_MAX];
    snprintf(new_backup_path, sizeof(new_backup_path), "%s/%s", backup_dir, timestamp);

    // Création du répertoire de sauvegarde
    if (mkdir(new_backup_path, 0755) != 0) {
        perror("Erreur lors de la création du répertoire de sauvegarde");
        return;
    }


    // ---------------------------------------------------------


    DIR *dir = opendir(source_dir);
    if (!dir) {
        perror("Erreur lors de l'ouverture du répertoire source");
        return;
    }

    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/.backup_log", backup_dir);

    // Vérifie si une sauvegarde précédente existe (log présent)
    int is_first_backup = (access(log_path, F_OK) != 0);

    if(is_first_backup) { // si le fichier n'existe pas, on le crée
        FILE *log_file = fopen(log_path, "w");
        fclose(log_file);
    }

    log_t logs = read_backup_log(log_path);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) { // on parcours tout ce qu'il y a dans le directory
        if (entry->d_name[0] == '.') continue; // on ignore les fichiers en ".*"

        char src_path[PATH_MAX];
        snprintf(src_path, sizeof(src_path), "%s/%s", source_dir, entry->d_name);

        struct stat file_stat;
        if (stat(src_path, &file_stat) != 0) {
            perror("Erreur lors de la récupération des informations du fichier");
            continue;
        }

        // Vérifier si une sauvegarde est nécessaire
        unsigned char md5[MD5_DIGEST_LENGTH];
        calculate_file_md5(src_path, md5);

        log_element *existing_log = NULL;
        for (log_element *cur = logs.head; cur; cur = cur->next) {
            if (strcmp(cur->path, src_path) == 0 && memcmp(cur->md5, md5, MD5_DIGEST_LENGTH) == 0) {
                existing_log = cur;
                break;
            }
        }

        if (!existing_log) {
            // Sauvegarde le fichier
            backup_file(src_path);

            char dest_path[PATH_MAX];
            snprintf(dest_path, sizeof(dest_path), "%s/%s.dat", backup_dir, entry->d_name);

            Chunk chunks[MAX_CHUNK];
            Md5Entry hash_table[HASH_TABLE_SIZE];
            deduplicate_file(fopen(src_path, "rb"), chunks, hash_table);

            // VERIFIER ce que fait vraiment cette fonction : write_backup_file(dest_path, chunks, MAX_CHUNK);

            // Ajouter le nouveau fichier au log
            log_element *new_log = malloc(sizeof(log_element));
            new_log->path = strdup(src_path);
            memcpy(new_log->md5, md5, MD5_DIGEST_LENGTH);
            asprintf(&new_log->date, "%ld", file_stat.st_mtime);
            new_log->next = NULL;
            new_log->prev = logs.tail;
            if (logs.tail) logs.tail->next = new_log;
            else logs.head = new_log;
            logs.tail = new_log;
        }
    }

    update_backup_log(log_path, &logs);
    closedir(dir);
}

// Fonction permettant d'enregistrer dans fichier le tableau de chunk dédupliqué
void write_backup_file(const char *output_filename, Chunk *chunks, int chunk_count) {
    // 1. Ouvrir le fichier en mode écriture
    FILE *file = fopen(output_filename, "w");
    if (!file) {
        fprintf(stderr, "Erreur : Impossible d'ouvrir le fichier %s\n", output_filename);
        return;
    }

    // 2. Parcourir chaque chunk
    for (int i = 0; i < chunk_count; i++) {
        // 3. Écrire le MD5 du chunk
        fprintf(file, "MD5:");
        for (int j = 0; j < MD5_DIGEST_LENGTH; j++) {
            fprintf(file, "%02x", chunks[i].md5[j]);
        }

        // 4. Écrire la taille des données
        fprintf(file, ";size:%ld", chunks[i].data ? CHUNK_SIZE : 0);

        // 5. Écrire les données si elles existent
        fprintf(file, ";data:");
        if (chunks[i].data) {
            for (size_t j = 0; j < CHUNK_SIZE; j++) {
                fprintf(file, "%02x", ((unsigned char *)chunks[i].data)[j]);
            }
        } else {
            fprintf(file, "NULL");
        }

        fprintf(file, "\n"); // Passer à la ligne suivante
    }

    // 6. Fermer le fichier
    fclose(file);
}


// Fonction implémentant la logique pour la sauvegarde d'un fichier
void backup_file(const char *filename) {
    /*
    */
}


// Fonction permettant la restauration du fichier backup via le tableau de chunk
void write_restored_file(const char *output_filename, Chunk *chunks, int chunk_count) {
    /*
    */
}

// Fonction pour restaurer une sauvegarde
void restore_backup(const char *backup_id, const char *restore_dir) {
    /* @param: backup_id est le chemin vers le répertoire de la sauvegarde que l'on veut restaurer
    *          restore_dir est le répertoire de destination de la restauration
    */
}
