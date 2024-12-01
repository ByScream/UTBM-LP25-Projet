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

    // Chemin du fichier .backup_log
    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/.backup_log", backup_dir);

    // Vérifie si une sauvegarde précédente existe (log présent)
    int is_first_backup = (access(log_path, F_OK) != 0);

    // Ouvre ou crée le fichier .backup_log
    FILE *log_file = fopen(log_path, is_first_backup ? "w" : "a+");
    if (!log_file) {
        perror("Erreur lors de l'ouverture du fichier .backup_log");
        return;
    }

    // Liste les fichiers du répertoire source
    DIR *source = opendir(source_dir);
    if (!source) {
        perror("Erreur d'ouverture du répertoire source");
        fclose(log_file);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(source)) != NULL) {
        // Ignore les fichiers spéciaux "." et ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char source_path[PATH_MAX];
        char backup_path[PATH_MAX];
        snprintf(source_path, sizeof(source_path), "%s/%s", source_dir, entry->d_name);
        snprintf(backup_path, sizeof(backup_path), "%s/%s", new_backup_path, entry->d_name);

        struct stat file_stat;
        if (stat(source_path, &file_stat) != 0) {
            perror("Erreur lors de l'obtention des informations du fichier");
            continue;
        }

        // Si c'est un fichier, effectuer la sauvegarde avec déduplication
        if (S_ISREG(file_stat.st_mode)) {
            FILE *src_file = fopen(source_path, "rb");
            if (!src_file) {
                perror("Erreur lors de l'ouverture du fichier source");
                continue;
            }

            // Préparer les structures pour la déduplication
            Chunk chunks[MAX_CHUNKS];
            Md5Entry hash_table[HASH_TABLE_SIZE];

            // Effectuer la déduplication
            deduplicate_file(src_file, chunks, hash_table);

            // Écrire les chunks dédupliqués dans le fichier de sauvegarde
            write_backup_file(backup_path, chunks, MAX_CHUNKS);

            // Écrire les informations dans .backup_log
            fprintf(log_file, "%s;%ld;%s\n", backup_path, file_stat.st_mtime, chunks[0].md5); // /!\ Question de design ici : le hash de tout le fichier ? ou le hash de chaque chunk ? (-> créer une boucle)
            fclose(src_file);
        }

        // Si c'est un répertoire, le recréer dans la sauvegarde
        else if (S_ISDIR(file_stat.st_mode)) {
            mkdir(backup_path, 0755);
        }
    }

    closedir(source);
    fclose(log_file);
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
