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


    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/.backup_log", backup_dir);

    // Vérifie si une sauvegarde précédente existe (log présent)
    int is_first_backup = (access(log_path, F_OK) != 0);

    if(is_first_backup) { // si le fichier n'existe pas, on le crée
        FILE *log_file = fopen(log_path, "w");
        fclose(log_file);
    }

    log_t logs = read_backup_log(log_path);

    traiter_un_dossier(dir, new_backup_path, logs); // traite le dossier de façon récursive

    update_backup_log(log_path, &logs);
}


// Fonction implémentant la logique pour la sauvegarde d'un fichier
void backup_file(const char *filename_src, const char *filename_output) {
    FILE *file = fopen(filename_src, "rb");
    if (!file) {
        perror("Erreur d'ouverture du fichier source");
        return;
    }

    Chunk chunks[1000];  // Tableau pour stocker les chunks
    Md5Entry hash_table[HASH_TABLE_SIZE] = {0};  // Table de hachage des MD5

    // dédupliquer le fichier
    deduplicate_file(file, chunks, hash_table);
    
    int chunk_count = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        if (hash_table[i].index != 0) {
            chunk_count++;
        }
    }
    // on enregistre les chunks
    save_deduplicated_file(filename_output, file ,chunks, chunk_count);

    fclose(file);
}

void save_deduplicated_file(const char *filename_output, FILE *source, Chunk *chunks, int chunk_count) {
    FILE *output = fopen(filename_output, "wb");
    if (!output) {
        perror("Erreur lors de l'ouverture du fichier de sortie");
        return;
    }

    for (int i = 0; i < chunk_count; i++) {
        if (chunks[i].data != NULL) {
            size_t chunk_size = CHUNK_SIZE; // Taille par défaut du chunk

            // Si c'est le dernier chunk ou un chunk isolé, calculer la taille réelle
            if (i == chunk_count - 1 || chunks[i + 1].data == NULL) {
                fseek(source, 0, SEEK_END); // Aller à la fin du fichier source
                long file_size = ftell(source); // Taille totale du fichier
                rewind(source); // Revenir au début pour ne pas perturber le fichier source

                chunk_size = file_size % CHUNK_SIZE; // Taille restante du dernier chunk
                if (chunk_size == 0) {
                    chunk_size = CHUNK_SIZE; // Si divisible parfaitement, garder CHUNK_SIZE
                }
            }

            fwrite(&chunk_size, sizeof(size_t), 1, output); // Écrire la taille du chunk
            fwrite(chunks[i].data, 1, chunk_size, output); // Écrire les données du chunk
            fwrite(chunks[i].md5, 1, MD5_DIGEST_LENGTH, output); // Écrire le MD5
        }
    }

    fclose(output);
}

void undeduplicate_fileV2(FILE *file, Chunk **chunks, int *chunk_count) {
    /* @param: file est le fichier binaire contenant les chunks dédupliqués
     *         chunks est un pointeur vers un tableau de chunks à remplir
     *         chunk_count sera mis à jour avec le nombre total de chunks lus
     */

    size_t chunk_size;
    int index = 0;

    // Allouer de la mémoire pour les chunks (à ajuster selon vos besoins)
    *chunks = malloc(1000 * sizeof(Chunk)); // Suppose un maximum de 1000 chunks pour cet exemple
    if (!*chunks) {
        perror("Erreur d'allocation mémoire pour les chunks");
        return;
    }

    // Lire le fichier binaire chunk par chunk
    while (fread(&chunk_size, sizeof(size_t), 1, file) == 1) {
        // Allouer la mémoire pour stocker les données si chunk_size > 0
        (*chunks)[index].data = malloc(chunk_size);
        if (!(*chunks)[index].data) {
            perror("Erreur d'allocation mémoire pour un chunk");
            break;
        }

        // Lire les données du chunk
        fread((*chunks)[index].data, 1, chunk_size, file);

        // Lire le MD5
        fread((*chunks)[index].md5, 1, MD5_DIGEST_LENGTH, file);

        index++;
    }

    // Mettre à jour le compteur de chunks
    *chunk_count = index;
}

void restore_file(const char *deduplicated_filename, const char *output_filename) {
    FILE *deduplicated_file = fopen(deduplicated_filename, "rb");
    if (!deduplicated_file) {
        perror("Erreur d'ouverture du fichier dédupliqué");
        return;
    }

    // Variables pour stocker les chunks et le compteur
    Chunk *chunks = NULL;
    int chunk_count = 0;

    // Lire les chunks depuis le fichier dédupliqué
    undeduplicate_fileV2(deduplicated_file, &chunks, &chunk_count);
    fclose(deduplicated_file);

    if (chunks == NULL || chunk_count == 0) {
        fprintf(stderr, "Aucun chunk trouvé dans le fichier dédupliqué\n");
        return;
    }

    // Ouvrir le fichier de sortie pour y écrire le contenu restauré
    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        perror("Erreur d'ouverture du fichier de sortie");
        free(chunks);
        return;
    }

    // Restaurer le fichier en parcourant les chunks
    for (int i = 0; i < chunk_count; i++) {
        if (chunks[i].data != NULL) {
            // Écrire les données du chunk unique
            fwrite(chunks[i].data, 1, CHUNK_SIZE, output_file);
        } else {
            // Chunk est un doublon, rechercher les données correspondantes
            for (int j = 0; j < chunk_count; j++) {
                if (memcmp(chunks[i].md5, chunks[j].md5, MD5_DIGEST_LENGTH) == 0 && chunks[j].data != NULL) {
                    fwrite(chunks[j].data, 1, CHUNK_SIZE, output_file);
                    break;
                }
            }
        }
    }

    // Libérer la mémoire des chunks
    for (int i = 0; i < chunk_count; i++) {
        free(chunks[i].data);
    }
    free(chunks);

    fclose(output_file);

    printf("Fichier restauré avec succès dans : %s\n", output_filename);
}

int calculate_file_md5(const char *src_path, char *md5) {
    if (!src_path || !md5) {
        return -1; // Paramètres invalides
    }

    FILE *file = fopen(src_path, "rb");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier");
        return -1;
    }

    MD5_CTX md5_ctx;
    unsigned char buffer[4096];
    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    size_t bytes_read;

    MD5_Init(&md5_ctx);

    // Lire le fichier par morceaux et mettre à jour le contexte MD5
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        MD5_Update(&md5_ctx, buffer, bytes_read);
    }

    if (ferror(file)) {
        perror("Erreur lors de la lecture du fichier");
        fclose(file);
        return -1;
    }

    fclose(file);

    // Finaliser le calcul du MD5
    MD5_Final(md5_hash, &md5_ctx);

    // Convertir le hash en chaîne hexadécimale
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&md5[i * 2], "%02x", md5_hash[i]);
    }

    md5[32] = '\0'; // Assurer la terminaison de la chaîne
    return 0;
}

// Fonction pour ajouter un élément à une liste log_t
void add_log_element(log_t *logs, const char *path, const unsigned char *md5, const char *date) {
    if (!logs || !path || !md5 || !date) {
        fprintf(stderr, "Erreur : paramètres invalides dans add_log_element.\n");
        return;
    }

    // Allouer un nouvel élément
    log_element *new_element = malloc(sizeof(log_element));
    if (!new_element) {
        perror("Erreur d'allocation mémoire pour log_element");
        return;
    }

    // Initialiser les champs
    new_element->path = strdup(path); // Copier le chemin
    if (!new_element->path) {
        perror("Erreur d'allocation mémoire pour path");
        free(new_element);
        return;
    }
    memcpy(new_element->md5, md5, MD5_DIGEST_LENGTH); // Copier le MD5
    new_element->date = strdup(date); // Copier la date
    if (!new_element->date) {
        perror("Erreur d'allocation mémoire pour date");
        free(new_element->path);
        free(new_element);
        return;
    }
    new_element->next = NULL;
    new_element->prev = logs->tail; // Connecter au dernier élément existant

    // Ajouter le nouvel élément à la liste
    if (logs->tail) {
        logs->tail->next = new_element; // Relier l'ancien dernier élément au nouveau
    } else {
        logs->head = new_element; // Si la liste était vide, définir le head
    }
    logs->tail = new_element; // Mettre à jour la queue
}

int create_directories(const char *path) {
    char temp[PATH_MAX];
    strncpy(temp, path, sizeof(temp));
    temp[sizeof(temp) - 1] = '\0';

    // Parcourir le chemin et créer chaque répertoire
    for (char *p = temp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0'; // Temporarily terminate string
            if (mkdir(temp, 0755) && errno != EEXIST) {
                perror("Erreur lors de la création du répertoire");
                return -1;
            }
            *p = '/'; // Restore the slash
        }
    }

    // Créer le répertoire final si ce n'était pas déjà fait
    if (mkdir(temp, 0755) && errno != EEXIST) {
        perror("Erreur lors de la création du répertoire final");
        return -1;
    }

    return 0;
}

void traiter_un_dossier(const char *source_dir, const char *backup_dir, log_t *logs)
{
    DIR *dir = opendir(source_dir);
    if (!dir) {
        perror("Erreur lors de l'ouverture du répertoire source (%s)", source_dir);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) { // on parcours tout ce qu'il y a dans le directory

        if (entry->d_name[0] == '.') continue; // on ignore les fichiers en ".*"

        if (entry->d_type == DT_DIR) { // Si l'entrée est un dossier
            // Construire le chemin du sous-dossier
            char subdir_path[PATH_MAX];
            snprintf(subdir_path, sizeof(subdir_path), "%s/%s", source_dir, entry->d_name);

            char dest_path[PATH_MAX];
            snprintf(dest_path, sizeof(dest_path), "%s/%s", backup_dir, entry->d_name);

            // Ignorer les dossiers spéciaux "." et ".."
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

            // Appeler récursivement la fonction sur le sous-dossier
            traiter_un_dossier(subdir_path, dest_path, logs);
        }

        // on traire les fichiers

        char src_path[PATH_MAX];
        snprintf(src_path, sizeof(src_path), "%s/%s", source_dir, entry->d_name);

        char dest_path[PATH_MAX];
        snprintf(dest_path, sizeof(dest_path), "%s/%s", backup_dir, entry->d_name);

        struct stat file_stat;
        if (stat(src_path, &file_stat) != 0) {
            perror("Erreur lors de la récupération des informations du fichier");
            continue;
        }

        // Vérifier si une sauvegarde est nécessaire
        unsigned char md5[MD5_DIGEST_LENGTH];
        if(calculate_file_md5(src_path, md5) == -1)
        {
            printf("erreur calcul md5 fichier %s", src_path);
            return;
        }

        log_element *existing_log = NULL;
        for (log_element *cur = logs.head; cur; cur = cur->next) {
            if (memcmp(cur->md5, md5, MD5_DIGEST_LENGTH) == 0) {
                existing_log = cur;
                break;
            }
        }

        if (!existing_log) { // si c'est un nouveau fichier ou un fichier modifié
            create_directories(dest_path); // on créé les dossiers nécessaires
            backup_file(src_path, dest_path); // Sauvegarde le fichier
        }

        // Ajouter le fichier au log
        add_log_element(logs, dest_path, md5, file_stat.st_mtime);
    }
    closedir(dir);
}


/*
(pour tester l'enregistrement d'un fichier dédupliqué)
utiliser restore_file("blalba.txt", "fichier_original.txt"); pour vérifier si c'est bon

int main() {
    backup_file("test.txt", "blalba.txt");

    return 0;
}

*/