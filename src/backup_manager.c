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
#include <errno.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <regex.h>

void get_base_path(const char *full_path, char *base_path) {
    // Trouver le dernier slash
    const char *last_slash = strrchr(full_path, '/');

    if (last_slash != NULL) {
        // Calculer la longueur jusqu'au dernier slash
        size_t base_length = last_slash - full_path + 1;

        // Copier la partie avant le dernier slash
        strncpy(base_path, full_path, base_length);
        base_path[base_length] = '\0'; // Terminer avec un '\0'
    } else {
        // Si aucun slash trouvé, retourner une chaîne vide
        base_path[0] = '\0';
    }
}


// Fonction pour restaurer une backup dans un dossier. Exemple : restore_backup("blabl/truc/2024-12-10-12:30:00.000", "bidule/ma_restauration/");
void restore_backup(const char *backup_dir, const char *restore_dir, const int verbose) {
    if (!directory_exists(backup_dir)) { // Vérifier l'existence de backup_dir
        fprintf(stderr, "Erreur : Le dossier de sauvegarde '%s' n'existe pas.\n", backup_dir);
        return;
    }

    if (!directory_exists(restore_dir)) { // Vérifier l'existence de restore_dir
        fprintf(stderr, "Erreur : Le dossier de restauration '%s' n'existe pas.\n", restore_dir);
        return;
    }

    // Construire le chemin vers .backup_log (situé dans le dossier parent de backup_dir)
    char backup_log_path[PATH_MAX];
    const char *slash = strrchr(backup_dir, '/'); // Localiser le dernier '/'
    if (slash) {
        size_t parent_dir_len = slash - backup_dir; // Longueur du chemin sans le dernier élément
        snprintf(backup_log_path, sizeof(backup_log_path), "%.*s/.backup_log", (int)parent_dir_len, backup_dir);
    } else {
        // Si aucun '/' n'est trouvé, assume que backup_dir est au niveau courant
        snprintf(backup_log_path, sizeof(backup_log_path), ".backup_log");
    }

    // Vérifier l'existence du fichier .backup_log
    if (!file_exists(backup_log_path)) {
        fprintf(stderr, "Erreur : Le fichier de log '%s' n'existe pas.\n", backup_log_path);
        return;
    }

    if (verbose) {
        printf("Prêt à restaurer depuis '%s' vers '%s'.\n", backup_dir, restore_dir);
        printf("Chemin d'acces vers .backup_log : %s\n", backup_log_path);
    }
    

    char date[24];
    get_backup_date(backup_dir, date, sizeof(date));
    log_t logs = read_backup_log(backup_log_path);

    if (verbose) {
        printf("On souhaite restaurer la date : <%s>\n", date);
    }
    

    char prefix[50];


    for (log_element *cur = logs.head; cur; cur = cur->next) {

        extract_prefix(cur->path, prefix);
        if (verbose) {
            printf("Entree : %s", prefix);
            printf(" <=> %s\n", date);
        }
        

        if (memcmp(prefix, date, sizeof(date)) == 0) {
            // Il faut restaurer le fichier correspondant
            if (verbose) {
                printf("Une entree trouvee\n");
            }
            
            traiter_restauration_fichier(cur, restore_dir, logs, backup_dir, verbose);
        }
    }
}

void traiter_restauration_fichier(log_element *cur, const char *restore_dir, log_t logs, const char *backup_dir, const int verbose) {
    char src_path[PATH_MAX];
    strncpy(src_path, cur->path, sizeof(src_path));
    src_path[sizeof(src_path) - 1] = '\0'; // Sécurisation de la chaîne

    // Si le fichier n'existe pas, trouver le chemin le plus ancien correspondant
    if (!file_exists(cur->path)) {
        const char *result = find_oldest_backup(logs, cur->path, cur->md5, verbose);
        if (result) {
            strncpy(src_path, result, sizeof(src_path));
            src_path[sizeof(src_path) - 1] = '\0'; // Sécurisation de la chaîne
        } else {
            fprintf(stderr, "Erreur : aucun fichier de sauvegarde trouvé pour %s\n", cur->path);
            return; // Abandonner si aucun fichier correspondant n'est trouvé
        }
    }

    // S'assurer que restore_dir se termine par un '/'
    char adjusted_restore_dir[PATH_MAX];
    snprintf(adjusted_restore_dir, sizeof(adjusted_restore_dir), "%s%s", 
             restore_dir, 
             (restore_dir[strlen(restore_dir) - 1] == '/') ? "" : "/");

    // Construire le chemin du fichier restauré en combinant restore_dir et cur->path
    char output_path[PATH_MAX];
    snprintf(output_path, sizeof(output_path), "%s%s", adjusted_restore_dir, cur->path);

    // Créer les répertoires nécessaires pour le chemin de destination
    create_directories(output_path);

    // Restaurer le fichier
    char base_path[PATH_MAX];
    char full_path[PATH_MAX];

    get_base_path(backup_dir, base_path);
    assemble_path(base_path, src_path, full_path);

    restore_file(full_path, output_path, verbose);
}

// Fonction principale pour trouver un fichier spécifique (date antérieure et md5 identique), avec l'entrée la plus ancienne respectant les critères
const char *find_oldest_backup(log_t logs, const char *file_path, const unsigned char *target_md5, const int verbose) {
    const char *oldest_path = NULL;
    const char *oldest_date = NULL;

    for (log_element *cur = logs.head; cur; cur = cur->next) {

        char prefix_cur[PATH_MAX];
        remove_prefix_by_datetime_removing_date(cur->path, prefix_cur);

        char prefix_file_path[PATH_MAX];
        remove_prefix_by_datetime_removing_date(file_path, prefix_file_path);

        // Vérifier le chemin d'accès
        if (verbose) {
            printf("On compare : [%s] et [%s]\n", prefix_cur, prefix_file_path);
        }
        if (strcmp(prefix_cur, prefix_file_path) == 0) {

            if (verbose) {
                printf("\tles chemins correspondent !\n");
            }
           
            // Vérifier que la date est antérieure à la date cible


            char prefix_date[50];
            extract_prefix(cur->path, prefix_date);

            char prefix_date_file_path[50];
            extract_prefix(file_path, prefix_date_file_path);

            if (verbose) {
                printf("\tOn compare : [%s] et [%s]\n", prefix_date, prefix_date_file_path);
            }
            

            if (compare_dates(prefix_date, prefix_date_file_path) < 0) {
                if (verbose) {
                    printf("\t\tles dates sont bonnes!\n");
                }
                
                // Vérifier que les MD5 correspondent
                if (compare_md5(cur->md5, target_md5)) {
                    // Si aucun fichier n'est encore sélectionné ou si la date actuelle est plus ancienne
                    if (!oldest_date || compare_dates(cur->date, oldest_date) < 0) {
                        oldest_date = cur->date;
                        oldest_path = cur->path;
                    }
                }
            }
        }
    }

    return oldest_path; // Retourne le chemin du fichier le plus ancien trouvé ou NULL si aucun ne correspond
}

void create_backup(const char *source_dir, const char *backup_dir, const int verbose) {
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

    if (verbose) {
        printf("chemin : %s\n", new_backup_path);
    }
    

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

    traiter_un_dossier(source_dir, new_backup_path, &logs, verbose); // traite le dossier de façon récursive

    update_backup_log(log_path, &logs);
}

// Fonction implémentant la logique pour la sauvegarde d'un fichier
void backup_file(const char *filename_src, const char *filename_output, const int verbose) {
    if (verbose) {
        printf("entree dans le backup_file\n");
    }
    
    FILE *file = fopen(filename_src, "rb");
    if (!file) {
        perror("Erreur d'ouverture du fichier source");
        return;
    }


    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if ((file_size / CHUNK_SIZE) > 1000) {
        fprintf(stderr, "Erreur : le fichier est trop grand pour le tableau de chunks.\n");
        fclose(file);
        return;
    }

    if (verbose) {
        printf("On déduplique le fichier\n");
    }
   
    Md5Entry hash_table[HASH_TABLE_SIZE];  // Table de hachage des MD5

    // dédupliquer le fichier
    int chunk_count = 0;
    Chunk *chunks = deduplicate_file(file, hash_table, &chunk_count, verbose);

    if (verbose ){
        printf("Dans le backup_file\n");
        print_hash_table(hash_table);

        printf("\nIl y a %d Chunks\n",chunk_count);
        print_chunk_content(chunks, chunk_count, hash_table);
    }
    

    // on enregistre les chunks
    save_deduplicated_file(filename_output, file ,chunks, chunk_count, verbose);

    fclose(file);
    free(chunks);
}

void save_deduplicated_file(const char *filename_output, FILE *source, Chunk *chunks, int chunk_count, const int verbose) {

    if (verbose) {
        printf("Entree dans save_deduplicated_file\n");
    }

    FILE *output = fopen(filename_output, "wb");
    if (!output) {
        perror("Erreur lors de l'ouverture du fichier de sortie");
        return;
    }

    for (int i = 0; i < chunk_count; i++) {
        if (verbose) {
            printf("\tBoucle for : i=%d\n", i);
        }
        
        if (chunks[i].data != NULL) {
            // Sauvegarde des chunks uniques
            size_t chunk_size = CHUNK_SIZE; // Taille par défaut du chunk

            // Si c'est le dernier chunk [ou un chunk isolé, calculer la taille réelle   if (i == chunk_count - 1 || (i + 1 < chunk_count && chunks[i + 1].data == NULL))]
            if (i == chunk_count - 1) {
                if (verbose) {
                    printf("calcul de la taille reelle du chunk : ");
                }
                
                fseek(source, 0, SEEK_END); // Aller à la fin du fichier source
                long file_size = ftell(source); // Taille totale du fichier
                rewind(source); // Revenir au début pour ne pas perturber le fichier source

                chunk_size = file_size % CHUNK_SIZE; // Taille restante du dernier chunk
                if (chunk_size == 0) {
                    chunk_size = CHUNK_SIZE; // Si divisible parfaitement, garder CHUNK_SIZE
                }

                // affichage du chunk concerné
                if (chunks[i].data != NULL) {
                    // Supposer que les données sont des octets, afficher en hexadécimal
                    for (int j = 0; j < CHUNK_SIZE; j++) {
                        // Afficher les octets de données, et stopper dès qu'on atteint la fin des données du chunk
                        if (j < CHUNK_SIZE && ((unsigned char*)chunks[i].data)[j] != '\0') {
                            if (verbose) {
                                printf("%02x ", ((unsigned char*)chunks[i].data)[j]);
                            }
                        } else {
                            break;
                        }
                    }
                } else {
                    if (verbose) {
                        printf("[NULL]");
                    } 
                }


                if (verbose) {
                    printf(" | taille <%ld>\n", chunk_size);
                }
                
            }

            // CE N'EST PLUS UN PROBLEME : au niveau de l'écriture : tout le bloc n'est pas enregistré

            // fwrite(buffer, blocSize, Nombre de bloc, stream);
            fwrite(&chunk_size, sizeof(size_t), 1, output); // Écrire la taille du chunk
            fwrite(chunks[i].data, 1, chunk_size, output); // Écrire les données du chunk
            fwrite(chunks[i].md5, 1, MD5_DIGEST_LENGTH, output); // Écrire le MD5
        } else {
            // Sauvegarde des chunks référencés
            int referenced_index = -1;

            // Rechercher dans la table de hachage l'index référencé
            for (int j = 0; j < chunk_count; j++) {
                if (memcmp(chunks[j].md5, chunks[i].md5, MD5_DIGEST_LENGTH) == 0) {
                    referenced_index = j;
                    break;
                }
            }

            if (referenced_index == -1) {
                fprintf(stderr, "Erreur : Chunk référencé non trouvé (chunk %d).\n", i);
                fclose(output);
                return;
            }

            // Écrire une référence au chunk référencé
            size_t ref_marker = 0; // Marqueur pour indiquer une référence
            fwrite(&ref_marker, sizeof(size_t), 1, output); // Indique qu'il s'agit d'une référence
            fwrite(&referenced_index, sizeof(int), 1, output); // Écrire l'index du chunk référencé
            fwrite(chunks[i].md5, 1, MD5_DIGEST_LENGTH, output); // Écrire le MD5 du chunk référencé
        }
    }

    fclose(output);
}

void undeduplicate_fileV2(FILE *file, Chunk **chunks, int *chunk_count, const int verbose) {
    size_t chunk_size;
    int index = 0;

    //chunk_size = CHUNK_SIZE;

    // Allouer de la mémoire pour les chunks (1000 chunks maximum)
    *chunks = calloc(INITIAL_CHUNK_CAPACITY, sizeof(Chunk));
    //*chunks = malloc(INITIAL_CHUNK_CAPACITY * sizeof(Chunk)); 
    if (!*chunks) {
        perror("Erreur d'allocation mémoire pour les chunks");
        return;
    }

    // Lire le fichier binaire chunk par chunk
    while (fread(&chunk_size, sizeof(size_t), 1, file) == 1) {
        if (chunk_size == 0) {
            // Cas d'un chunk référencé
            int referenced_index;
            unsigned char md5_reference[MD5_DIGEST_LENGTH];

            // Lire l'index du chunk référencé
            if (fread(&referenced_index, sizeof(int), 1, file) != 1) {
                perror("Erreur de lecture de l'index du chunk référencé");
                break;
            }

            // Lire le MD5 du chunk référencé
            if (fread(md5_reference, 1, MD5_DIGEST_LENGTH, file) != MD5_DIGEST_LENGTH) {
                perror("Erreur de lecture du MD5 du chunk référencé");
                break;
            }

            // Ajouter le chunk référencé à la liste
            (*chunks)[index].data = NULL; // Pas de données propres, c'est une référence
            memcpy((*chunks)[index].md5, md5_reference, MD5_DIGEST_LENGTH);

            if (verbose) {
                printf("Chunk %d: référence au chunk %d avec MD5 ", index, referenced_index);
                print_md5(md5_reference);
            }
            
        } else {
            // Cas d'un chunk unique

            // Allouer la mémoire pour le chunk
            (*chunks)[index].data = calloc(chunk_size, 1);
            //(*chunks)[index].data = malloc(chunk_size);
            if (!(*chunks)[index].data) {
                perror("Erreur d'allocation mémoire pour un chunk");
                break;
            }

            // Lire les données du chunk
            size_t bytes_read = fread((*chunks)[index].data, 1, chunk_size, file);
            if (bytes_read != chunk_size) {
                perror("Erreur de lecture des données du chunk");
                break;
            }

            // Lire le MD5
            if (fread((*chunks)[index].md5, 1, MD5_DIGEST_LENGTH, file) != MD5_DIGEST_LENGTH) {
                perror("Erreur de lecture du MD5");
                break;
            }
            
            if (verbose) {
                printf("Chunk %d: taille %zu, données ", index, chunk_size);
                for (size_t i = 0; i < chunk_size; i++) {
                    printf("%02x ", ((unsigned char*)(*chunks)[index].data)[i]);
                }
                printf("\nMD5 : ");
                print_md5((*chunks)[index].md5);
            }
            
        }
        index++;
    }

    *chunk_count = index;  // Mettre à jour le compteur de chunks
}

void restore_file(const char *deduplicated_filename, const char *output_filename, const int verbose) {
    FILE *deduplicated_file = fopen(deduplicated_filename, "rb");
    if (!deduplicated_file) {
        perror("Erreur d'ouverture du fichier dédupliqué");
        return;
    }

    // Variables pour stocker les chunks et le compteur
    Chunk *chunks = NULL;
    int chunk_count = 0;

    // Lire les chunks depuis le fichier dédupliqué
    undeduplicate_fileV2(deduplicated_file, &chunks, &chunk_count, verbose);
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

    if (verbose) {
        printf("Fichier restauré avec succès dans : %s\n", output_filename);
    }

}

int calculate_file_md5(const char *src_path, unsigned char *md5_hash) {
    if (!src_path || !md5_hash) {
        return -1; // Paramètres invalides
    }

    FILE *file = fopen(src_path, "rb");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier");
        return -1;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Erreur lors de l'initialisation du contexte MD5\n");
        fclose(file);
        return -1;
    }

    const EVP_MD *md = EVP_md5();
    EVP_DigestInit_ex(mdctx, md, NULL);

    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }

    EVP_DigestFinal_ex(mdctx, md5_hash, NULL);
    EVP_MD_CTX_free(mdctx);
    fclose(file);
    return 0;
}

// Fonction pour ajouter un élément à une liste log_t
void add_log_element(log_t *logs, const char *path, const unsigned char *md5, const char *date, const int verbose) {
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
        free((char *)new_element->path);
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
    if (verbose) {
        printf("Ajout du %s\n", new_element->path);
    }
    
}

int create_directories(const char *path) {
    char temp[PATH_MAX];
    strncpy(temp, path, sizeof(temp));
    temp[sizeof(temp) - 1] = '\0';


    // Extraire uniquement le chemin des répertoires (sans le nom de fichier)
    char *last_slash = strrchr(temp, '/');
    if (!last_slash) {
        fprintf(stderr, "Erreur : Le chemin ne contient pas de répertoires.\n");
        return -1;
    }
    *last_slash = '\0'; // Terminer la chaîne au dernier '/'


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

void traiter_un_dossier(const char *source_dir, const char *backup_dir, log_t *logs, const int verbose)
{
    DIR *dir = opendir(source_dir);
    if (!dir) {
        printf("erreur repertoire [%s]\n", source_dir);
        perror("Erreur lors de l'ouverture du répertoire source");
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
            traiter_un_dossier(subdir_path, dest_path, logs, verbose);
        }

        // on traite les fichiers

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
        for (log_element *cur = logs->head; cur; cur = cur->next) {
            if (memcmp(cur->md5, md5, MD5_DIGEST_LENGTH) == 0) {
                existing_log = cur;
                break;
            }
        }

        if (!existing_log) { // si c'est un nouveau fichier ou un fichier modifié
            create_directories(dest_path); // on créé les dossiers nécessaires
            backup_file(src_path, dest_path, verbose); // Sauvegarde le fichier
        }

        // Ajouter le fichier au log

        char mtime_str[64];
        struct tm *time_info = localtime(&file_stat.st_mtime);
        strftime(mtime_str, sizeof(mtime_str), "%Y-%m-%d %H:%M:%S", time_info);

        char chemin_pour_log[PATH_MAX];
        remove_prefix_by_datetime(dest_path, chemin_pour_log);

        add_log_element(logs, chemin_pour_log, md5, mtime_str, verbose);
    }
    closedir(dir);
}

int directory_exists(const char *path) {
    struct stat info;
    if (stat(path, &info) == 0 && S_ISDIR(info.st_mode)) {
        return 1; // Le répertoire existe
    }
    return 0; // Le répertoire n'existe pas ou n'est pas un dossier
}

int file_exists(const char *path) {
    struct stat info;
    return stat(path, &info) == 0; // Retourne vrai si le fichier existe
}

void get_backup_date(const char *backup_dir, char *date, size_t date_size) {
    if (!backup_dir || !date) {
        fprintf(stderr, "Paramètres invalides.\n");
        return;
    }

    // Trouver le dernier '/' dans le chemin pour obtenir le nom du dossier
    const char *last_slash = strrchr(backup_dir, '/');
    const char *folder_name = last_slash ? last_slash + 1 : backup_dir;

    // Copier la date (le nom du dossier) dans la variable `date`
    snprintf(date, date_size, "%s", folder_name);
}

// Fonction pour comparer deux dates sous le format YYYY-MM-DD-hh:mm:ss.sss
int compare_dates(const char *date1, const char *date2) {
    return strcmp(date1, date2); // strcmp fonctionne ici car le format des dates permet une comparaison lexicographique
}

// Fonction pour comparer deux MD5 (tableaux d'octets)
int compare_md5(const unsigned char *md5_1, const unsigned char *md5_2) {
    return memcmp(md5_1, md5_2, MD5_DIGEST_LENGTH) == 0;
}


void list_backups(const char *backup_dir, const int verbose) {
    // Ouvrir le répertoire
    DIR *dir = opendir(backup_dir);
    if (dir == NULL) {
        perror("Erreur lors de l'ouverture du répertoire");
        return;
    }

    // Lire les fichiers du répertoire
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Ignorer les répertoires spéciaux '.' et '..'
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (entry->d_type == DT_DIR) { // Si l'entrée est un dossier
            if (verbose) {
                printf("Sauvegarde trouvée : %s/%s\n", backup_dir, entry->d_name);
            }
        }
    }
    closedir(dir);
}

void read_binary_file(const char *filename, const int verbose) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Erreur d'ouverture du fichier");
        return;
    }

    unsigned char buffer[100];
    size_t bytes_read;
    
    if (verbose) {
        printf("Contenu du fichier %s :\n", filename);
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            for (size_t i = 0; i < bytes_read; i++) {
                printf("%02x ", buffer[i]);  // Affiche les octets en hexadécimal
            }
            printf("\n");
        }
    }
    

    fclose(file);
}

void print_chunk_content(Chunk *chunks, int chunk_count, Md5Entry *hash_table) {

    printf("Dans le print_chunk_content \n");
    print_hash_table(hash_table);
    

    for (int i = 0; i < chunk_count; i++) {
        printf("Chunk %d:\n", i);
        
        // Afficher le MD5 en hexadécimal
        printf("\tMD5 : ");
        for (int j = 0; j < MD5_DIGEST_LENGTH; j++) {
            printf("%02x", chunks[i].md5[j]);
        }
        printf("\n");

        // Afficher les données du chunk en hexadécimal
        printf("\tData : ");
        if (chunks[i].data != NULL) {
            // Supposer que les données sont des octets, afficher en hexadécimal
            for (int j = 0; j < CHUNK_SIZE; j++) {
                // Afficher les octets de données, et stopper dès qu'on atteint la fin des données du chunk
                if (j < CHUNK_SIZE && ((unsigned char*)chunks[i].data)[j] != '\0') {
                    printf("%02x ", ((unsigned char*)chunks[i].data)[j]);
                } else {
                    break;
                }
            }
        }
        else
        {
            printf("[NULL]");
        }
        
        printf("\n");
    }

    /*

    for (int i = 0; i < chunk_count; i++) {
        printf("Chunk %d:\n", i);
        
        // Vérifier si ce chunk est référencé dans la table de hachage
        int index_in_hash_table = find_md5(hash_table, chunks[i].md5);

        printf("\tIndex dans la hash_table : %d\n", index_in_hash_table);


        if (index_in_hash_table != -1 && index_in_hash_table != i) {
            // Si le chunk est référencé (et pas le même index), afficher la référence
            printf("\tRéférence au chunk %d avec MD5 : ", index_in_hash_table);
        } else {
            // Sinon, afficher le contenu du chunk
            printf("\tDonnées : ");
            for (int j = 0; j < 16; j++) { // Affichage des 16 premiers octets du chunk
                printf("%02x ", ((unsigned char*)chunks[i].data)[j]);
            }
            printf("\n");
        }
    }
    */
}

void print_hash_table(Md5Entry *hash_table) {
    printf("Table de hachage :\n");

    // Parcourir toute la table de hachage
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        if (hash_table[i].index != -1) { // Si l'entrée n'est pas vide
            printf("Index %d :\n", i);
            printf("  MD5 : ");
            for (int j = 0; j < MD5_DIGEST_LENGTH; j++) {
                printf("%02x", hash_table[i].md5[j]); // Afficher chaque octet du MD5 en hex
            }
            printf("\n");
            printf("  Chunk index : %d\n", hash_table[i].index); // Afficher l'index du chunk
        }
    }
}


void remove_prefix_by_datetime(const char *input_path, char *output_path) {
    // Expression régulière pour rechercher un dossier au format YYYY-MM-DD-HH:MM:SS
    const char *pattern = "/[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}:[0-9]{2}:[0-9]{2}";

    regex_t regex;
    regmatch_t matches[1];

    // Compiler l'expression régulière
    if (regcomp(&regex, pattern, REG_EXTENDED)) {
        fprintf(stderr, "Erreur de compilation de l'expression régulière\n");
        return;
    }

    // Trouver la correspondance dans le chemin
    if (regexec(&regex, input_path, 1, matches, 0) == 0) {
        // Extraire la partie du chemin après la correspondance
        strncpy(output_path, input_path + matches[0].rm_so + 1, strlen(input_path) - matches[0].rm_so); // +1 pour ignorer le '/'
    } else {
        // Si aucun motif trouvé, renvoyer le chemin complet
        strcpy(output_path, input_path);
    }

    // Libérer la mémoire allouée pour l'expression régulière
    regfree(&regex);
}

void remove_prefix_by_datetime_removing_date(const char *input_path, char *output_path) {
    // Trouver la position du premier '/'
    const char *slash_pos = strchr(input_path, '/');
    if (slash_pos) {
        // Copier tout après le '/'
        strcpy(output_path, slash_pos + 1);
    } else {
        // Si aucun '/' n'est trouvé, juste copier toute la chaîne
        strcpy(output_path, input_path);
    }
}


void extract_prefix(const char *line, char *prefix) {
    // Trouver la position du premier '/'
    const char *slash_pos = strchr(line, '/');
    if (slash_pos) {
        // Copier la partie avant le '/'
        size_t prefix_length = slash_pos - line;
        strncpy(prefix, line, prefix_length);
        prefix[prefix_length] = '\0'; // Terminer la chaîne avec un '\0'
    } else {
        // Si aucun '/' trouvé, on copie toute la ligne
        strcpy(prefix, line);
    }
}

void assemble_path(const char *backup_dir, const char *src_path, char *output) {
    // Vérifier si backup_dir se termine par un '/'
    size_t backup_len = strlen(backup_dir);
    int needs_separator = (backup_dir[backup_len - 1] != '/');

    // Construire le chemin final
    if (needs_separator) {
        snprintf(output, PATH_MAX, "%s/%s", backup_dir, src_path);
    } else {
        snprintf(output, PATH_MAX, "%s%s", backup_dir, src_path);
    }
}

/*

int main() {
    
    //create_backup("/media/sf_fichiers_partages_windows_linux/src/a_sauvegarder/test", "/home/elias/Documents/sav");
    //restore_backup("/home/elias/Documents/sav/2024-12-15-15:55:11", "/home/elias/Documents/restaurer");
    return 0;
}

*/

/*

POUR tester l'enregistrement et restauration d'1 fichier :

int main() {
    
    printf("Backup...\n");
    backup_file("base.txt", "sauvegarde.txt");
    printf("Restauration...\n");
    restore_file("sauvegarde.txt", "fichier_original.txt");
    read_binary_file("sauvegarde.txt");

    return 0;
}

*/