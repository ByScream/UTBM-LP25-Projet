#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include "file_handler.h"

void list_files(const char *path){
    /* Implémenter la logique pour lister les fichiers présents dans un répertoire
    */
    DIR *dir;
    struct dirent *entry;

    // Ouvre le répertoire
    dir = opendir(path);
    if (dir == NULL) {
        perror("Erreur lors de l'ouverture du répertoire");
        exit(1);
    }

    // Parcourt tous les fichiers du répertoire
    printf("Fichiers dans le répertoire %s :\n", path);
    while ((entry = readdir(dir)) != NULL) {
        // Ignore les répertoires "." et ".."
        if (entry->d_name[0] != '.') {
            printf("- %s\n", entry->d_name);
        }
    }

    // Ferme le répertoire
    closedir(dir);
}


// Fonction permettant de lire un élément du fichier .backup_log
log_t read_backup_log(const char *logfile){
    /* Implémenter la logique pour la lecture d'une ligne du fichier ".backup_log"
    * @param: logfile - le chemin vers le fichier .backup_log
    * @return: une structure log_t
    */
    log_t log = {0}; // Initialiser la structure log avec un debut et une fin NULL
    FILE *file = fopen(logfile, "r");
    if (!file) {
        return log; // Renvoie un log vide si le fichier ne peut pas être ouvert
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        // Création du nouveau log_element
        log_element *new_element = malloc(sizeof(log_element));
        if (!new_element) {
            break; // Si l'allocation mémoire à échoué
        }
        memset(new_element, 0, sizeof(log_element));

        // Parse line: path|md5|date
        char *path = strtok(line, "|");
        char *date = strtok(NULL, "|");
        char *md5_token = strtok(NULL, "\n");

        if (path && md5_token && date) {
            // Copie du chemin
            new_element->path = strdup(path);

            // Convertion du MD5 hexadecimale en binaire
            if (strlen(md5_token) == MD5_DIGEST_LENGTH * 2) {
                for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
                    sscanf(md5_token + 2*i, "%2hhx", &new_element->md5[i]);
                }
            }

            // Copie de la date
            new_element->date = strdup(date);

            // Ajoute a la liste
            if (!log.head) {
                log.head = log.tail = new_element;
            } else {
                log.tail->next = new_element;
                new_element->prev = log.tail;
                log.tail = new_element;
            }
        } else {
            free(new_element);
        }
    }

    fclose(file);
    return log;
}

void write_log_element(log_element *elt, FILE *logfile){
    /* Implémenter la logique pour écrire un élément log de la liste chaînée log_element dans le fichier .backup_log
     * @param: elt - un élément log à écrire sur une ligne
     *         logfile - le chemin du fichier .backup_log
     */
    if (elt == NULL || logfile == NULL) {
        return;
    }

    // Convertir le hash MD5 en chaîne hexadécimale
    char md5_string[MD5_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(md5_string + i * 2, "%02x", elt->md5[i]);
    }
    md5_string[MD5_DIGEST_LENGTH * 2] = '\0';

    // Écrire les informations de l'élément log dans le fichier
    fprintf(logfile, "%s|%s|%s\n",
            elt->path,          // Chemin du fichier/dossier
            md5_string,         // Hash MD5 en hexadécimal
            elt->date           // Date de dernière modification
    );

    // Appel de fflush pour s'assurer que l'écriture est immédiate
    fflush(logfile);
}


// Fonction permettant de mettre à jour une ligne du fichier .backup_log
void update_backup_log(const char *logfile, log_t *logs){
    /* Implémenter la logique de modification d'une ligne du fichier ".bakcup_log"
    * @param: logfile - le chemin vers le fichier .backup_log
    *         logs - qui est la liste de toutes les lignes du fichier .backup_log sauvegardée dans une structure log_t
    */
    // Vérifier les paramètres d'entrée
    if (!logfile || !logs) {
        return;
    }

    // Ouvrir le fichier en mode écriture
    FILE *file = fopen(logfile, "w");
    if (!file) {
        return;
    }

    // Parcourir la liste des logs
    log_element *element_courant = logs->head;
    while (element_courant) {
        // Convertir le hash MD5 en chaîne hexadécimale
        char md5_chaine[MD5_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            sprintf(md5_chaine + i * 2, "%02x", element_courant->md5[i]);
        }
        md5_chaine[MD5_DIGEST_LENGTH * 2] = '\0';

        // Écrire l'élément dans le fichier
        fprintf(file, "%s|%s|%s\n",
                element_courant->path,   // Chemin du fichier
                element_courant->date,              // Hash MD5
                md5_chaine                                      // Date
        );

        // Passer à l'élément suivant
        element_courant = element_courant->next;
    }

    // Fermer le fichier
    fclose(file);
}


void copy_file(const char *src, const char *dest){
    FILE *source = fopen(src, "rb");
    if (!source) {
        return;
    }

    FILE *destination = fopen(dest, "wb");
    if (!destination) {
        fclose(source);
        return;
    }

    // Déterminer la taille du fichier
    fseek(source, 0, SEEK_END);
    long taille = ftell(source);
    rewind(source);

    // Allouer un tampon pour la copie
    char *tampon = malloc(taille);
    if (!tampon) {
        fclose(source);
        fclose(destination);
        return;
    }

    // Lire et écrire le contenu
    size_t lu = fread(tampon, 1, taille, source);
    fwrite(tampon, 1, lu, destination);

    // Libérer les ressources
    free(tampon);
    fclose(source);
    fclose(destination);
}
