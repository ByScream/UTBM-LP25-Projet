#include <stdio.h>
#include <stdlib.h>
#include "file_handler.h"

void list_files(const char *path) {
    // Implémenter la logique pour lister les fichiers dans le répertoire donné
}

void read_file(const char *filepath) {
    // Ouvrir le fichier en mode lecture binaire
    FILE *file = fopen(filepath, "rb");
    if (file == NULL) {
        // Gestion d'erreur si le fichier ne peut pas être ouvert
        perror("Erreur lors de l'ouverture du fichier");
        *size = 0;
        return NULL;
    }

    // Aller à la fin du fichier pour déterminer sa taille
    fseek(file, 0, SEEK_END);
    *size = ftell(file);

    // Revenir au début du fichier
    rewind(file);

    // Allouer de la mémoire pour le contenu du fichier
    char *buffer = malloc(*size + 1);  // +1 pour le caractère nul terminal
    if (buffer == NULL) {
        // Gestion d'erreur si l'allocation mémoire échoue
        perror("Erreur d'allocation mémoire");
        fclose(file);
        *size = 0;
        return NULL;
    }

    // Lire le contenu du fichier
    size_t bytes_read = fread(buffer, 1, *size, file);
    if (bytes_read != *size) {
        // Gestion d'erreur si la lecture est incomplète
        perror("Erreur lors de la lecture du fichier");
        free(buffer);
        fclose(file);
        *size = 0;
        return NULL;
    }

    // Ajouter un caractère nul terminal
    buffer[*size] = '\0';

    // Fermer le fichier
    fclose(file);

    return buffer;
}

void write_file(const char *filepath, const void *data, size_t size) {
    // Ouvrir le fichier en mode écriture binaire
    FILE *file = fopen(filepath, "wb");
    if (file == NULL) {
        // Gestion d'erreur si le fichier ne peut pas être ouvert
        perror("Erreur lors de l'ouverture du fichier");
        return;
    }

    // Écrire les données dans le fichier
    size_t bytes_written = fwrite(data, 1, size, file);

    // Vérifier si l'écriture a réussi complètement
    if (bytes_written != size) {
        // Gestion d'erreur si l'écriture est incomplète
        perror("Erreur lors de l'écriture du fichier");

        // Fermer le fichier avant de quitter
        fclose(file);
        return;
    }

    // Fermer le fichier
    if (fclose(file) != 0) {
        // Gestion d'erreur si la fermeture échoue
        perror("Erreur lors de la fermeture du fichier");
    }
}

