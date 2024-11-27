#include "deduplication.h"
#include "file_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <dirent.h>

// Fonction de hachage MD5 pour l'indexation
// dans la table de hachage
unsigned int hash_md5(unsigned char *md5) {
    unsigned int hash = 0;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        hash = (hash << 5) + hash + md5[i];
    }
    return hash % HASH_TABLE_SIZE;
}

// Fonction pour calculer le MD5 d'un chunk
void compute_md5(void *data, size_t len, unsigned char *md5_out) {
    MD5_CTX md5_context;
    MD5_Init(&md5_context);
    MD5_Update(&md5_context, data, len);
    MD5_Final(md5_out, &md5_context);
}

// Fonction permettant de chercher un MD5 dans la table de hachage
int find_md5(Md5Entry *hash_table, unsigned char *md5) {
    /* @param: hash_table est le tableau de hachage qui contient les MD5 et l'index des chunks unique
    *           md5 est le md5 du chunk dont on veut déterminer l'unicité
    *  @return: retourne l'index s'il trouve le md5 dans le tableau et -1 sinon
    */
    
    unsigned int hash_index = hash_md5(md5);

    // Recherche dans la table de hachage
    while (hash_table[hash_index].index != -1) {
        if (memcmp(hash_table[hash_index].md5, md5, MD5_DIGEST_LENGTH) == 0) {
            return hash_table[hash_index].index; // Trouvé
        }
        hash_index = (hash_index + 1) % HASH_TABLE_SIZE; // Gestion des collisions
    }

    return -1; // Non trouvé
}

// Ajouter un MD5 dans la table de hachage
void add_md5(Md5Entry *hash_table, unsigned char *md5, int index) {
    unsigned int hash_index = hash_md5(md5);

    // Ajout dans la table de hachage (gestion des collisions)
    while (hash_table[hash_index].index != -1) {
        hash_index = (hash_index + 1) % HASH_TABLE_SIZE;
    }

    memcpy(hash_table[hash_index].md5, md5, MD5_DIGEST_LENGTH);
    hash_table[hash_index].index = index;
}

// Fonction pour convertir un fichier non dédupliqué en tableau de chunks
void deduplicate_file(FILE *file, Chunk *chunks, Md5Entry *hash_table){
    /* @param:  file est le fichier qui sera dédupliqué
    *           chunks est le tableau de chunks initialisés qui contiendra les chunks issu du fichier
    *           hash_table est le tableau de hachage qui contient les MD5 et l'index des chunks unique
    */
    
    unsigned char buffer[CHUNK_SIZE];
    unsigned char md5[MD5_DIGEST_LENGTH];
    size_t bytes_read;
    int chunk_index = 0;

    // Initialiser la table de hachage avec des index vides (-1)
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        hash_table[i].index = -1;
    }

    // Lecture du fichier par chunks
    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, file)) > 0) {
        // Calculer le MD5 pour le chunk courant
        compute_md5(buffer, bytes_read, md5);

        // Vérifier si le MD5 existe déjà dans la table de hachage
        int existing_index = find_md5(hash_table, md5);
        if (existing_index == -1) {
            // Nouveau chunk unique : l'ajouter dans le tableau
            chunks[chunk_index].data = malloc(bytes_read);
            memcpy(chunks[chunk_index].data, buffer, bytes_read);
            memcpy(chunks[chunk_index].md5, md5, MD5_DIGEST_LENGTH);

            // Ajouter le MD5 dans la table de hachage
            add_md5(hash_table, md5, chunk_index);
        } else {
            // Chunk déjà existant : réutiliser les données de l'index trouvé
            chunks[chunk_index].data = NULL; // Pas besoin de stocker les données dupliquées
            memcpy(chunks[chunk_index].md5, hash_table[existing_index].md5, MD5_DIGEST_LENGTH);
        }

        chunk_index++;
    }
}


// Fonction permettant de charger un fichier dédupliqué en table de chunks
// en remplaçant les références par les données correspondantes
void undeduplicate_file(FILE *file, Chunk **chunks, int *chunk_count) {
    /* @param: file est le nom du fichier dédupliqué présent dans le répertoire de sauvegarde
    *           chunks représente le tableau de chunk qui contiendra les chunks restauré depuis filename
    *           chunk_count est un compteur du nombre de chunk restauré depuis le fichier filename
    */

    for (int i = 0; i < chunk_count; i++) {
        if (chunks[i].data != NULL) {
            // Écrire les données du chunk unique dans le fichier
            fwrite(chunks[i].data, 1, CHUNK_SIZE, file);
        } else {
            // Le chunk est un doublon, rechercher les données correspondantes
            for (int j = 0; j < chunk_count; j++) {
                if (memcmp(chunks[i].md5, chunks[j].md5, MD5_DIGEST_LENGTH) == 0 && chunks[j].data != NULL) {
                    fwrite(chunks[j].data, 1, CHUNK_SIZE, file);
                    break;
                }
            }
        }
    }
}
