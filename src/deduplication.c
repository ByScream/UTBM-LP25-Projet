#include "deduplication.h"
#include "file_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <dirent.h>
#include <openssl/evp.h> // Pour les fonctions modernes de calcul de hachage

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
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); // Allouer un nouveau contexte pour le calcul du MD5
    if (mdctx == NULL) {
        perror("Erreur d'allocation du contexte EVP_MD_CTX");
        exit(EXIT_FAILURE);
    }

    // Initialisation pour MD5
    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1) {
        perror("Erreur d'initialisation d'EVP_MD_CTX");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    // Mise à jour avec les données
    if (EVP_DigestUpdate(mdctx, data, len) != 1) {
        perror("Erreur de mise à jour d'EVP_MD_CTX");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    // Finalisation pour récupérer le hash MD5
    if (EVP_DigestFinal_ex(mdctx, md5_out, NULL) != 1) {
        perror("Erreur lors de la finalisation d'EVP_MD_CTX");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    // Libération du contexte
    EVP_MD_CTX_free(mdctx);
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
            //printf("MD5 trouvé à l'index %d : ", hash_index);
            //print_md5(hash_table[hash_index].md5);
            return hash_table[hash_index].index; // Trouvé // FONCTIONNE AUSSI : return hash_index; -> modifier le else : hash_table[existing_index].md5
        }
        hash_index = (hash_index + 1) % HASH_TABLE_SIZE; // Gestion des collisions
    }

    //printf("MD5 non trouvé : ");
    //print_md5(md5);
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

    // log
    //printf("Ajout dans la table : Index %d -> ", index);
    //print_md5(md5);
}

// Fonction pour convertir un fichier non dédupliqué en tableau de chunks
Chunk* deduplicate_file(FILE *file, Md5Entry *hash_table, int *chunk_count) {
    Chunk *chunks = malloc(INITIAL_CHUNK_CAPACITY * sizeof(Chunk));
    int capacity = INITIAL_CHUNK_CAPACITY;
    int chunk_index = 0;

    // Initialiser la table de hachage
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        hash_table[i].index = -1;
    }

    unsigned char buffer[CHUNK_SIZE];
    unsigned char md5[MD5_DIGEST_LENGTH];
    size_t bytes_read;

    // fread(buffer, taille en octet d'une unité à lire, nombre d'unité à lire, stream)
    bytes_read = fread(buffer, 1, CHUNK_SIZE, file); // bytes <=> octets
    printf("Nombre de bytes lus : %ld => ", bytes_read);
        printf("\t[%.*s]\n", (int)bytes_read, buffer);

    // TRAITER LE CAS avec un nombre_de_bytes < Chunk_size ==> réglé par un calloc à la place d'un malloc

    while (bytes_read > 0) {
        if (chunk_index >= capacity) {
            capacity *= 2;
            chunks = realloc(chunks, capacity * sizeof(Chunk));
        }

        compute_md5(buffer, bytes_read, md5);
        
        //printf("Chunk %d MD5 (calculé): ", chunk_index);
        //print_md5(md5);

        int existing_index = find_md5(hash_table, md5);

        //printf("Recherche du MD5 : ");
        //print_md5(md5);
        //printf(" -> Index trouvé : %d\n\n", existing_index);

        if (existing_index == -1) {
            chunks[chunk_index].data = calloc(bytes_read, 1);
            //chunks[chunk_index].data = malloc(bytes_read);
            memcpy(chunks[chunk_index].data, buffer, bytes_read);
            memcpy(chunks[chunk_index].md5, md5, MD5_DIGEST_LENGTH);
            add_md5(hash_table, md5, chunk_index);
        } else {
            
            chunks[chunk_index].data = NULL;
            memcpy(chunks[chunk_index].md5, chunks[existing_index].md5, MD5_DIGEST_LENGTH);

            //printf("Copie du MD5 pour le chunk %d à partir de la table de hachage\n", chunk_index);
            //print_md5(chunks[existing_index].md5);
        }

        bytes_read = fread(buffer, 1, CHUNK_SIZE, file);
        printf("Nombre de bytes lus : %ld => ", bytes_read);
        printf("\t[%.*s]\n", (int)bytes_read, buffer);
        chunk_index++;
    }

    *chunk_count = chunk_index;
    return chunks;
}

void print_md5(unsigned char *md5) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", md5[i]);
    }
    printf("\n");
}