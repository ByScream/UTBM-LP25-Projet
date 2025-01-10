#ifndef DEDUPLICATION_H
#define DEDUPLICATION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <dirent.h>

// Taille d'un chunk (en octets)
#define CHUNK_SIZE 7

#define INITIAL_CHUNK_CAPACITY 100

// Taille de la table de hachage qui contiendra les chunks
// dont on a déjà calculé le MD5 pour effectuer les comparaisons
#define HASH_TABLE_SIZE 1000

// Structure pour un chunk
typedef struct {
    unsigned char md5[MD5_DIGEST_LENGTH]; // MD5 du chunk
    void *data; // Données du chunk
} Chunk;

// Table de hachage pour stocker les MD5 et leurs index
typedef struct {
    unsigned char md5[MD5_DIGEST_LENGTH];
    int index;
} Md5Entry;


// Fonction de hachage MD5 pour l'indexation dans la table de hachage
unsigned int hash_md5(unsigned char *md5);
// Fonction pour calculer le MD5 d'un chunk
void compute_md5(void *data, size_t len, unsigned char *md5_out);
// Fonction permettant de chercher un MD5 dans la table de hachage
int find_md5(Md5Entry *hash_table, unsigned char *md5, const int verbose);
// Fonction pour ajouter un MD5 dans la table de hachage
void add_md5(Md5Entry *hash_table, unsigned char *md5, int index, const int verbose);
// Fonction pour convertir un fichier non dédupliqué en tableau de chunks
Chunk* deduplicate_file(FILE *file, Md5Entry *hash_table, int *chunk_count, const int verbose);

void print_md5(unsigned char *md5);


#endif // DEDUPLICATION_H