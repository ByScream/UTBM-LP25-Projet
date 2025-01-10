#ifndef BACKUP_MANAGER_H
#define BACKUP_MANAGER_H

#include "deduplication.h"
#include "file_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>


// Fonction permettant de lister les différentes sauvegardes présentes dans la destination
void list_backups(const char *backup_dir, const int verbose);

// Fonction pour restaurer une backup dans un dossier. Exemple : restore_backup("blabl/truc/2024-12-10-12:30:00.000", "bidule/ma_restauration/");
void restore_backup(const char *backup_dir, const char *restore_dir, const int verbose);

// Fonction pour gérer la restauration d'un fichier dédupliqué
void traiter_restauration_fichier(log_element *cur, const char *restore_dir, log_t logs, const char *backup_dir, const int verbose);

// Fonction principale pour trouver un fichier spécifique (date antérieure et md5 identique), avec l'entrée la plus ancienne respectant les critères
const char *find_oldest_backup(log_t logs, const char *file_path, const unsigned char *target_md5, const int verbose);

// Fonction pour créer un nouveau backup incrémental
void create_backup(const char *source_dir, const char *backup_dir, const int verbose);

// Fonction implémentant la logique pour la sauvegarde d'un fichier en le dédupliquant
void backup_file(const char *filename_src, const char *filename_output, const int verbose);

// Fonction pour enregistrer une liste de chunks dans un fichier
void save_deduplicated_file(const char *filename_output, FILE *source, Chunk *chunks, int chunk_count, const int verbose);

void undeduplicate_fileV2(FILE *file, Chunk **chunks, int *chunk_count, const int verbose);

// Fonction pour restaurer un fichier
void restore_file(const char *deduplicated_filename, const char *output_filename, const int verbose);

// Fonction pour calculer le md5 d'un fichier
int calculate_file_md5(const char *src_path, unsigned char *md5_hash);

// Fonction pour ajouter un élément à une liste log_t
void add_log_element(log_t *logs, const char *path, const unsigned char *md5, const char *date, const int verbose);

// Fonction pour créer tous les répertoires contenus dans le path
int create_directories(const char *path);

// Fonction qui parcours récusirvement le dossier pour en effectuer la sauvegarde
void traiter_un_dossier(const char *source_dir, const char *backup_dir, log_t *logs, const int verbose);

// Fonction pour récupérer la date d'une sauvegarde à partir de son chemin d'accès
void get_backup_date(const char *backup_dir, char *date, size_t date_size);

// Fonction pour comparer deux dates sous le format YYYY-MM-DD-hh:mm:ss.sss
int compare_dates(const char *date1, const char *date2);

// Fonction pour comparer deux MD5 (tableaux d'octets)
int compare_md5(const unsigned char *md5_1, const unsigned char *md5_2);


int directory_exists(const char *path);
int file_exists(const char *path);

void print_hash_table(Md5Entry *hash_table);
void print_chunk_content(Chunk *chunks, int chunk_count, Md5Entry *hash_table);
void read_binary_file(const char *filename, const int verbose);

void remove_prefix_by_datetime(const char *input_path, char *output_path); // (utile pour le fichier .backup_log)
void extract_prefix(const char *line, char *prefix);
void remove_prefix_by_datetime_removing_date(const char *input_path, char *output_path);

void assemble_path(const char *backup_dir, const char *src_path, char *output);

#endif // BACKUP_MANAGER_H
