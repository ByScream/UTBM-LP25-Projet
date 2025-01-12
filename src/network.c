#include "network.h"
#include <stdlib.h>
#include <errno.h>

// Fonction pour envoyer des données à un serveur distant
void send_data(const char *server_address, int port, const void *data, size_t size) {
    int sock;
    struct sockaddr_in server;

    // Création du socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Erreur lors de la création du socket");
        exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // Conversion de l'adresse IP en format binaire
    if (inet_pton(AF_INET, server_address, &server.sin_addr) <= 0) {
        perror("Adresse IP invalide ou non supportée");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Connexion au serveur
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Échec de la connexion au serveur");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Envoi des données
    if (send(sock, data, size, 0) < 0) {
        perror("Erreur lors de l'envoi des données");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Données envoyées avec succès\n");

    // Fermeture du socket
    close(sock);
}

// Fonction pour recevoir des données sur un port spécifié
size_t receive_data(int port, size_t size) {
    int server_sock, client_sock;
    struct sockaddr_in server, client;
    socklen_t client_len = sizeof(client);
    void *buffer = malloc(size);

    if (!buffer) {
        perror("Erreur d'allocation mémoire");
        exit(EXIT_FAILURE);
    }

    // Création du socket
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Erreur lors de la création du socket");
        free(buffer);
        exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    // Liaison du socket à l'adresse et au port
    if (bind(server_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Erreur lors de la liaison du socket");
        close(server_sock);
        free(buffer);
        exit(EXIT_FAILURE);
    }

    // Écoute des connexions entrantes
    if (listen(server_sock, 1) < 0) {
        perror("Erreur lors de l'écoute");
        close(server_sock);
        free(buffer);
        exit(EXIT_FAILURE);
    }

    printf("En attente d'une connexion sur le port %d...\n", port);

    // Acceptation de la connexion
    if ((client_sock = accept(server_sock, (struct sockaddr *)&client, &client_len)) < 0) {
        perror("Erreur lors de l'acceptation de la connexion");
        close(server_sock);
        free(buffer);
        exit(EXIT_FAILURE);
    }

    printf("Connexion acceptée\n");

    // Réception des données
    ssize_t received_size = recv(client_sock, buffer, size, 0);
    if (received_size < 0) {
        perror("Erreur lors de la réception des données");
        close(client_sock);
        close(server_sock);
        free(buffer);
        exit(EXIT_FAILURE);
    }

    printf("Données reçues : %ld octets\n", received_size);

    // Fermeture des sockets
    close(client_sock);
    close(server_sock);

    // Libération de la mémoire
    free(buffer);

    return (size_t)received_size;
}
