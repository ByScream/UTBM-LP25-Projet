CC = gcc
CFLAGS = -Wall -Wextra -I./src
LDFLAGS = -lcrypto
SRC = src/main.c src/file_handler.c src/deduplication.c src/backup_manager.c src/network.c
OBJ = $(SRC:.c=.o)

all: lp25_borgbackup

lp25_borgbackup: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJ) lp25_borgbackup
