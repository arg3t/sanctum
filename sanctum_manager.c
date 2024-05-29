#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <create|open> <directory_name>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *command = argv[1];
    const char *dir_name = argv[2];

    if (strcmp(command, "create") == 0) {
        // Create directory
        if (mkdir(dir_name, 0755) == -1) {
            perror("mkdir");
            return EXIT_FAILURE;
        }

        // Change to the newly created directory
        if (chdir(dir_name) == -1) {
            perror("chdir");
            return EXIT_FAILURE;
        }

        // Spawn a shell
        execlp("sh", "sh", NULL);
        // If execlp fails
        perror("execlp");
        return EXIT_FAILURE;
    } else if (strcmp(command, "open") == 0) {
        printf("TODO\n");
        return EXIT_SUCCESS;
    } else {
        fprintf(stderr, "Invalid command. Use 'create' or 'open'.\n");
        return EXIT_FAILURE;
    }
}
