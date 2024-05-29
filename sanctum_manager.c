#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void create_directory_with_shell(char *dirname) {
    // Check if the directory name starts with "sanctum_"
    const char *prefix = "sanctum_";
    char full_dirname[256];

    if (strncmp(dirname, prefix, strlen(prefix)) != 0) {
        // Add prefix if it does not start with "sanctum_"
        snprintf(full_dirname, sizeof(full_dirname), "%s%s", prefix, dirname);
    } else {
        strncpy(full_dirname, dirname, sizeof(full_dirname));
        full_dirname[sizeof(full_dirname) - 1] = '\0';  // Ensure null-termination
    }

    // Create the directory
    if (mkdir(full_dirname, 0755) == -1) {
        perror("mkdir");
        exit(EXIT_FAILURE);
    }

    // Change into the directory
    if (chdir(full_dirname) == -1) {
        perror("chdir");
        exit(EXIT_FAILURE);
    }

    // Spawn a shell
    execl("/bin/sh", "sh", (char *)NULL);
    perror("execl");  // If execl returns, there was an error
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <create|open> <dirname>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "create") == 0) {
        create_directory_with_shell(argv[2]);
    } else if (strcmp(argv[1], "open") == 0) {
        printf("TODO\n");
    } else {
        fprintf(stderr, "Invalid command: %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    return 0;
}
