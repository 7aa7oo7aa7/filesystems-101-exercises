#include <solution.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

const char* proc_path = "/proc/";
const char* fd_path = "/fd/";
const char* map_files_path = "/map_files/";

const int MAX_FILES = 4096;
const int FILE_PATH_MAX_LENGTH = 4096;

void lsof(void)
{
	DIR* proc_dir = opendir(proc_path);
	if (proc_dir == NULL) {
		report_error(proc_path, errno);
		return;
	}

	char file_path[FILE_PATH_MAX_LENGTH];
	strcpy(file_path, proc_path);

	// paths to files
	char** files = (char**) malloc(MAX_FILES * sizeof(char*));
    for (int i = 0; i < MAX_FILES; ++i) {
        files[i] = (char*) malloc(FILE_PATH_MAX_LENGTH * sizeof(char));
    }

	for (struct dirent* proc_dirent = readdir(proc_dir); proc_dirent != NULL; proc_dirent = readdir(proc_dir)) {
		char* endptr;
		pid_t pid = (pid_t) strtol(proc_dirent->d_name, &endptr, 10);
		if (*endptr) {
			// encountered a non-pid directory, skip it
			continue;
		}

		strcpy(file_path + strlen(proc_path) * sizeof(char), proc_dirent->d_name);
		char* current_path = file_path + (strlen(proc_path) + strlen(proc_dirent->d_name)) * sizeof(char);

		strcpy(current_path, fd_path);
		current_path += strlen(fd_path) * sizeof(char);
		DIR* files_dir = opendir(file_path);
		if (files_dir == NULL) {
			report_error(file_path, errno);
			continue;
		}

		int num_files = 0;
		for (struct dirent* files_dirent = readdir(files_dir); files_dirent != NULL; files_dirent = readdir(files_dir)) {
			if (strcmp(files_dirent->d_name, ".") == 0 || strcmp(files_dirent->d_name, "..") == 0) {
				continue;
			}
			strcpy(current_path, files_dirent->d_name);
			ssize_t link_length = readlink(file_path, files[num_files++], FILE_PATH_MAX_LENGTH);
			if (link_length < 0) {
				report_error(file_path, errno);
				continue;
			}
		}

		for (int i = 0; i < num_files; ++i) {
			report_file(files[i]);
		}

		closedir(files_dir);
	}

	closedir(proc_dir);

	for (int i = 0; i < MAX_FILES; ++i) {
        free(files[i]);
    }
    free(files);
}
