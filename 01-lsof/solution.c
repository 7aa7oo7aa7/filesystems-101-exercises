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

const int FILE_PATH_MAX_LENGTH = 8192;

void lsof(void)
{
	DIR* proc_dir = opendir(proc_path);
	if (proc_dir == NULL) {
		report_error(proc_path, errno);
		return;
	}

	char file_path[FILE_PATH_MAX_LENGTH];
	strcpy(file_path, proc_path);

	char* lsof_path = (char*) calloc(FILE_PATH_MAX_LENGTH, sizeof(char));

	for (struct dirent* proc_dirent = readdir(proc_dir); proc_dirent != NULL; proc_dirent = readdir(proc_dir)) {
		char* endptr;
		strtol(proc_dirent->d_name, &endptr, 10);
		if (*endptr) {
			// encountered a non-pid directory, skip it
			continue;
		}

		strcpy(file_path + strlen(proc_path) * sizeof(char), proc_dirent->d_name);
		char* current_path = file_path + (strlen(proc_path) + strlen(proc_dirent->d_name)) * sizeof(char);

		strcpy(current_path, fd_path);
		DIR* files_dir = opendir(file_path);
		if (files_dir == NULL) {
			report_error(file_path, errno);
			continue;
		}
		
		for (struct dirent* files_dirent = readdir(files_dir); files_dirent != NULL; files_dirent = readdir(files_dir)) {
			if (strcmp(files_dirent->d_name, ".") == 0 || strcmp(files_dirent->d_name, "..") == 0) {
				continue;
			}
			strcpy(current_path + strlen(fd_path) * sizeof(char), files_dirent->d_name);
			memset((void*) lsof_path, '\0', FILE_PATH_MAX_LENGTH * sizeof(char));
			ssize_t link_length = readlink(file_path, lsof_path, FILE_PATH_MAX_LENGTH);
			if (link_length == -1) {
				report_error(file_path, errno);
				continue;
			}
			report_file(lsof_path);
		}

		closedir(files_dir);
	}

	closedir(proc_dir);
    free(lsof_path);
}
