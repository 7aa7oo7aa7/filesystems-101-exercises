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
const char* exe_path = "/exe";
const char* cmdline_path = "/cmdline";
const char* environ_path = "/environ";

const int MAX_ARG_STRLEN = 131072;
const int FILE_PATH_MAX_LENGTH = 4096;
const int EXE_COMMAND_MAX_LENGTH = 4096;

void ps(void)
{
	DIR* proc_dir = opendir(proc_path);
	if (proc_dir == NULL) {
		report_error(proc_path, errno);
		return;
	}

	char file_path[FILE_PATH_MAX_LENGTH];
	char exe[EXE_COMMAND_MAX_LENGTH];
	const int arg_max = sysconf(_SC_ARG_MAX);
	char** argv = (char**) malloc(arg_max * sizeof(char*));
    char** envp = (char**) malloc(arg_max * sizeof(char*));
    for (int i = 0; i < arg_max; ++i) {
        argv[i] = calloc(MAX_ARG_STRLEN, sizeof(char));
        envp[i] = calloc(MAX_ARG_STRLEN, sizeof(char));
    }

	for (struct dirent* proc_dirent = readdir(proc_dir); proc_dirent != NULL; proc_dirent = readdir(proc_dir)) {
		char* endptr;
		pid_t pid = (pid_t) strtol(proc_dirent->d_name, &endptr, 10);
		if (*endptr) {
			// encountered a non-pid directory, skip it
			continue;
		}

		strcpy(file_path, proc_path);
		strcpy(file_path + strlen(proc_path) * sizeof(char), proc_dirent->d_name);
		char* current_path = file_path + (strlen(proc_path) + strlen(proc_dirent->d_name)) * sizeof(char);

		strcpy(current_path, exe_path);
		ssize_t exe_command_length = readlink(file_path, exe, EXE_COMMAND_MAX_LENGTH);
		if (exe_command_length < 0) {
			report_error(file_path, errno);
			continue;
		}

		strcpy(current_path, cmdline_path);
		FILE* argv_file = fopen(file_path, "r");
		if (argv_file == NULL) {
			report_error(file_path, errno);
			continue;
		}
		for (int i = 0; i < arg_max; ++i) {
			if (getdelim(argv + i * sizeof(char*), MAX_ARG_STRLEN * sizeof(char), '\0', argv_file) < 0 || argv[i][0] == '\0') {
				argv[i] = NULL;
				break;
			}
		}
		fclose(argv_file);

		strcpy(current_path, environ_path);
		FILE* envp_file = fopen(file_path, "r");
		if (envp_file == NULL) {
			report_error(file_path, errno);
			continue;
		}
		for (int i = 0; i < arg_max; ++i) {
			if (getdelim(envp + i * sizeof(char*), MAX_ARG_STRLEN * sizeof(char), '\0', envp_file) < 0 || envp[i][0] == '\0') {
				envp[i] = NULL;
				break;
			}
		}
		fclose(envp_file);

		report_process(pid, exe, argv, envp);
	}

	closedir(proc_dir);

	for (int i = 0; i < arg_max; ++i) {
        free(argv[i]);
        free(envp[i]);
    }
    free(argv);
    free(envp);
}
