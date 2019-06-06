/*
 * json.c - IP block sshd login abuse
 *
 * (C) Copyright 2019 Intel Corporation
 * Authors:
 *     Auke Kok <auke-jan.h.kok@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <fcntl.h>

#include <json-c/json.h>

#include "data.h"

static const char *s_pattern;
static const char *s_filter;
static int s_ban;
static double s_score;
static bool g_filter, g_ban, g_score, g_pattern = false;

static int json_parse(json_object *ob)
{
	int i, count = 0;
	bool l_filter, l_ban, l_score, l_pattern = false;

	json_object_object_foreach(ob, key, val) {
		enum json_type type;
		type = json_object_get_type(val);
		switch (type) {
		case json_type_null:
			break;
		case json_type_boolean:
			break;
		case json_type_double:
			if (strcmp(key, "score") == 0) {
				l_score = g_score = true;
				s_score = json_object_get_double(val);
			} else {
				fprintf(stderr, "Invalid JSON key \"%s\"\n", key);
				return (0);
			}
			break;
		case json_type_int:
			if (strcmp(key, "ban") == 0) {
				l_ban = g_ban = true;
				s_ban = json_object_get_int(val);
			} else {
				fprintf(stderr, "Invalid JSON key \"%s\"\n", key);
				return (0);
			}
			break;
		case json_type_string:
			if (strcmp(key, "filter") == 0) {
				l_filter = g_filter = true;
				s_filter = json_object_get_string(val);
			} else if (strcmp(key, "pattern") == 0) {
				l_pattern = g_pattern = true;
				s_pattern = json_object_get_string(val);
			} else {
				fprintf(stderr, "Invalid JSON key \"%s\"\n", key);
				return (0);
			}
			break;
		case json_type_array:
			ob = json_object_object_get(ob, key);
			int len = json_object_array_length(ob);
			json_object *val;
			for (i = 0; i < len; i++) {
				val = json_object_array_get_idx(ob, i);
				count += json_parse(val);
			}
			break;
		case json_type_object:
			ob = json_object_object_get(ob, key);
			count += json_parse(ob);
			break;
		}
	}

	/* check and finish if can */
	if (g_score && g_ban && g_pattern && g_filter) {
#ifdef DEBUG
		fprintf(stderr, "Adding: %s %s %d %lf\n", s_filter, s_pattern, s_ban, s_score);
#endif
		filter_add(s_filter);
		pattern_add(s_pattern, s_ban, s_score);
		count++;
	}

	/* cleanup */
	if (l_score) {
		l_score = g_score = false;
	} else if (l_ban) {
		l_ban = g_ban = false;
	} else if (l_pattern) {
		l_pattern = g_pattern = false;
	} else if (l_filter) {
		l_filter = g_filter = false;
	}

	return (count);
}

static int json_load_file(const char* file)
{
	int i, count = 0;
	char *json;
	int fd;
	struct stat st;
	fd = open(file, O_RDONLY);
	fstat(fd, &st);
	json = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);

	struct json_object *obj;

	obj = json_tokener_parse(json);
	if (json_object_is_type(obj,json_type_array)) {
		int len = json_object_array_length(obj);
		json_object *val;
		for (i = 0; i < len; i++) {
			val = json_object_array_get_idx(obj, i);
			count += json_parse(val);
		}
	} else if (json_object_is_type(obj, json_type_object)) {
		count += json_parse(obj);
	} else {
		fprintf(stderr, "This does not look like JSON: %s\n", file);
		return (0);
	}

	json_object_put(obj);

	munmap(json, st.st_size);
	return (count);
}

static int json_load_dir(const char *dir)
{
	int count = 0;

	DIR *d = opendir(dir);
	if (!d) {
		fprintf(stderr, "Skipped reading %s: %s\n", dir, strerror(errno));
		return (count);
	}
	struct dirent *entry;
	for (;;) {
		entry = readdir(d);
		if (!entry)
			break;
		size_t l = strlen(entry->d_name);
		if (l < strlen(".json"))
			continue;
		if (strcmp(entry->d_name + l - strlen(".json"), ".json") == 0) {
			char *p;
			if (!asprintf(&p, "%s/%s", dir, entry->d_name)) {
				fprintf(stderr, "asprintf: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}

			/* allow /etc/tallow files to override /usr/share/tallow files */
			if (strcmp(dir, DATADIR "/" PACKAGE_NAME) == 0) {
				char *sp;
				if (!asprintf(&sp, SYSCONFDIR "/" PACKAGE_NAME "/%s", entry->d_name)) {
					fprintf(stderr, "asprintf: %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}

				struct stat st;
				if (stat(sp, &st) == 0) {
					dbg("Skipped " SYSCONFDIR "/" PACKAGE_NAME "/%s\n", entry->d_name);
					free(sp);
					continue;
				}
				free(sp);
			}

			int c = json_load_file(p);
			fprintf(stderr, "%s: %d patterns\n", p, c);
			count += c;
			free(p);
		}

	}
	closedir(d);

	return (count);
}

void json_load_patterns(void)
{
	int count = 0;
	count += json_load_dir(DATADIR "/" PACKAGE_NAME);
	count += json_load_dir(SYSCONFDIR "/" PACKAGE_NAME);
	fprintf(stderr, "Loaded %d patterns total\n", count);
	if (count < 1) {
		/* consider sending a special exit code here */
		fprintf(stderr, "No patterns loaded, nothing to do!\n");
		exit(EXIT_SUCCESS);
	}
}
