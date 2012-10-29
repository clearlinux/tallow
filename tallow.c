/*
 * tallow.c - IP block sshd login abuse
 *
 * (C) Copyright 2012 Intel Corporation
 * Authors:
 *     Auke Kok <auke@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/time.h>

#include <systemd/sd-journal.h>

struct tallow_struct {
	char *ip;
	int count;
	struct timeval time;
	struct tallow_struct *next;
};

static struct tallow_struct *head;

#define FILTER_STRING "SYSLOG_IDENTIFIER=sshd"
#define PATH_IPTABLES "/usr/sbin"
#define TALLOW_CHAIN "TALLOW"
#define TALLOW_THRESHOLD 3
#define TALLOW_TIMEOUT 3600

const char *whitelist[32] = {
	"192.168.1.1",
	"192.168.1.10",
	"127.0.0.1",
	NULL
};

static int ext(char *fmt, ...)
{
	va_list args;
	char cmd[1024];

	va_start(args, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, args);
	va_end(args);

	fprintf(stderr, "Executing: \"%s\"\n", cmd);

	return (system(cmd));
}

static void block(struct tallow_struct *s)
{
	if (s->count != TALLOW_THRESHOLD)
		return;
	(void) ext("%s/iptables -t filter -A %s -s %s -j DROP", PATH_IPTABLES, TALLOW_CHAIN, s->ip);
}

static void unblock(char *ip)
{
	(void) ext("%s/iptables -t filter -D %s -s %s -j DROP", PATH_IPTABLES, TALLOW_CHAIN, ip);
}

static void find(char *ip)
{
	struct tallow_struct *s = head;
	struct tallow_struct *n;
	int i;

	/* whitelist */
	for (i = 0; whitelist[i]; i++)
		if (!strcmp(whitelist[i], ip))
			return;

	/* walk and update entry */
	while (s) {
		if (!strcmp(s->ip, ip)) {
			s->count++;
			(void) gettimeofday(&s->time, NULL);

			block(s);
			return;
		}

		if (s->next)
			s = s->next;
		else
			break;
	}

	/* append */
	n = malloc(sizeof(struct tallow_struct));
	if (!n) {
		fprintf(stderr, "Out of memory.\n");
		exit(1);
	}

	if (!head)
		head = n;
	else
		s->next = n;

	n->ip = strdup(ip);
	n->count = 1;
	n->next = NULL;
	(void) gettimeofday(&n->time, NULL);

	block(n);
	return;
}

static void prune(void)
{
	struct tallow_struct *s = head;
	struct tallow_struct *p;
	struct timeval tv;

	(void) gettimeofday(&tv, NULL);
	p = NULL;

	while (s) {
		if ((tv.tv_sec - s->time.tv_sec) > TALLOW_TIMEOUT) {
			if (p) {
				unblock(s->ip);
				p->next = s->next;
				free(s->ip);
				free(s);
				s = p->next;
				continue;
			} else {
				unblock(s->ip);
				head = s->next;
				free(s->ip);
				free(s);
				s = head;
				p = NULL;
				continue;
			}
		}
		p = s;
		s = s->next;
	}
}

int main(int argc, char *argv[])
{
	int r;
	sd_journal *j;

	r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
	if (r < 0) {
		fprintf(stderr, "Failed to open journal: %s\n", strerror(-r));
		exit(1);
	}

	/* init iptables chain */
	(void) ext("%s/iptables -t filter -N %s > /dev/null 2>&1", PATH_IPTABLES, TALLOW_CHAIN);
	if (ext("%s/iptables -t filter -F %s", PATH_IPTABLES, TALLOW_CHAIN)) {
		fprintf(stderr, "Unable to create/flush iptables chain \"%s\".\n", TALLOW_CHAIN);
		exit(1);
	}

	/* ffwd journal */
	sd_journal_add_match(j, FILTER_STRING, 0);
	sd_journal_seek_tail(j);

	while (sd_journal_wait(j, (uint64_t) -1)) {
		const void *d;
		size_t l;

		while (sd_journal_next(j) != 0) {
			char *t;
			char *m;
			int i;

			if (sd_journal_get_data(j, "MESSAGE", &d, &l) < 0) {
				fprintf(stderr, "Failed to read message field: %s\n", strerror(-r));
				continue;
			}

			m = strndup(d, l+1);
			m[l] = '\0';

			if (strstr(m, "MESSAGE=Failed password for invalid user ")) {
				t = strtok(m, " ");
				for (i = 0; i < 7; i++)
					t = strtok(NULL, " ");
				find(t);
			}

			if (strstr(m, "MESSAGE=Failed password for root ")) {
				t = strtok(m, " ");
				for (i = 0; i < 5; i++)
					t = strtok(NULL, " ");
				find(t);
			}
		}

		prune();
	}

	exit(0);
}
