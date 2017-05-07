/*
 * tallow.c - IP block sshd login abuse
 *
 * (C) Copyright 2015 Intel Corporation
 * Authors:
 *     Auke Kok <auke-jan.h.kok@intel.com>
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
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <sys/time.h>

#include <systemd/sd-journal.h>

struct tallow_struct {
	char *ip;
	int count;
	struct timeval time;
	struct tallow_struct *next;
};

static struct tallow_struct *head;

static struct tallow_struct *whitelist;

#define FILTER_STRING "SYSLOG_IDENTIFIER=sshd"

static char iptables_path[PATH_MAX];
static char chain[PATH_MAX];
static int threshold = 3;
static int expires = 3600;
static int has_ipv6 = 0;
static sd_journal *j;

static int ext(char *fmt, ...)
{
	va_list args;
	char cmd[1024];
	int ret = 0;

	va_start(args, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, args);
	va_end(args);

	ret = system(cmd);
	if (ret)
		fprintf(stderr, "Error executing \"%s\": returned %d\n", cmd, ret);
	return (ret);
}

static void ext_ignore(char *fmt, ...)
{
	va_list args;
	char cmd[1024];

	va_start(args, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, args);
	va_end(args);

	(void) system(cmd);
}

static void block(struct tallow_struct *s)
{
	if (s->count != threshold)
		return;

	if (strchr(s->ip, ':')) {
		if (has_ipv6)
			(void) ext("%s/ip6tables -t filter -A %s -s %s -j DROP", iptables_path, chain, s->ip);
	} else {
		(void) ext("%s/iptables -t filter -A %s -s %s -j DROP", iptables_path, chain, s->ip);
	}

	fprintf(stderr, "Blocked %s\n", s->ip);
}

static void unblock(struct tallow_struct *s)
{
	if (s->count < threshold)
		return;

	if (strchr(s->ip, ':')) {
		if (has_ipv6)
			(void) ext("%s/ip6tables -t filter -D %s -s %s -j DROP", iptables_path, chain, s->ip);
	} else {
		(void) ext("%s/iptables -t filter -D %s -s %s -j DROP", iptables_path, chain, s->ip);
	}

	fprintf(stderr, "Unblocked %s\n", s->ip);
}

static void whitelist_add(char *ip)
{
	struct tallow_struct *w = whitelist;
	struct tallow_struct *n;

	while (w && w->next)
		w = w->next;

	n = malloc(sizeof(struct tallow_struct));
	if (!n) {
		fprintf(stderr, "Out of memory.\n");
		exit(1);
	}
	memset(n, 0, sizeof(struct tallow_struct));
	n->ip = strdup(ip);
	n->next = NULL;

	if (!whitelist)
		whitelist = n;
	else
		w->next = n;
}

static void find(char *ip)
{
	struct tallow_struct *s = head;
	struct tallow_struct *n;
	struct tallow_struct *w = whitelist;

	/*
	 * not validating the IP address format here, just
	 * making sure we're not passing special characters
	 * to system().
	 */
	if (strspn(ip, "0123456789abcdef:.") != strlen(ip))
		return;

	/* whitelist */
	while (w) {
		if (!strcmp(w->ip, ip))
			return;
		w = w->next;
	}

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
	memset(n, 0, sizeof(struct tallow_struct));

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

static void dump(void)
{
	struct tallow_struct *s = head;
	fprintf(stderr, "Received SIGUSR1 - dumping address table: address: count, time\n");

	while (s) {
		fprintf(stderr, "%s: %d, %lu.%lu\n", s->ip, s->count, s->time.tv_sec, s->time.tv_usec);
		s = s->next;
	}
}

static void sig(int s)
{
	if (s == SIGUSR1) {
		dump();
	} else {
		fprintf(stderr, "Exiting on request.\n");
		sd_journal_close(j);

		struct tallow_struct *s = head;
		while (s) {
			struct tallow_struct *n = NULL;

			free(s->ip);
			n = s;
			s = s->next;
			free(n);
		}
		exit(0);
	}
}

static void prune(void)
{
	struct tallow_struct *s = head;
	struct tallow_struct *p;
	struct timeval tv;

	(void) gettimeofday(&tv, NULL);
	p = NULL;

	while (s) {
		if ((tv.tv_sec - s->time.tv_sec) > expires) {
			if (p) {
				unblock(s);
				p->next = s->next;
				free(s->ip);
				free(s);
				s = p->next;
				continue;
			} else {
				unblock(s);
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
	FILE *f;
	struct sigaction s;
	int timeout = 60;

	strcpy(iptables_path, "/usr/sbin");
	strcpy(chain, "TALLOW");

	memset(&s, 0, sizeof(struct sigaction));
	s.sa_handler = sig;
	sigaction(SIGUSR1, &s, NULL);
	sigaction(SIGHUP, &s, NULL);
	sigaction(SIGTERM, &s, NULL);
	sigaction(SIGINT, &s, NULL);

	if (access("/proc/sys/net/ipv6", R_OK | X_OK) == 0)
		has_ipv6 = 1;

	f = fopen("/etc/tallow.conf", "r");
	if (f) {
		char buf[256];
		char *key;
		char *val;

		while (fgets(buf, 80, f) != NULL) {
			char *c;

			c = strchr(buf, '\n');
			if (c) *c = 0; /* remove trailing \n */

			if (buf[0] == '#')
				continue; /* comment line */

			key = strtok(buf, "=");
			if (!key)
				continue;
			val = strtok(NULL, "=");
			if (!val)
				continue;

			// todo: filter leading/trailing whitespace

			if (!strcmp(key, "iptables_path"))
				strncpy(iptables_path, val, PATH_MAX - 1);
			if (!strcmp(key, "chain"))
				strncpy(chain, val, PATH_MAX - 1);
			if (!strcmp(key, "threshold"))
				threshold = atoi(val);
			if (!strcmp(key, "expires"))
				expires = atoi(val);
			if (!strcmp(key, "whitelist"))
				whitelist_add(val);
			if (!strcmp(key, "ipv6"))
				has_ipv6 = atoi(val);
		}
		fclose(f);
	}

	if (!has_ipv6)
		fprintf(stdout, "ipv6 support disabled.\n");

	if (!whitelist)
		whitelist_add("127.0.0.1");

	r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
	if (r < 0) {
		fprintf(stderr, "Failed to open journal: %s\n", strerror(-r));
		exit(1);
	}

	/* init ip(6)tables chains */
	ext_ignore("%s/iptables -t filter -N %s > /dev/null 2>&1", iptables_path, chain);
	if (ext("%s/iptables -t filter -F %s", iptables_path, chain)) {
		fprintf(stderr, "Unable to create/flush iptables chain \"%s\".\n", chain);
		exit(1);
	}

	if (has_ipv6) {
		ext_ignore("%s/ip6tables -t filter -N %s > /dev/null 2>&1", iptables_path, chain);
		if (ext("%s/ip6tables -t filter -F %s", iptables_path, chain)) {
			fprintf(stderr, "Unable to create/flush ip6tables chain \"%s\".\n", chain);
			exit(1);
		}
	}

	/* ffwd journal */
	sd_journal_add_match(j, FILTER_STRING, 0);
	r = sd_journal_seek_tail(j);
	sd_journal_wait(j, (uint64_t) 0);
	fprintf(stderr, "sd_journal_seek_tail() returned %d\n", r);
	while (sd_journal_next(j) != 0)
		r++;
	fprintf(stderr, "Forwarded through %d items in the journal to reach the end\n", r);

	fprintf(stderr, "Started\n");

	for (;;) {
		const void *d;
		size_t l;

		r = sd_journal_wait(j, (uint64_t) timeout * 1000000);
		if (r == SD_JOURNAL_INVALIDATE) {
			fprintf(stderr, "Journal was rotated, resetting\n");
			sd_journal_seek_tail(j);
		}

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

			free(m);
		}

		prune();
	}

	sd_journal_close(j);

	exit(0);
}
