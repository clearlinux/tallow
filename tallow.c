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
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <sys/time.h>
#include <pcre.h>

#include <systemd/sd-journal.h>

#ifdef DEBUG
#define dbg(args...) fprintf(stderr, ##args)
#else
#define dbg(args...) do {} while (0)
#endif

struct tallow_struct {
	char *ip;
	float score;
	struct timeval time;
	struct tallow_struct *next;
	bool blocked;
};

static struct tallow_struct *head;

struct whitelist_struct {
	char *ip;
	size_t len;
	struct whitelist_struct *next;
};

static struct whitelist_struct *whitelist;

#define FILTER_STRING "SYSLOG_IDENTIFIER=sshd"
struct pattern_struct {
	int instant_block;
	float weight;
	char *pattern;
	pcre *re;
};

#define PATTERN_COUNT 10
static struct pattern_struct patterns[PATTERN_COUNT] = {
	{ 0, 0.2, "MESSAGE=Failed .* for .* from ([0-9a-z:.]+) port \\d+ ssh2", NULL},
	{ 0, 0.2, "MESSAGE=error: PAM: Authentication failure for .* from ([0-9a-z:.]+)", NULL},
	{10, 0.2, "MESSAGE=Invalid user .* from ([0-9a-z:.]+) port \\d+", NULL},
	{10, 0.3, "MESSAGE=Did not receive identification string from ([0-9a-z:.]+) port \\d+", NULL},
	{15, 0.4, "MESSAGE=Bad protocol version identification .* from ([0-9a-z:.]+)", NULL},
	{15, 0.4, "MESSAGE=Connection closed by authenticating user .* ([0-9a-z:.]+) port \\d+", NULL},
	{10, 0.3, "MESSAGE=Received disconnect from ([0-9a-z:.]+) port .*\\[preauth\\]", NULL},
	{10, 0.3, "MESSAGE=Connection closed by ([0-9a-z:.]+) port .*\\[preauth\\]", NULL},
	{30, 0.5, "MESSAGE=Failed .* for root from ([0-9a-z:.]+) port \\d+ ssh2", NULL},
	{60, 0.6, "MESSAGE=Unable to negotiate with ([0-9a-z:.]+) port \\d+: no matching key exchange method found.", NULL}
};

#define MAX_OFFSETS 30

static char ipt_path[PATH_MAX];
static int expires = 3600;
static int has_ipv6 = 0;
static bool nocreate = false;
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

	__attribute__((unused)) int ret = system(cmd);
}

static void setup(void)
{
	static bool done = false;
	if (done)
		return;
	done = true;

	if (nocreate)
		return;

	/* init ipset and iptables */
	/* delete iptables ref to set before the ipset! */
	ext_ignore("%s/iptables -t filter -D INPUT -m set --match-set tallow src -j DROP 2> /dev/null", ipt_path);
	ext_ignore("%s/ipset destroy tallow 2> /dev/null", ipt_path);
	if (ext("%s/ipset create tallow hash:ip family inet timeout %d", ipt_path, expires)) {
		fprintf(stderr, "Unable to create ipv4 ipset.\n");
		exit(EXIT_FAILURE);
	}
	if (ext("%s/iptables -t filter -A INPUT -m set --match-set tallow src -j DROP", ipt_path)) {
		fprintf(stderr, "Unable to create iptables rule.\n");
		exit(EXIT_FAILURE);
	}

	if (has_ipv6) {
		ext_ignore("%s/ip6tables -t filter -D INPUT -m set --match-set tallow6 src -j DROP 2> /dev/null", ipt_path);
		ext_ignore("%s/ipset destroy tallow6 2> /dev/null", ipt_path);
		if (ext("%s/ipset create tallow6 hash:ip family inet6 timeout %d", ipt_path, expires)) {
			fprintf(stderr, "Unable to create ipv6 ipset.\n");
			exit(EXIT_FAILURE);
		}
		if (ext("%s/ip6tables -t filter -A INPUT -m set --match-set tallow6 src -j DROP", ipt_path)) {
			fprintf(stderr, "Unable to create ipt6ables rule.\n");
			exit(EXIT_FAILURE);
		}
	}
}

static void block(struct tallow_struct *s, int instant_block)
{
	setup();


	if (strchr(s->ip, ':')) {
		if (has_ipv6) {
			if (instant_block > 0) {
				(void) ext("%s/ipset -! add tallow6 %s timeout %d",
					   ipt_path, s->ip, instant_block);
			} else {
				(void) ext("%s/ipset -! add tallow6 %s", ipt_path, s->ip);
				s->blocked = true;
			}
		}
	} else {
		if (instant_block > 0) {
			(void) ext("%s/ipset -! add tallow %s timeout %d",
				   ipt_path, s->ip, instant_block);
		} else {
			(void) ext("%s/ipset -! add tallow %s", ipt_path, s->ip);
			s->blocked = true;
		}
	}

	if (s->blocked) {
		fprintf(stderr, "Blocked %s\n", s->ip);
	} else {
		dbg("Throttled %s\n", s->ip);
	}
}

static void whitelist_add(char *ip)
{
	struct whitelist_struct *w = whitelist;
	struct whitelist_struct *n;

	while (w && w->next)
		w = w->next;

	n = calloc(1, sizeof(struct whitelist_struct));
	if (!n) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	n->ip = strdup(ip);
	size_t l = strlen(ip);
	if ((ip[l-1] == '.') || (ip[l-1] == ':'))
		n->len = l;
	else
		n->len = -1;

	if (!whitelist)
		whitelist = n;
	else
		w->next = n;
}

static void find(const char *ip, float weight, int instant_block)
{
	struct tallow_struct *s = head;
	struct tallow_struct *n;
	struct whitelist_struct *w = whitelist;

	if (!ip)
		return;

	/*
	 * not validating the IP address format here, just
	 * making sure we're not passing special characters
	 * to system().
	 */
	if (strspn(ip, "0123456789abcdef:.") != strlen(ip))
		return;

	/* whitelist */
	while (w) {
		if (w->len > 0) {
			if (!strncmp(w->ip, ip, w->len))
				return;
		} else {
			if (!strcmp(w->ip, ip))
				return;
		}
		w = w->next;
	}

	/* walk and update entry */
	while (s) {
		if (!strcmp(s->ip, ip)) {
			s->score += weight;
			dbg("%s: %1.3f\n", s->ip, s->score);
			(void) gettimeofday(&s->time, NULL);

			if (s->blocked) {
				return;
			}

			if (s->score >= 1.0) {
				block(s, 0);
			} else if (instant_block > 0) {
				block(s, instant_block);
			}

			return;
		}

		if (s->next)
			s = s->next;
		else
			break;
	}

	/* append */
	n = calloc(1, sizeof(struct tallow_struct));
	if (!n) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	if (!head)
		head = n;
	else
		s->next = n;

	n->ip = strdup(ip);
	n->score = weight;
	n->next = NULL;
	n->blocked = false;
	(void) gettimeofday(&n->time, NULL);
	dbg("%s: %1.3f\n", n->ip, n->score);

	if (weight >= 1.0) {
		block(n, 0);
	} else if (instant_block > 0) {
		block(n, instant_block);
	}
	return;
}

#ifdef DEBUG
static void sigusr1(int u __attribute__ ((unused)))
{
	fprintf(stderr, "Dumping score list on request:\n");
	struct tallow_struct *s = head;
	while (s) {
		fprintf(stderr, "%ld %s %1.3f\n", s->time.tv_sec, s->ip, s->score);
		s = s->next;
	}
}
#endif

static void prune(void)
{
	struct tallow_struct *s = head;
	struct tallow_struct *p;
	struct timeval tv;

	(void) gettimeofday(&tv, NULL);
	p = NULL;

	while (s) {
		/*
		 * Expire all records, but if they are blocked, make sure to
		 * expire them *before* the ipset rule expires, otherwise
		 * you might get an IP to bypass checks.
		 */
		time_t age = tv.tv_sec - s->time.tv_sec;
		if ((age > expires) ||
		    ((s->blocked) && (age > expires / 2))) {
			dbg("Expired record for %s\n", s->ip);
			if (p) {
				p->next = s->next;
				free(s->ip);
				free(s);
				s = p->next;
				continue;
			} else {
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

int main(void)
{
	int r;
	FILE *f;
	int timeout = 60;

	strcpy(ipt_path, "/usr/sbin");

#ifdef DEBUG
	struct sigaction s;

	memset(&s, 0, sizeof(struct sigaction));
	s.sa_handler = sigusr1;
	sigaction(SIGUSR1, &s, NULL);
#endif

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
			if (!strcmp(key, "ipt_path"))
				strncpy(ipt_path, val, PATH_MAX - 1);
			if (!strcmp(key, "expires"))
				expires = atoi(val);
			if (!strcmp(key, "whitelist"))
				whitelist_add(val);
			if (!strcmp(key, "ipv6"))
				has_ipv6 = atoi(val);
			if (!strcmp(key, "nocreate"))
				nocreate = (atoi(val) == 1);
		}
		fclose(f);
	}

	if (!has_ipv6)
		fprintf(stdout, "ipv6 support disabled.\n");

	if (!whitelist) {
		whitelist_add("127.0.0.1");
		whitelist_add("192.168.");
		whitelist_add("10.");
	}

	r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
	if (r < 0) {
		fprintf(stderr, "Failed to open journal: %s\n", strerror(-r));
		exit(EXIT_FAILURE);
	}


	/* ffwd journal */
	sd_journal_add_match(j, FILTER_STRING, 0);
	r = sd_journal_seek_tail(j);
	sd_journal_wait(j, (uint64_t) 0);
	dbg("sd_journal_seek_tail() returned %d\n", r);
	while (sd_journal_next(j) != 0)
		r++;
	dbg("Forwarded through %d items in the journal to reach the end\n", r);

	fprintf(stderr, "Started\n");

	for (int i = 0; i < PATTERN_COUNT; i++) {
		int err;
		const char *pcre_err;
		patterns[i].re = pcre_compile(patterns[i].pattern, 0, &pcre_err, &err, NULL);
		if (!patterns[i].re) {
			fprintf(stderr, "PCRE compilation failed. Pattern %d, offset %d: %s\n",
				i, err, pcre_err);
			exit(EXIT_FAILURE);
		}
	}

	for (;;) {
		const void *d;
		size_t l;

		r = sd_journal_wait(j, (uint64_t) timeout * 1000000);
		if (r == SD_JOURNAL_INVALIDATE) {
			fprintf(stderr, "Journal was rotated, resetting\n");
			sd_journal_seek_tail(j);
		} else if (r == SD_JOURNAL_NOP) {
			dbg("Timeout reached, waiting again\n");
			continue;
		}

		while (sd_journal_next(j) != 0) {
			char *m;

			if (sd_journal_get_data(j, "MESSAGE", &d, &l) < 0) {
				fprintf(stderr, "Failed to read message field: %s\n", strerror(-r));
				break;
			}

			m = strndup(d, l+1);
			m[l] = '\0';

			for (int i = 0; i < PATTERN_COUNT; i++) {
				int off[MAX_OFFSETS];
				int ret = pcre_exec(patterns[i].re, NULL, m, l, 0, 0, off, MAX_OFFSETS);
				if (ret == 2) {
					const char *s;
					ret = pcre_get_substring(m, off, 2, 1, &s);
					if (ret > 0) {
						dbg("%s == %s\n", s, patterns[i].pattern);
						find(s, patterns[i].weight, patterns[i].instant_block);
						pcre_free_substring(s);
					}
				}
			}

			free(m);

		}

		prune();
	}

	sd_journal_close(j);

	exit(EXIT_SUCCESS);
}
