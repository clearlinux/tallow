/*
 * tallow.c - IP block sshd login abuse
 *
 * (C) Copyright 2015-2019 Intel Corporation
 * Authors:
 *     Auke Kok <auke-jan.h.kok@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include <pcre.h>
#include <systemd/sd-journal.h>

#include "json.h"
#include "data.h"

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

static void reset_rules(void)
{
	/* reset all rules in case the running fw changes */
	ext_ignore("%s/firewall-cmd --permanent --direct --quiet --remove-rule ipv4 filter INPUT 1 -m set --match-set tallow src -j DROP", ipt_path);
	ext_ignore("%s/firewall-cmd --quiet --permanent --delete-ipset=tallow", ipt_path);

	/* delete iptables ref to set before the ipset! */
	ext_ignore("%s/iptables -t filter -D INPUT -m set --match-set tallow src -j DROP 2> /dev/null", ipt_path);
	ext_ignore("%s/ipset destroy tallow 2> /dev/null", ipt_path);

	if (has_ipv6) {
		ext_ignore("%s/firewall-cmd --permanent --direct --quiet --remove-rule ipv6 filter INPUT 1 -m set --match-set tallow6 src -j DROP", ipt_path);
		ext_ignore("%s/firewall-cmd --permanent --delete-ipset=tallow6 --quiet", ipt_path);	
		
		/* delete iptables ref to set before the ipset! */
		ext_ignore("%s/ip6tables -t filter -D INPUT -m set --match-set tallow6 src -j DROP 2> /dev/null", ipt_path);
		ext_ignore("%s/ipset destroy tallow6 2> /dev/null", ipt_path);		
	}
}

static void setup(void)
{
	static bool done = false;
	if (done)
		return;
	done = true;

	if (nocreate)
		return;

	/* firewalld */
	char *fwd_path;
	if (asprintf(&fwd_path, "%s/firewall-cmd", ipt_path) < 0)
	{
		fprintf(stderr, "Unable to allocate buffer for path to firewall-cmd.\n");
		exit(EXIT_FAILURE);
	}

	if ((access(fwd_path, X_OK) == 0) && ext("%s/firewall-cmd --state --quiet", ipt_path) == 0) {
		fprintf(stdout, "firewalld is running and will be used by tallow.\n");

		reset_rules();

		/* create ipv4 rule and ipset */
		if (ext("%s/firewall-cmd --permanent --quiet --new-ipset=tallow --type=hash:ip --family=inet --option=timeout=%d", ipt_path, expires)) {
			fprintf(stderr, "Unable to create ipv4 ipset with firewall-cmd.\n");
			exit(EXIT_FAILURE);
		}
		if (ext("%s/firewall-cmd --permanent --direct --quiet --add-rule ipv4 filter INPUT 1 -m set --match-set tallow src -j DROP", ipt_path)) {
			fprintf(stderr, "Unable to create ipv4 firewalld rule.\n");
			exit(EXIT_FAILURE);
		}

		/* create ipv6 rule and ipset */
		if (has_ipv6) {
			if (ext("%s/firewall-cmd --permanent --quiet --new-ipset=tallow6 --type=hash:ip --family=inet6 --option=timeout=%d", ipt_path, expires)) {
				fprintf(stderr, "Unable to create ipv6 ipset with firewall-cmd.\n");
				exit(EXIT_FAILURE);
			}
			if (ext("%s/firewall-cmd --permanent --direct --quiet --add-rule ipv6 filter INPUT 1 -m set --match-set tallow6 src -j DROP ", ipt_path)) {
				fprintf(stderr, "Unable to create ipv6 firewalld rule.\n");
				exit(EXIT_FAILURE);
			}
		}

		/* reload firewalld for ipsets to load */
		if (ext("%s/firewall-cmd --reload --quiet", ipt_path, expires)) {
			fprintf(stderr, "Unable to reload firewalld rules.\n");
			exit(EXIT_FAILURE);
		}
	}
	/* iptables */
	else {

		reset_rules();

		/* create ipv4 rule and ipset */
		if (ext("%s/ipset create tallow hash:ip family inet timeout %d", ipt_path, expires)) {
			fprintf(stderr, "Unable to create ipv4 ipset.\n");
			exit(EXIT_FAILURE);
		}
		if (ext("%s/iptables -t filter -A INPUT -m set --match-set tallow src -j DROP", ipt_path)) {
			fprintf(stderr, "Unable to create iptables rule.\n");
			exit(EXIT_FAILURE);
		}

		/* create ipv6 rule and ipset */
		if (has_ipv6) {
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

	free(fwd_path);
}

static void block(struct block_struct *s, int instant_block)
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

void find(const char *ip, float weight, int instant_block)
{
	struct block_struct *s = blocks;
	struct block_struct *n;

	if (!ip)
		return;

	/*
	 * not validating the IP address format here, just
	 * making sure we're not passing special characters
	 * to system().
	 */
	if (strspn(ip, "0123456789abcdef:.") != strlen(ip))
		return;

	if (whitelist_find(ip))
		return;

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
	n = calloc(1, sizeof(struct block_struct));
	if (!n) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	if (!blocks)
		blocks = n;
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
	struct block_struct *s = blocks;
	while (s) {
		fprintf(stderr, "%ld %s %1.3f\n", s->time.tv_sec, s->ip, s->score);
		s = s->next;
	}
}
#endif


int main(void)
{
	int r;
	FILE *f;
	int timeout = 60;
	long long int last_timestamp = 0;

	json_load_patterns();

	strcpy(ipt_path, "/usr/sbin");

#ifdef DEBUG
	fprintf(stderr, "Debug output enabled. Send SIGUSR1 to dump internal state table\n");

	struct sigaction s;

	memset(&s, 0, sizeof(struct sigaction));
	s.sa_handler = sigusr1;
	sigaction(SIGUSR1, &s, NULL);
#endif

	if (access("/proc/sys/net/ipv6", R_OK | X_OK) == 0)
		has_ipv6 = 1;

	f = fopen(SYSCONFDIR "/tallow.conf", "r");
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

	/* add all filters */
	struct filter_struct *flt = filters;
	while (flt) {
		sd_journal_add_match(j, flt->filter, 0);
		flt = flt->next;
	}

	/* go to the tail and wait */
	r = sd_journal_seek_tail(j);
	sd_journal_wait(j, (uint64_t) 0);
	dbg("sd_journal_seek_tail() returned %d\n", r);
	while (sd_journal_next(j) != 0)
		r++;
	dbg("Forwarded through %d items in the journal to reach the end\n", r);

	fprintf(stderr, PACKAGE_STRING " Started\n");

	for (;;) {
		const void *d, *dt;
		size_t l, dl;

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

			/*
			 * discard messages older than ones we've already seen before
			 * this happens when the journal rotates - we get replayed events
			 */
			if (sd_journal_get_data(j, "_SOURCE_REALTIME_TIMESTAMP", &dt, &dl) == 0) {
				long long int lt = atoi(dt + strlen("_SOURCE_REALTIME_TIMESTAMP="));
				if (lt > last_timestamp)
					last_timestamp = lt;
				else if (lt < last_timestamp)
					continue;
			}

			if (sd_journal_get_data(j, "MESSAGE", &d, &l) < 0) {
				fprintf(stderr, "Failed to read message field: %s\n", strerror(-r));
				break;
			}

			m = strndup(d, l+1);
			m[l] = '\0';

			struct pattern_struct *pat = patterns;
			while (pat) {
				int off[MAX_OFFSETS];
				int ret = pcre_exec(pat->re, NULL, m, l, 0, 0, off, MAX_OFFSETS);
				if (ret == 2) {
					const char *s;
					ret = pcre_get_substring(m, off, 2, 1, &s);
					if (ret > 0) {
						dbg("%s == %s\n", s, pat->pattern);
						find(s, pat->weight, pat->instant_block);
						pcre_free_substring(s);
					}
				}

				pat = pat->next;
			}

			free(m);

		}

		prune(expires);
	}

	sd_journal_close(j);

	exit(EXIT_SUCCESS);
}
