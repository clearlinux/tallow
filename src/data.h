/*
 * data.h - IP block sshd login abuse
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

#pragma once

#include <pcre.h>

#ifdef DEBUG
#define dbg(args...) fprintf(stderr, ##args)
#else
#define dbg(args...) do {} while (0)
#endif

struct block_struct {
	char *ip;
	float score;
	struct timeval time;
	struct block_struct *next;
	bool blocked;
};

struct whitelist_struct {
	char *ip;
	size_t len;
	struct whitelist_struct *next;
};

struct pattern_struct {
	int instant_block;
	float weight;
	char *pattern;
	pcre *re;
	struct pattern_struct *next;
};

struct filter_struct {
	char *filter;
	struct filter_struct *next;
};

extern struct block_struct *blocks;
extern struct pattern_struct *patterns;
extern struct filter_struct *filters;
extern struct whitelist_struct *whitelist;

void filter_add(const char *filter);
void pattern_add(const char *pattern, int ban, double score);
void whitelist_add(const char *ip);
bool whitelist_find(const char *ip);
void prune(int expires);
