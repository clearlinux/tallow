
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <systemd/sd-journal.h>

#define FILTER_STRING "SYSLOG_IDENTIFIER=sshd"

int main(int argc, char *argv[])
{
	int r;
	sd_journal *j;

	r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
	if (r < 0) {
		fprintf(stderr, "Failed to open journal: %s\n", strerror(-r));
		exit(1);
	}

	sd_journal_add_match(j, FILTER_STRING, 0);
	sd_journal_seek_tail(j);

	while (sd_journal_wait(j, (uint64_t) -1)) {
		const void *d;
		size_t l;

		while (sd_journal_next(j) != 0) {
			char *m;

			if (sd_journal_get_data(j, "MESSAGE", &d, &l) < 0) {
				fprintf(stderr, "Failed to read message field: %s\n", strerror(-r));
				continue;
			}

			/* read and parse messages */
			fprintf(stderr, "%.*s\n", (int) l, (const char*) d);

			m = strndup((const char*) d, l + 1);
			if (strstr(m, "Failed password for invalid user")) {
				char *s;
				char *c;

				c = m + strlen("Failed password for invalid user") + 1;
				s = strchr(c, ' ');
				s = '\0';

				fprintf(stderr, "%s\n", c);

			}
		}
	}

	exit(0);
}
