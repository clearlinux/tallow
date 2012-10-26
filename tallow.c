
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
#define TALLOW_CHAIN "TALLOW"
#define PATH_IPTABLES "/usr/sbin"
#define TALLOW_THRESHOLD 3

const char *whitelist[32] = {
	"192.168.1.1",
	"192.168.1.10",
	NULL
};

static int ext(char *fmt, ...)
{
	va_list args;
	char cmd[1024];

	va_start(args, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, args);
	va_end(args);

	return (system(cmd));
}

static void block(struct tallow_struct *s)
{
	if (s->count != TALLOW_THRESHOLD)
		return;
	(void) ext("/usr/bin/echo %s/iptables -t filter -A %s -s %s -j DROP", PATH_IPTABLES, TALLOW_CHAIN, s->ip);
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

	n->ip = ip;
	n->count = 1;
	(void) gettimeofday(&n->time, NULL);

	block(n);
	return;
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
//	sd_journal_seek_tail(j);

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

			if (strstr(m, "MESSAGE=Failed password for root  ")) {
				t = strtok(m, " ");
				for (i = 0; i < 5; i++)
					t = strtok(NULL, " ");
				find(t);
			}
		}
	}

	exit(0);
}
