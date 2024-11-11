#ifndef SHARED_H
#define SHARED_H

#define MAX_BLOCKLIST_ENTRIES 10
#define MAX_HOST_LEN 100

struct blocklist_item {
	char host[MAX_HOST_LEN];
	int is_last;
};

#endif
