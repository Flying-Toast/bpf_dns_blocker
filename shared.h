#ifndef SHARED_H
#define SHARED_H

#include <stdbool.h>

#define MAX_BLOCKLIST_ENTRIES 10
#define MAX_HOST_LEN 100

struct blocklist_item {
	char host[MAX_HOST_LEN];
	bool is_last;
};

#endif
