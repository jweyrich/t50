#ifndef MODULES_H
#define MODULES_H

#include <common.h>

typedef struct {
	int protocol_id;
	char *acronym;
  char *description;
  int (*func)(const socket_t, const struct config_options *);
} modules_table_t;

#define BEGIN_MODULES_TABLE modules_table_t mod_table[] = {
#define END_MODULES_TABLE { 0, NULL, NULL, NULL } };

#define MODULE_ENTRY(id,acronym,descr,func) { (id), acronym, descr, func },

extern modules_table_t mod_table[];

#endif
