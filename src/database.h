/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef DATABASE_H
#define DATABASE_H

#define db_get_int(X) db_get_count((X))

void *db_open(const char *path, const char mode);
const char *db_errmsg(void *db);
void db_begin(void *db);
void db_end(void *db);
int db_exec(void *db, void *ud, const char *sql, int (*cb)(void *userdata, int cols, char *val[], char *col[]));

/**
 * Transform a row (or rows) to a set of records
 *
 * \a userdata here is a char ** cast to void *.
 */
int db_row_to_record(void *userdata, int cols, char *val[], char *col[]);

/**
 * Transform a set of row values to a set of records
 *
 * \a userdata here is a char ** cast to void *.
 */
int db_values_to_record(void *userdata, int cols, char *val[], char *col[]);

void *db_prepare(void *db, const char *sql);
void db_bind(void *stmt, const char *fmt, ...);
unsigned db_get_count(void *stmt);
char *db_get_string(void *stmt);
char *db_get_prepared_sql(void *stmt);
int db_do_prepared(void *stmt);
void db_reset_prepared(void *stmt);
void db_free_prepared(void *stmt);
void db_free(void *p);
void db_close(void *dbc);

#endif /* DATABASE_H */
