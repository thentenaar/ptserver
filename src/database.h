/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2025 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef DATABASE_H
#define DATABASE_H

/**
 * Get a singular result value (int)
 */
#define db_get_int(X) db_get_count((X))

/**
 * Open a database
 *
 * \param path Path to the database file
 * \param mode 'r' or 'w'
 * \return A database handle on success, NULL on error
 */
void *db_open(const char *path, const char mode);

/**
 * Get the most recent error message for a database
 */
const char *db_errmsg(void *db);

/**
 * Begin a transaction on a database
 */
void db_begin(void *db);

/**
 * Commit the current transaction on a database
 */
void db_end(void *db);

/**
 * Execute a query against the given db
 *
 * \param db  Database handle
 * \param ud  Userdata for the row callback
 * \param sql SQL statement to execute
 * \param cb  Callback function to be called for each result row
 * \return Non-zero on failure
 */
int db_exec(void *db, void *ud, const char *sql,
            int (*cb)(void *userdata, int cols, char *val[], char *col[]));

/**
 * Transform a row (or rows) to a set of records
 *
 * \a userdata here is a char **
 */
int db_row_to_record(void *userdata, int cols, char *val[], char *col[]);

/**
 * Transform a row to a set of records, one record per field.
 *
 * \a userdata here is a char **
 */
int db_row_to_record_per_field(void *userdata, int cols, char *val[], char *col[]);

/**
 * Transform a set of row values to a set of records
 *
 * \a userdata here is a char **
 */
int db_values_to_record(void *userdata, int cols, char *val[], char *col[]);

/**
 * Prepare a statement (which may contain placeholders) for the given db
 * \return the prepared statement handle, or NULL on failure
 */
void *db_prepare(void *db, const char *sql);

/**
 * Bind parameters to a prepared query
 *
 * \param stmt Prepared statement handle
 * \param fmt  Format string
 *
 * The format string has three directives, one for each placeholder:
 *   i - Integer
 *   n - Null (integer)
 *   t - Text (or NULL)
 */
void db_bind(void *stmt, const char *fmt, ...);

/**
 * Get the result of a `SELECT COUNT(*)` query
 */
unsigned db_get_count(void *stmt);

/**
 * Get a singular result value (string)
 */
char *db_get_string(void *stmt);

/**
 * Get the generated SQL for the given prepared statement
 *
 * The result of this function must be freed with ``db_free()``
 */
char *db_get_prepared_sql(void *stmt);

/**
 * Execute a prepared statement
 *
 * \param stmt Statement handle
 * \return non-zero on failure
 */
int db_do_prepared(void *stmt);

/**
 * Reset a prepared statement, clearing its bindings
 */
void db_reset_prepared(void *stmt);

/**
 * Free a prepared statement
 */
void db_free_prepared(void *stmt);

/**
 * Free a dynamically-allocated sqlite value
 */
void db_free(void *p);

/**
 * Close a database connection
 */
void db_close(void *dbc);

#endif /* DATABASE_H */
