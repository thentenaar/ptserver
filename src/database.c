/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "database.h"
#include "logging.h"
#include "protocol.h"

static const char * const schema[] = {
"PRAGMA application_id = 0x5054dead;",

"CREATE TABLE users("
"	uid                        INTEGER PRIMARY KEY AUTOINCREMENT,"
"	nickname                   TEXT NOT NULL COLLATE NOCASE UNIQUE,"
"	email                      TEXT NOT NULL COLLATE NOCASE,"
"	first                      TEXT NOT NULL DEFAULT '',"
"	last                       TEXT NOT NULL DEFAULT '',"
"	privacy                    TEXT NOT NULL DEFAULT 'A'," /* A, T, P */
"	verified                   INT NOT NULL DEFAULT 0,"
"	random                     INT NOT NULL DEFAULT 0,"
"	paid1                      TEXT NOT NULL DEFAULT 'N'," /* Y, 6, E */
"	get_offers_from_us         INT NOT NULL DEFAULT 1,"
"	get_offers_from_affiliates INT NOT NULL DEFAULT 1,"
"	banners                    INT NOT NULL DEFAULT 0,"
"	admin                      INT NOT NULL DEFAULT 0,"
"	sup                        INT NOT NULL DEFAULT 0,"
"	created                    TEXT NOT NULL DEFAULT '',"
"	last_login                 TEXT"
") STRICT;",

/* PT 5.1 doesn't like users having a uid of 1 */
"INSERT INTO users(nickname,email,first,last) VALUES('nxuser', 'root@localhost', 'Nonexistent', 'User');",

"CREATE TABLE user_devices("
"	uid       INTEGER PRIMARY KEY REFERENCES users,"
"	device_id TEXT NOT NULL COLLATE NOCASE DEFAULT '',"
"	logins    INT NOT NULL DEFAULT 0,"
"	PRIMARY KEY(uid, device_id)"
") STRICT;",

"CREATE TABLE secret_questions("
"	id       INTEGER PRIMARY KEY AUTOINCREMENT,"
"	secret_q TEXT NOT NULL"
") STRICT;",

"INSERT INTO secret_questions VALUES(0, \"What is the answer to the question of life, the universe, and everything?\");",
"INSERT INTO secret_questions VALUES(1, \"What is the name of the street where you grew up?\");",
"INSERT INTO secret_questions VALUES(2, \"What is the name of your favorite restaraunt?\");",
"INSERT INTO secret_questions VALUES(3, \"What is the name of your favorite cartoon character?\");",
"INSERT INTO secret_questions VALUES(4, \"What is the name of your favorite fictional character?\");",
"INSERT INTO secret_questions VALUES(5, \"What is the title of your favorite book?\");",
"INSERT INTO secret_questions VALUES(6, \"Where did you go on your first date?\");",
"INSERT INTO secret_questions VALUES(7, \"What is your favorite Pet's name?\");",
"INSERT INTO secret_questions VALUES(8, \"What is the your best friends last name?\");",
"INSERT INTO secret_questions VALUES(9, \"What is the your dream occupation?\");",

"CREATE TABLE secrets("
"	uid           INTEGER PRIMARY KEY REFERENCES users,"
"	password      TEXT NOT NULL,"
"	sq_index      INTEGER REFERENCES secret_questions,"
"	sq_answer     TEXT COLLATE NOCASE,"
"	password_hint TEXT COLLATE NOCASE"
") STRICT;",

"CREATE TABLE banlevel("
"	uid   INTEGER PRIMARY KEY REFERENCES users,"
"	level INT NOT NULL DEFAULT 0"
") STRICT;",

"CREATE TABLE buddylist("
"	uid     INTEGER REFERENCES users,"
"	buddy   INTEGER REFERENCES users,"
"	display TEXT,"
"	PRIMARY KEY(uid, buddy)"
") STRICT;",

"CREATE TABLE blocklist("
"	uid   INTEGER REFERENCES users,"
"	buddy INTEGER REFERENCES users,"
"	PRIMARY KEY(uid, buddy)"
") STRICT;",

"CREATE TABLE categories("
"	code  INTEGER PRIMARY KEY AUTOINCREMENT,"
"	value TEXT NOT NULL"
") STRICT;",

"CREATE TABLE subcategories("
"	subcatg INTEGER PRIMARY KEY AUTOINCREMENT,"
"	catg    INTEGER REFERENCES categories,"
"	disp    INT DEFAULT 1,"
"	name    TEXT NOT NULL"
") STRICT;",

/**
 * Most of these I gleaned from screenshots I found around the web. Not
 * having access to my old packet dumps, we'll just invent some IDs here.
 */

/* These IDs are hard-coded */
"INSERT INTO categories VALUES(0x7530, \"Top Rooms\");",
"INSERT INTO categories VALUES(0x7594, \"Featured Rooms\");"

/* These are set to be sorted after the previous two */
"INSERT INTO categories VALUES(0x7601, \"Paltalk Help Rooms\");",
"INSERT INTO categories VALUES(0x7602, \"Paltalk Radio\");",
"INSERT INTO categories VALUES(0x7603, \"Distance Learning\");",
"INSERT INTO categories VALUES(0x7604, \"Meet New Friends\");",
"INSERT INTO categories VALUES(0x7605, \"Love and Romance\");",
"INSERT INTO categories VALUES(0x7606, \"Social Issues\");",
"INSERT INTO categories VALUES(0x7607, \"By Language: Europe\");",
"INSERT INTO categories VALUES(0x7608, \"By Language: Arabic\");",
"INSERT INTO categories VALUES(0x7609, \"By Language: Spanish & Portugese\");",
"INSERT INTO categories VALUES(0x760a, \"By Language: Asia & The Far East\");",
"INSERT INTO categories VALUES(0x760b, \"By Language: Middle East\");",
"INSERT INTO categories VALUES(0x760c, \"By Language: India & Pakistan\");",
"INSERT INTO categories VALUES(0x760d, \"By Language / Nationality / Other\");",
"INSERT INTO categories VALUES(0x760e, \"African American\");",
"INSERT INTO categories VALUES(0x760f, \"Welcome Brazil\");",
"INSERT INTO categories VALUES(0x7610, \"Early Teens (13 - 17 ONLY) - NO ADULTS\");",
"INSERT INTO categories VALUES(0x7611, \"Young Adults (18+)\");",
"INSERT INTO categories VALUES(0x7612, \"Religious\");",
"INSERT INTO categories VALUES(0x7613, \"Christianity\");",
"INSERT INTO categories VALUES(0x7614, \"Islam\");",
"INSERT INTO categories VALUES(0x7615, \"Judaism\");",
"INSERT INTO categories VALUES(0x7616, \"Health Related / Parenting\");",
"INSERT INTO categories VALUES(0x7617, \"Computers - Hi Tech\");",
"INSERT INTO categories VALUES(0x7618, \"Sports and Hobbies\");",
"INSERT INTO categories VALUES(0x7619, \"Business and Finance\");",
"INSERT INTO categories VALUES(0x761a, \"Music\");",
"INSERT INTO categories VALUES(0x761b, \"Miscellaneous\");",
"INSERT INTO categories VALUES(0x761c, \"Adult Oriented\");",

"CREATE TABLE rooms("
"	id           INTEGER PRIMARY KEY AUTOINCREMENT,"
"	catg         INTEGER REFERENCES categories,"
"	subcatg      INTEGER REFERENCES subcategories,"
"	lang         TEXT NOT NULL DEFAULT 'all',"
"	r            TEXT NOT NULL DEFAULT 'A',"
"	v            INT DEFAULT 0,"
"	p            INT DEFAULT 0,"
"	l            INT DEFAULT 0,"
"	c            TEXT NOT NULL DEFAULT '000000000'," /* rrrgggbbb (decimal) */
"	nm           TEXT,"
"	mike         INT DEFAULT 1,"
"	text         INT DEFAULT 0,"
"	video        INT DEFAULT 0,"
"	topic        TEXT,"
"	topic_setter INTEGER REFERENCES users,"
"	code         INT DEFAULT 0,"    /* admin code */
"	password     TEXT,"
"	created      TEXT NOT NULL DEFAULT ''"
") STRICT;",

/* I don't remember what these were called, but they're hard-coded. */
"INSERT INTO rooms(id,catg,r,v,p,l,c,nm) VALUES(0x01c2, 0x7601, 'G', 1, 0, 0, \"Welcome New Users\");",
"INSERT INTO rooms(id,catg,r,v,p,l,c,nm) VALUES(0x0258, 0x7601, 'G', 1, 0, 0, \"Paltalk Support\");",
"UPDATE rooms SET created=datetime('now','subsec');",

/* TODO: room_admins, owner? */

"CREATE TABLE room_bans("
"	id     INTEGER REFERENCES rooms,"
"	uid    INTEGER REFERENCES users,"
"	banner INTEGER REFERENCES users,"
"	ts     TEXT NOT NULL DEFAULT '',"
"	PRIMARY KEY(id, uid)"
") STRICT;",

"CREATE TABLE room_bounces("
"	id      INTEGER REFERENCES rooms,"
"	uid     INTEGER REFERENCES users,"
"	bouncer INTEGER REFERENCES users,"
"	reason  TEXT DEFAULT '',"
"	ts      TEXT NOT NULL DEFAULT '',",
"	PRIMARY KEY(id, uid)",
") STRICT;",

"CREATE TRIGGER IF NOT EXISTS users_delete BEFORE DELETE ON users BEGIN "
"  DELETE FROM secrets WHERE uid=OLD.uid;"
"  DELETE FROM buddylist WHERE uid=OLD.uid OR buddy=OLD.uid;"
"  DELETE FROM blocklist WHERE uid=OLD.uid OR buddy=OLD.uid;"
"END;",

"CREATE TRIGGER IF NOT EXISTS category_delete BEFORE DELETE ON categories BEGIN "
"  DELETE FROM rooms WHERE catg=OLD.code;"
"  DELETE FROM subcategories WHERE catg=OLD.code;"
"END;",

"CREATE TRIGGER IF NOT EXISTS subcategory_delete BEFORE DELETE ON subcategories BEGIN "
"  UPDATE rooms SET subcatg=0 WHERE subcatg=OLD.subcatg;"
"END;",

"CREATE TABLE offline_messages("
"	from_uid INTEGER REFERENCES users,"
"	to_uid   INTEGER REFERENCES users,"
"	tstamp   TEXT NOT NULL,"
"	msg      TEXT NOT NULL,"
"	PRIMARY KEY(from_uid, to_uid, tstamp)"
") STRICT;",

/* fecf */
"CREATE TABLE user_complaints("
"	id           INTEGER PRIMARY KEY AUTOINCREMENT,"
"	complaintant INTEGER REFERENCES users,"
"	subject      INTEGER REFERENCES users,"
"	complaint    TEXT,"
") STRICT;"
};

/**
 * Connection-level settings / temp tables
 */
static const char * const preamble[] = {
	"PRAGMA foreign_keys = ON;",
	"PRAGMA journal_mode = WAL;",
	"PRAGMA temp_store = memory;",
	"PRAGMA synchronous = NORMAL;",
	"PRAGMA auto_vacuum = FULL;",

	"CREATE TEMPORARY TABLE room_users("
	"	id    INTEGER REFERENCES rooms,"
	"	uid   INTEGER REFERENCES users,"
	"	req   INT DEFAULT 0,"
	"	mic   INT DEFAULT 0,"
	"	pub   TEXT DEFAULT 'N',"
	"	away  INT DEFAULT 0,"
	"	invis INT DEFAULT 0,"
	"	PRIMARY KEY(id, uid)"
	") STRICT;"
};

static const char * const epilogue[] = {
	"DROP TABLE room_users"
};

/**
 * page_count will be zero if this is a new database file
 */
static int check_page_count(void *userdata, int cols, char *val[], char *col[])
{
	(void)userdata;
	(void)col;

	return (cols && !atol(val[0])) ? SQLITE_EMPTY : SQLITE_OK;
}

static int check_application_id(void *userdata, int cols, char *val[], char *col[])
{
	(void)userdata;
	(void)col;

	if (cols && atol(val[0]) != 0x5054dead) {
		ERROR(("The specified database file seems to be for another application"));
		return SQLITE_MISMATCH;
	}

	return SQLITE_OK;
}

void *db_open(const char *path, const char mode)
{
	size_t i;
	char *errmsg = NULL;
	int ret = 0, flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX;
	sqlite3 *db = NULL;

	if (mode == 'w')
		flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX;

	if ((ret = sqlite3_open_v2(path, &db, flags, NULL)) != SQLITE_OK)
		goto err;

	/* Create the db if empty */
	if (mode == 'w' && sqlite3_exec(db, "PRAGMA page_count;", check_page_count, db, NULL) != SQLITE_OK) {
		db_begin(db);
		for (i = 0; i < sizeof schema / sizeof *schema; i++) {
			if (sqlite3_exec(db, schema[i], NULL, NULL, &errmsg) != SQLITE_OK) {
				ERROR(("Error executing schema item %lu", ++i));
				goto err;
			}
		}
		db_end(db);
	}

	/* Apply connection-level settings */
	for (i = 0; i < sizeof preamble / sizeof *preamble; i++) {
		if (sqlite3_exec(db, preamble[i], NULL, NULL, &errmsg) != SQLITE_OK) {
			ERROR(("Error executing preamble item %lu (mode=%c)", ++i, mode));
			goto err;
		}
	}

	/* Make sure we're not looking at another app's db */
	if (sqlite3_exec(db, "PRAGMA application_id;", check_application_id, NULL, NULL) == SQLITE_OK)
		return db;

err:
	if (ret && !errmsg) ERROR(("db_open(): %s", sqlite3_errstr(ret)));
	if (errmsg) {
		ERROR(("db_open(): %s", errmsg));
		sqlite3_free(errmsg);
	}

	db_close(db);
	return NULL;

}

const char *db_errmsg(void *db)
{
	return sqlite3_errmsg(db);
}

void db_begin(void *db)
{
	char *errmsg = NULL;

	if (sqlite3_exec(db, "BEGIN IMMEDIATE TRANSACTION;", NULL, NULL, &errmsg) != SQLITE_OK)
		ERROR(("db_begin(): %s", errmsg));
	sqlite3_free(errmsg);
	return;
}

void db_end(void *db)
{
	char *errmsg = NULL;

	if (sqlite3_exec(db, "COMMIT;", NULL, NULL, &errmsg) != SQLITE_OK)
		ERROR(("db_end(): %s", errmsg));
	sqlite3_free(errmsg);
	return;
}

int db_exec(void *db, void *ud, const char *sql, int (*cb)(void *userdata, int cols, char *val[], char *col[]))
{
	int ret = 0;
	char *errmsg = NULL;

	if (sqlite3_exec(db, sql, cb, ud, &errmsg) != SQLITE_OK) {
		ERROR(("db_exec: [%s] error: %s", sql, errmsg));
		--ret;
	}

	sqlite3_free(errmsg);
	return ret;
}

/**
 * Transform a row (or rows) to a set of records
 *
 * \a userdata here is a char ** cast to void *.
 */
int db_row_to_record(void *userdata, int cols, char *val[], char *col[])
{
	int i;
	char *buf = NULL, **out = (char **)userdata;

	if (!userdata)
		return SQLITE_ERROR;

	for (i = 0; i < cols; i++)
		buf = append_field(buf, col[i], val[i]);
	*out = append_record(*out, buf);
	free(buf);
	return SQLITE_OK;
}

/**
 * Transform a set of row values to a set of records
 *
 * \a userdata here is a char ** cast to void *.
 */
int db_values_to_record(void *userdata, int cols, char *val[], char *col[])
{
	int i;
	char *buf = NULL, **out = (char **)userdata;
	(void)col;

	if (!userdata)
		return SQLITE_ERROR;

	for (i = 0; i < cols; i++)
		buf = append_value(buf, val[i]);
	*out = append_record(*out, buf);
	free(buf);
	return SQLITE_OK;
}

void *db_prepare(void *db, const char *sql)
{
	sqlite3_stmt *stmt;

	if (sqlite3_prepare_v2(db, sql, (int)strlen(sql) + 1, &stmt, NULL) == SQLITE_OK)
		return stmt;
	return NULL;
}

void db_bind(void *stmt, const char *fmt, ...)
{
	size_t i = 1;
	va_list ap;
	const char *s;
	int x;

	if (!stmt || !fmt || !*fmt)
		return;

	va_start(ap, fmt);
	while (*fmt) {
		switch (*fmt++) {
		case 'i':
			x = va_arg(ap, int);
			sqlite3_bind_int(stmt, i++, x);
			break;
		case 'n':
			sqlite3_bind_null(stmt, i++);
			break;
		case 't':
			if (!(s = va_arg(ap, const char *))) {
				sqlite3_bind_null(stmt, i++);
			} else sqlite3_bind_text(stmt, i++, strdup(s), strlen(s), free);
			break;
		}
	}
	va_end(ap);
}

unsigned db_get_count(void *stmt)
{
	unsigned cnt = 0;

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		cnt = (unsigned)sqlite3_column_int(stmt, 0);
		while (sqlite3_step(stmt) == SQLITE_ROW);
	}

	return cnt;
}

char *db_get_string(void *stmt)
{
	char *out = NULL;
	const unsigned char *s;

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		if ((s = sqlite3_column_text(stmt, 0)))
			out = strdup((const char *)s);
		while (sqlite3_step(stmt) == SQLITE_ROW);
	}

	return out;
}

char *db_get_prepared_sql(void *stmt)
{
	return sqlite3_expanded_sql(stmt);
}

int db_do_prepared(void *stmt)
{
	int i;

	do { i = sqlite3_step(stmt); } while (i == SQLITE_ROW);
	return i == SQLITE_DONE;
}

void db_reset_prepared(void *stmt)
{
	sqlite3_reset(stmt);
	sqlite3_clear_bindings(stmt);
}

void db_free_prepared(void *stmt)
{
	sqlite3_finalize(stmt);
}

void db_free(void *p)
{
	sqlite3_free(p);
}

void db_close(void *db)
{
	unsigned i;
	char *errmsg;

	for (i = 0; i < sizeof epilogue / sizeof *epilogue; i++) {
		if (sqlite3_exec(db, epilogue[i], NULL, NULL, &errmsg) != SQLITE_OK) {
			ERROR(("Error executing epilogue item %lu", ++i));
			goto err;
		}
	}

err:
	if (errmsg) {
		ERROR(("db_close(): %s", errmsg));
		sqlite3_free(errmsg);
	}

	sqlite3_close_v2(db);
}

