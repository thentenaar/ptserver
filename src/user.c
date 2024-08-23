#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "macros.h"
#include "database.h"
#include "logging.h"
#include "protocol.h"
#include "user.h"

/**
 * Write prepared statement handles
 *
 * We only need prepare these once as we only have one write
 * connection.
 */
static void *set_pw;
static void *set_pw_hint;
static void *set_secret_q;
static void *insert_user;
static void *logged_in;
static void *set_privacy;

static int user_from_row(void *userdata, int cols, char *val[], char *col[])
{
	int i;

	for (i = 0; i < cols; i++)
		user_from_named_field(userdata, col[i], val[i]);
	return cols ? 0 : -1;
}

/**
 * Convert a user struct to a protocol record
 * \param version Target protocol version
 */
char *user_to_record(struct user *user, unsigned short version)
{
	char *s;
	char buf[32];

	sprintf(buf, "%ld", user->uid);
	s = append_field(NULL, "first", user->first);
	s = append_field(s, "last", user->last);
	s = append_field(s, "nickname", user->nickname);
	s = append_field(s, "email", user->email);
	s = append_field(s, "uid", buf);
	s = append_field(s, "admin", user->admin ? "1" : "0");
	s = append_field(s, "banners", user->banners ? "yes" : "no");
	s = append_field(s, "get_offers_from_us", user->get_offers_from_us ? "Y" : "N");
	s = append_field(s, "get_offers_from_affiliates", user->get_offers_from_affiliates ? "Y" : "N");
	s = append_field(s, "random", user->random ? "Y" : "N");
	s = append_field(s, "verified", user->verified ? "Y" : "N");
	s = append_field(s, "privacy", user->privacy);

	if (user->paid1 && *user->paid1 == 'E' && version < PROTOCOL_VERSION_80)
		s = append_field(s, "paid1", "6");
	else s = append_field(s, "paid1", user->paid1 ? user->paid1 : "N");

	return s;
}

/**
 * Lookup a user's uid by nickname
 */
unsigned long lookup_uid(void *db_r, const char *nick) {
	void *p;
	unsigned long ret = 0;

	if (!(p = db_prepare(db_r, "SELECT uid FROM users WHERE nickname=?")))
		goto ret;

	db_reset_prepared(p);
	db_bind(p, "t", nick);
	ret = db_get_int(p);
	db_free_prepared(p);

ret:
	return ret ? ret : UID_ALL;
}

/**
 * Returns non-zero if the given nickname is in use
 */
int nickname_in_use(void *db_r, const char *nick)
{
	int ret;
	void *p;

	if (!(p = db_prepare(db_r, "SELECT COUNT(*) FROM users WHERE nickname=?")))
		return 0;

	db_reset_prepared(p);
	db_bind(p, "t", nick);
	ret = db_get_count(p);
	db_free_prepared(p);
	return !!ret;
}

/**
 * Appends random digits to \a nick to find a nickname not in use.
 */
char *suggest_nickname(void *db_r, const char *nick)
{
	char *s;
	void *p;

	if (!db_r || !nick || !(s = malloc(min(NICKNAME_MAX, strlen(nick)) + 4)))
		return NULL;

	if (!(p = db_prepare(db_r, "SELECT COUNT(*) FROM users WHERE nickname=?"))) {
		free(s);
		return NULL;
	}

	do {
		sprintf(s, "%.*s%d", (int)min(NICKNAME_MAX - 3, strlen(nick)), nick, rand() % 1000);
		db_reset_prepared(p);
		db_bind(p, "t", s);
	} while (db_get_count(p));

	db_free_prepared(p);
	return s;
}

/**
 * Given a field name (\a k) and value (\a v), set the appropriate
 * field in the user struct pointed to by \a ud; ignoring unknown
 * fields.
 */
void user_from_named_field(void *ud, const char *k, const char *v)
{
	int known = 0;
	struct user *u = (struct user *)ud;

	if (!u || !k || !*k || !v)
		return;

	switch(strlen(k)) {
	case 3:
		switch (*k) {
		case 'u': if (!strcmp(k, "uid")) { u->uid = atol(v); ++known; } break;
		case 's': if (!strcmp(k, "sup")) { u->sup = atoi(v); ++known; } break;
		}
	break;
	case 4:
		if (!strcmp(k, "last")) {
			u->last = strdup(v);
			++known;
		}
	break;
	case 5:
		switch (*k) {
		case 'a': if (!strcmp(k, "admin")) { u->admin = atoi(v);   ++known; } break;
		case 'e': if (!strcmp(k, "email")) { u->email = strdup(v); ++known; } break;
		case 'f': if (!strcmp(k, "first")) { u->first = strdup(v); ++known; } break;
		case 'p': if (!strcmp(k, "paid1")) { u->paid1 = strdup(v); ++known; } break;
		}
	break;
	case 6:
		if (!strcmp(k, "random")) {
			u->random = tolower(*v) == 'y';
			++known;
		}
	break;
	case 7:
		switch (*k) {
		case 'b': if (!strcmp(k, "banners")) { u->banners = tolower(*v) == 'y'; ++known; } break;
		case 'p': if (!strcmp(k, "privacy")) { u->privacy = strdup(v);          ++known; } break;
		}
	break;
	case 8:
		switch (*k) {
		case 'n': if (!strcmp(k, "nickname")) { u->nickname = strdup(v);          ++known; } break;
		case 'p': if (!strcmp(k, "password")) { u->password = strdup(v);          ++known; } break;
		case 'v': if (!strcmp(k, "verified")) { u->verified = tolower(*v) == 'y'; ++known; } break;
		}
	break;
	default:
		if (!strcmp(k, "get_offers_from_affiliates")) {
			u->get_offers_from_affiliates = tolower(*v) == 'y';
			++known;
		} else if (!strcmp(k, "get_offers_from_us")) {
			u->get_offers_from_us = tolower(*v) == 'y';
			++known;
		}
	}

#ifndef NDEBUG
	if (!known && strcmp(k, "created") && strcmp(k, "last_login"))
		WARN(("Ignoring unknown user field `%s=%s'", k, v));
#endif
}

/**
 * Validate the password given by a user
 * \return 0 on failure, non-zero on success
 */
int user_check_password(void *db_r, unsigned long uid, const char *pw)
{
	void *p;
	char *s;
	int ret = 0;

	if (!db_r || !pw || !*pw || UID_IS_ERROR(uid))
		goto ret;

	if (!(p = db_prepare(db_r, "SELECT password FROM secrets WHERE uid=?")))
		goto ret;

	db_reset_prepared(p);
	db_bind(p, "i", uid);
	if ((s = db_get_string(p))) {
		ret = strlen(s) == strlen(pw) && !strcmp(s, pw);
		free(s);
	}
	db_free_prepared(p);

ret:
	return ret;
}

int user_check_question_response(void *db_r, unsigned long uid, const char *response)
{
	int ret = 0;
	char *s;
	void *p;

	if (!db_r || !response)
		goto ret;

	if (!(p = db_prepare(db_r, "SELECT sq_answer FROM secrets WHERE uid=?")))
		goto ret;

	db_reset_prepared(p);
	db_bind(p, "i", uid);
	if ((s = db_get_string(p))) {
		ret = strlen(s) == strlen(response) && !strcmp(s, response);
		free(s);
	}
	db_free_prepared(p);

ret:
	return ret;
}

int user_set_password(void *db_w, unsigned long uid, const char *pw)
{
	int ret = -1;

	if (!db_w || !pw || !*pw || UID_IS_ERROR(uid))
		goto ret;

	if (!set_pw) {
		set_pw = db_prepare(db_w,
			"INSERT INTO secrets(uid, password) VALUES(?,?) ON CONFLICT "
			"DO UPDATE SET password=excluded.password");

		if (!set_pw) {
			ERROR(("user_set_password: Failed to prepare query"))
			goto ret;
		}
	}

	db_reset_prepared(set_pw);
	db_bind(set_pw, "it", uid, pw);
	if (db_do_prepared(set_pw))
		++ret;
	else ERROR(("user_set_password: upsert failed: %s", db_errmsg(db_w)));
	db_reset_prepared(set_pw);

ret:
	return ret;
}

int user_set_password_hint(void *db_w, unsigned long uid, const char *hint)
{
	int ret = -1;

	if (!db_w || UID_IS_ERROR(uid))
		goto ret;

	if (!set_pw_hint) {
		set_pw_hint = db_prepare(db_w, "UPDATE secrets SET password_hint=? WHERE uid=?");

		if (!set_pw_hint) {
			ERROR(("user_set_password_hint: Failed to prepare query"))
			goto ret;
		}
	}

	db_reset_prepared(set_pw_hint);
	db_bind(set_pw_hint, "ti", hint, uid);
	if (db_do_prepared(set_pw_hint))
		++ret;
	else ERROR(("user_set_password_hint: update failed: %s", db_errmsg(db_w)));
	db_reset_prepared(set_pw_hint);

ret:
	return ret;
}

int user_set_secret_question(void *db_w, unsigned long uid, unsigned id, const char *response)
{
	int ret = -1;

	if (!db_w || UID_IS_ERROR(uid))
		goto ret;

	if (!set_secret_q) {
		set_secret_q = db_prepare(db_w,	"UPDATE secrets SET sq_index=?, sq_answer=? WHERE uid=?");
		if (!set_secret_q) {
			ERROR(("user_set_secret_question: Failed to prepare query"))
			goto ret;
		}
	}

	db_reset_prepared(set_secret_q);
	db_bind(set_secret_q, "iti", id, response, uid);
	if (db_do_prepared(set_secret_q))
		++ret;
	else ERROR(("user_set_secret_question: update failed: %s", db_errmsg(db_w)));
	db_reset_prepared(set_secret_q);

ret:
	return ret;
}

int user_get_secret_question(void *db_r, unsigned long uid, char **q)
{
	void *p;
	int ret = -1;

	if (!db_r || !q || UID_IS_ERROR(uid))
		goto ret;

	if (!(p = db_prepare(db_r, "SELECT secret_q FROM secret_questions WHERE id=(SELECT sq_index FROM secrets WHERE uid=?)")))
		goto ret;

	db_reset_prepared(p);
	db_bind(p, "i", uid);
	*q = db_get_string(p);
	db_free_prepared(p);
	ret += !!*q;

ret:
	return ret;

}

int register_user(void *db_w, struct user *u)
{
	int ret = -1;

	if (!db_w)
		goto ret;

	if (!insert_user) {
		insert_user = db_prepare(db_w,
			"INSERT INTO users(nickname, email, first, last, privacy, "
			"verified, random, paid1, get_offers_from_us, "
			"get_offers_from_affiliates, banners, admin, sup, created) "
			"VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now','subsec')) "
			"RETURNING uid");

		if (!insert_user) {
			ERROR(("register_user: Failed to prepare query: %s", db_errmsg(db_w)))
			goto ret;
		}
	}

	db_reset_prepared(insert_user);
	db_bind(insert_user, "tttttiitiiiii", u->nickname, u->email, u->first,
	        u->last, u->privacy ? u->privacy : "G", !!u->verified,
	        !!u->random, u->paid1 ? u->paid1 : "Y",
	        !!u->get_offers_from_us, !!u->get_offers_from_affiliates,
	        !!u->banners, !!u->admin, !!u->sup);

	if ((u->uid = db_get_int(insert_user)))
		++ret;
	else ERROR(("register_user: insert failed: %s", db_errmsg(db_w)));
	db_reset_prepared(insert_user);

ret:
	return ret;
}

int lookup_user(void *db_r, unsigned long uid, struct user *user)
{
	char buf[64];

	if (!db_r || !user || UID_IS_ERROR(uid))
		return -1;

	sprintf(buf, "SELECT * FROM users WHERE uid=%ld;", uid);
	return db_exec(db_r, user, buf, user_from_row);
}

int user_exists(void *db_r, unsigned long uid)
{
	void *p;
	int ret = 0;

	if (!db_r || UID_IS_ERROR(uid) || uid < UID_MIN || uid == UID_NEWUSER)
		goto ret;

	if (!(p = db_prepare(db_r, "SELECT COUNT(*) FROM users WHERE uid=?")))
		goto ret;

	db_reset_prepared(p);
	db_bind(p, "i", uid);
	ret += db_get_count(p);
	db_free_prepared(p);

ret:
	return ret;
}

int user_is_staff(void *db_r, unsigned long uid)
{
	void *p;
	int ret = 0;

	if (!db_r || UID_IS_ERROR(uid) || uid < UID_MIN || uid == UID_NEWUSER)
		goto ret;

	if (!(p = db_prepare(db_r, "SELECT admin+sup FROM users WHERE uid=?")))
		goto ret;

	db_reset_prepared(p);
	db_bind(p, "i", uid);
	ret += db_get_count(p);
	db_free_prepared(p);

ret:
	return ret;
}

void user_logged_in(void *db_w, unsigned long uid)
{
	if (!db_w || UID_IS_ERROR(uid))
		return;

	if (!logged_in) {
		logged_in = db_prepare(db_w, "UPDATE users SET last_login=datetime('now','subsec') WHERE uid=?");

		if (!logged_in) {
			ERROR(("user_logged_in: Failed to prepare query"))
			return;
		}
	}

	db_reset_prepared(logged_in);
	db_bind(logged_in, "i", uid);
	db_do_prepared(logged_in);
}

void user_set_privacy(void *db_w, unsigned long uid, char privacy)
{
	char buf[2];

	if (!db_w || UID_IS_ERROR(uid))
		return;

	if (!set_privacy) {
		set_privacy = db_prepare(db_w, "UPDATE users SET privacy=? WHERE uid=?");

		if (!set_privacy) {
			ERROR(("user_set_privacy: Failed to prepare query"))
			return;
		}
	}

	buf[0] = privacy;
	buf[1] = '\0';
	db_reset_prepared(set_privacy);
	db_bind(set_privacy, "ti", buf, uid);
	db_do_prepared(set_privacy);
}

static const char * const search_expr[3] = {
	"%%%s%%", /* partial */
	"%s",     /* exact   */
	"%s%%",   /* prefix  */
};

char *search_users(void *db_r, const char *field, const char *partial)
{
	void *p;
	int e = 0;
	char *buf, *sql = NULL, *s = NULL;

	if (!db_r || !field || !partial || !(buf = calloc(strlen(field) + 64, 1)))
		return NULL;

	/* 'p' for prefix, 'x' for exact */
	if ((e = ((*field == 'p') << 1) | (*field == 'x')))
		field++;

	sprintf(buf, "SELECT uid,nickname,first,last,email FROM users WHERE %s LIKE ?", field);
	if (!(p = db_prepare(db_r, buf))) {
		ERROR(("search_users: Failed to prepare query"));
		free(buf);
		return NULL;
	}

	sprintf(buf, search_expr[e], partial);
	db_reset_prepared(p);
	db_bind(p, "t", buf);
	sql = db_get_prepared_sql(p);
	db_exec(db_r, &s, sql, db_row_to_record);
	db_free(sql);
	db_free_prepared(p);
	free(buf);
	return s;
}

void free_user(struct user *user)
{
	if (!user) return;
	if (user->password) free(user->password);
	if (user->nickname) free(user->nickname);
	if (user->email)    free(user->email);
	if (user->first)    free(user->first);
	if (user->last)     free(user->last);
	if (user->paid1)    free(user->paid1);
	if (user->privacy)  free(user->privacy);
	memset(user, 0, sizeof *user);
}
