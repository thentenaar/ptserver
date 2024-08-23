/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef USER_H
#define USER_H

struct user {
	unsigned long uid;
	char *password;
	char *nickname;
	char *email;
	char *first;
	char *last;
	char *privacy;
	char verified;
	char random;
	char *paid1;
	char get_offers_from_us;
	char get_offers_from_affiliates;
	char banners;
	char admin;
	char sup;
};

/**
 * Lookup a user's uid by nickname
 */
unsigned long lookup_uid(void *db_r, const char *nick);

/**
 * Returns non-zero if the given nickname is in use
 */
int nickname_in_use(void *db_r, const char *nick);

/**
 * Appends random digits to \a nick to find a nickname not in use.
 */
char *suggest_nickname(void *db_r, const char *nick);

/**
 * Given a field name (\a k) and value (\a v), set the appropriate
 * field in the user struct pointed to by \a ud; ignoring unknown
 * fields.
 */
void user_from_named_field(void *ud, const char *k, const char *v);

/**
 * Convert a user struct to a protocol record
 * \param version Target protocol version
 */
char *user_to_record(struct user *user, unsigned short version);

/**
 * Validate the password given by a user
 * \return 0 on failure, non-zero on success
 */
int user_check_password(void *db_r, unsigned long uid, const char *pw);
int user_check_question_response(void *db_r, unsigned long uid, const char *response);

int user_set_password(void *db_w, unsigned long uid, const char *pw);
int user_set_password_hint(void *db_w, unsigned long uid, const char *hint);
int user_set_secret_question(void *db_w, unsigned long uid, unsigned id, const char *response);
int user_get_secret_question(void *db_r, unsigned long uid, char **q);

int register_user(void *db_w, struct user *u);
int user_exists(void *db_r, unsigned long uid);
int user_is_staff(void *db_r, unsigned long uid);
void user_logged_in(void *db_w, unsigned long uid);
void user_set_privacy(void *db_w, unsigned long uid, char privacy);
int lookup_user(void *db_r, unsigned long uid, struct user *user);
char *search_users(void *db_r, const char *field, const char *partial);
void free_user(struct user *user);

#endif /* USER_H */
