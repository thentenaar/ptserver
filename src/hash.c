/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "hash.h"

#define max(X,Y) ((X) > (Y) ? (X) : (Y))

/**
 * Default table size
 */
#define HT_DEFAULT_SIZE 32

/**
 * A "tombstone" marker to mark dead positions in our table so that we
 * don't break the probing chains.
 */
#define HT_TOMBSTONE (1 << 15)

/**
 * Probe gaps for our table
 *
 * These values are the product of experimentation with different
 * table sizes, to find a prime that, when used as a probe gap,
 * produces a lower maximum probe length.
 */
#define HT_GAP_S 7
#define HT_GAP_L 313

/**
 * Hash table flags
 */
#define HT_RESIZE 0x10 /**< The table is being resized */

/**
 * Representation of a hash table entry
 */
union value {
	unsigned long l;
	const char *s;
	const void *p;
	void *nc;
};

struct entry {
	union value v;   /**< Value       */
	unsigned int h;  /**< Hash        */
	unsigned char t; /**< Value type  */
	char *k;         /**< Key         */
};

/**
 * Hash table
 */
struct ht {
	struct entry *e;       /**< Entries                     */
	unsigned int gap;      /**< Probe gap                   */
	unsigned int max_pd;   /**< Max probe depth             */
	unsigned int size;     /**< Current table size (entries)*/
	unsigned int capacity; /**< Table capacity (power of 2) */
	unsigned int mask;     /**< Mask (mod capacity)         */
	unsigned int flags;    /**< Flags                       */
	unsigned long v;       /**< Initial hash value          */
};

/**
 * 32-bit FNV-1a Hash Function
 * See: http://isthe.com/chongo/tech/comp/fnv
 *
 * Also, the '1' bit in the result is always set to ensure we don't
 * return 0, since 0 is used to represent non-existent entries in the
 * table.
 *
 * If the system has ints that are less than 32 bits wide, we'll fold
 * the result to 16 bits.
 *
 * \param[in] s String to hash
 * \param[in] v Hash value
 * \return the hashed representation of \a s.
 */
static unsigned int hash(const char *s, unsigned long v)
{
	unsigned int i;
	assert(s && *s);

	if (!v) v = 2166136261;
	while ((i = (unsigned int)*s++))
		v = (v ^ (i & 0xff)) * 16777619;

	if (sizeof i < 4)
		return (((v >> 16) ^ (v & 0xffff)) & ~HT_TOMBSTONE) | 1;
	return (v & ~HT_TOMBSTONE) | 1;
}

static unsigned int search(struct ht *ht, const char *key)
{
	unsigned int i, h, j = 1, q = 0;

	h = hash(key, ht->v);
	i = h & ht->mask;

	while (ht->e[i].h && j <= ht->max_pd) {
		if (ht->e[i].h == h && !strcmp(ht->e[i].k, key))
			return i;
		i = (i + (q += ht->gap)) & ht->mask;
	}

	errno = ENOENT;
	return UINT_MAX;
}

static unsigned int insert(struct ht *ht, const char *key,
                           const void *v, unsigned char t)
{
	unsigned int h, i = 0, j = 1, q = 0, ret = 0;
	char *k = NULL;
	assert(ht);

	/**
	 * Copy the key unless it's static
	 */
	if (!(ht->flags & (HT_STATIC_KEYS | HT_RESIZE))) {
		if (!(k = malloc(strlen(key) + 1))) {
			errno = ENOMEM;
			goto err;
		}

		memcpy(k, key, strlen(key) + 1);
	} else memcpy(&k, &key, sizeof key);

	/**
	 * Search for a suitable place to add the new entry
	 */
	h = hash(key, ht->v);
	i = h & ht->mask;

	while (ht->e[i].h & ~HT_TOMBSTONE) {
		if (ht->e[i].h == h && !strcmp(ht->e[i].k, key))
			goto ret;
		++j;
		i = (i + (q += ht->gap)) & ht->mask;
	}

	/**
	 * Finally, insert our entry
	 */
	ht->max_pd = max(ht->max_pd, j);
	ht->e[i].k = k;
	ht->e[i].h = h;
	ht->e[i].t = t;
	k = NULL;

	switch (t) {
	case HT_LONG: ht->e[i].v.l = *(const unsigned long *)v; break;
	case HT_PTR:  ht->e[i].v.p = v;                         break;
	default: /* HT_STR */
		if (!(ht->e[i].v.s = malloc(strlen((const char *)v) + 1))) {
			if (!(ht->flags & HT_STATIC_KEYS))
				free(ht->e[i].k);
			errno = ENOMEM;
			goto err;
		}
		memcpy(ht->e[i].v.nc, v, strlen((const char *)v) + 1);
	}

	++ht->size;

ret:
	if (!(ht->flags & (HT_STATIC_KEYS | HT_RESIZE))) free(k);
	return ret;

err:
	ret = UINT_MAX;
	goto ret;
}

static int resize(struct ht *ht, unsigned int capacity)
{
	int ret = -1;
	unsigned int i, j, _c, _sz;
	struct entry *e = ht->e;
	const void *v;

	assert(ht);
	_c  = ht->capacity;
	_sz = ht->size;
	capacity = max(capacity, HT_DEFAULT_SIZE);
	if (!(ht->e = calloc(capacity, sizeof *e)))
		goto nomem;

	ht->size     = 0;
	ht->max_pd   = 0;
	ht->capacity = capacity;
	ht->mask     = capacity - 1;
	ht->gap      = (capacity > 8000) ? HT_GAP_L : HT_GAP_S;
	ht->flags   |= HT_RESIZE;

	/**
	 * Re-hash entries from the original table, skipping dead and
	 * non-existent entries.
	 */
	for (i=0, j = 0; i < _c && j < _sz; i++) {
		if (e[i].h) ++j;
		if (!e[i].k || e[i].h & HT_TOMBSTONE)
			continue;

		switch(e[i].t) {
		case HT_LONG: v = &e[i].v.l; break;
		default:      v = e[i].v.p;  break;
		}

		insert(ht, e[i].k, v, e[i].t);
	}

	free(e);
	++ret;

ret:
	ht->flags &= ~HT_RESIZE;
	return ret;

nomem:
	ht->e = e;
	ret = ENOMEM;
	goto ret;
}

/**
 * Allocate space for a new hash table
 *
 * \param[in] value Initial hash value for the hash function
 * \return A pointer to the new hash_table, or NULL on error
 */
struct ht *ht_alloc(unsigned long value, unsigned flags)
{
	struct ht *ht;

	if (!(ht = calloc(sizeof *ht, 1)))
		goto ret;

	ht->flags  = flags;
	ht->v      = value;
	ht->gap    = HT_GAP_S;
	ht->max_pd = 0;

	if (resize(ht, HT_DEFAULT_SIZE)) {
		free(ht);
		ht = NULL;
	}

ret:
	return ht;
}

/**
 * Lookup a key in the given hash table
 *
 * On error, this function returns NULL, and reports the following errors
 * via \a errno:
 *
 * EINVAL - Invalid arguments were supplied
 * ENOENT - No entry found for the given key
 * ERANGE - The type of the item doesn't match the requested type
 */
static const void *ht_get(struct ht *ht, const char *key, unsigned int type)
{
	unsigned int i;

	if (!ht || !key || !*key || type > HT_MAX) {
		errno = EINVAL;
		goto ret;
	}

	errno = 0;

	if ((i = search(ht, key)) == UINT_MAX)
		goto ret;

	if (ht->e[i].t != type)
		goto etype;

	switch (ht->e[i].t) {
	case HT_LONG: return (const void *)&ht->e[i].v.l;
	case HT_STR:  return ht->e[i].v.s;
	default:      return ht->e[i].v.p;
	}

ret:
	return NULL;

etype:
	errno = ERANGE;
	goto ret;
}

/**
 * Get a long entry from a hash table
 *
 * Errors reported via errno:
 *
 * EINVAL - Invalid arguments were supplied
 * ENOENT - No entry found for the given key
 * ERANGE - The item isn't a long
 *
 * \param[in] ht  Hash table
 * \param[in] key Key to find
 * \return the long value stored at \a key, or ULONG_MAX on error
 */
unsigned long ht_get_long(struct ht *ht, const char *key)
{
	const void *p;
	return (p = ht_get(ht, key, HT_LONG)) ?
	       *(const unsigned long *)p : ULONG_MAX;
}

/**
 * Get a string entry from a hash table
 *
 * Errors reported via errno:
 *
 * EINVAL - Invalid arguments were supplied
 * ENOENT - No entry found for the given key
 * ERANGE - The item isn't a string
 *
 * \param[in] ht  Hash table
 * \param[in] key Key to find
 * \return a pointer to the string stored at \a key, or NULL on error
 */
const void *ht_get_str(struct ht *ht, const char *key)
{
	return ht_get(ht, key, HT_STR);
}

/**
 * Get a pointer entry from a hash table
 *
 * Errors reported via errno:
 *
 * EINVAL - Invalid arguments were supplied
 * ENOENT - No entry found for the given key
 * ERANGE - The item isn't a pointer
 *
 * \param[in] ht  Hash table
 * \param[in] key Key to find
 * \return a pointer to the object stored at \a key, or NULL on error
 */
const void *ht_get_ptr(struct ht *ht, const char *key)
{
	return ht_get(ht, key, HT_PTR);
}

/**
 * Get an entry from a hash table (non-const)
 *
 * This is intended for certain cases where a pointer to an object which
 * reqires later modification is stored (as \a HT_PTR.)
 *
 * Errors reported via errno:
 *
 * EINVAL  - Invalid arguments were supplied
 * ENOENT  - No entry found for the given key
 * ERANGE  - The item isn't a pointer
 *
 * \param[in] ht  Hash table
 * \param[in] key Key to find
 * \return a pointer to the object stored at \a key or NULL on error
 */
void *ht_get_ptr_nc(struct ht *ht, const char *key)
{
	void *ret;
	const void *p;

	p = ht_get(ht, key, HT_PTR);
	memcpy(&ret, &p, sizeof p);
	return ret;
}

/**
 * Remove an entry from a hash table
 *
 * This function will shrink the table if the load factor falls below
 * 25%.
 *
 * Returns the following errors:
 *
 * EINVAL  - Invalid arguments
 * ENOMEM  - Out of memory while shrinking the table
 *
 * \param[in] ht  Hash table
 * \param[in] key Key to find
 * \return 0 on success, non-zero on error
 */
int ht_rm(struct ht *ht, const char *key)
{
	unsigned i;
	if (!ht || !key || !*key) return EINVAL;
	if (!ht->size)            goto ret;

	if ((i = search(ht, key)) == UINT_MAX)
		return (errno == ENOENT) ? 0 : -1;

	--ht->size;
	ht->e[i].k    = NULL;
	ht->e[i].v.nc = NULL;
	ht->e[i].h   |= HT_TOMBSTONE;

	if (ht->e[i].t == HT_STR) free(ht->e[i].v.nc);
	if (!(ht->flags & HT_STATIC_KEYS))
		free(ht->e[i].k);

	/* If our load factor drops below 25%, resize the table */
	if (ht->size < (ht->capacity >> 2))
		resize(ht, ht->size >> 1);

ret:
	return 0;
}

/**
 * Add or Replace an entry in a hash table
 *
 * \param[in] ht   Hash table
 * \param[in] key  Key
 * \param[in] type The appropriate HT_* type constant
 * \param[in] in   Pointer (or pointer to an object) to store
 * \return 0 on success, ENOMEM on out-of-memory, EINVAL on invalid args
 */
int ht_set(struct ht *ht, const char *key, unsigned char type,
           const void *in)
{
	if (!ht || !in || !key || !*key || type > HT_MAX)
		return EINVAL;

	/**
	 * Resize the table if our load factor goes above 75%
	 */
	if (ht->size > (ht->capacity >> 1) + (ht->capacity >> 2))
		resize(ht, ht->capacity << 1);

	return ((insert(ht, key, in, type)) == UINT_MAX) ? errno : 0;
}

/**
 * Destroy a hash table
 *
 * \param[in] ht Hash table
 */
void ht_free(struct ht *ht)
{
	unsigned int i;
	if (!ht) return;

	if (!(ht->flags & HT_STATIC_KEYS)) {
		for (i = 0; i < ht->capacity; i++)
			free(ht->e[i].k);
	}
	free(ht->e);
	free(ht);
}

