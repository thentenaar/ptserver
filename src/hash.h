/**
 * ptserver - A server for the Paltalk protocol
 * Copyright (C) 2004 - 2024 Tim Hentenaar.
 *
 * This code is licensed under the Simplified BSD License.
 * See the LICENSE file for details.
 */
#ifndef HASH_H
#define HASH_H

#include <stddef.h>

/**
 * Hash table implementation intended for indexing
 * small (< 32,768 entries) sets of data.
 *
 * Useful Preprocessor Defines:
 *
 * HT_STATS - Statistics
 */

/**
 * Hash table entry value types
 */
#define HT_LONG 0 /**< A long int               */
#define HT_STR  1 /**< A string (copied on set) */
#define HT_PTR  2 /**< A pointer                */
#define HT_MAX  HT_PTR

/**
 * Defaults for ht_alloc()
 */
#define HT_VALUE_DEFAULT 0

/**
 * Flags for ht_alloc()
 */
#define HT_STATIC_KEYS 0x01 /**< Don't duplicate keys */

struct ht;

/**
 * Get the type of the given index in the type array. This
 * assumes that the array is non-NULL.
 *
 * \param T Type array
 * \param I Entry's index in the value array
 */
#define HT_TYPE(T, I) \
	((((const unsigned char *)(T))[(I) >> 1] >> (((I) & 1) << 2)) & 0x0f)

/**
 * Allocate space for a new hash table
 *
 * \param[in] value Initial hash value for the hash function
 * \return A pointer to the new hash_table, or NULL on out-of-memory
 */
struct ht *ht_alloc(unsigned long value, unsigned flags);

/**
 * Get a char entry from a hash table
 *
 * Errors reported via errno:
 *
 * EINVAL - Invalid arguments were supplied
 * ENOENT - No entry found for the given key
 * ERANGE - The item isn't a char
 *
 * \param[in] ht  Hash table
 * \param[in] key Key to find
 * \return the char value stored at \a key, or UCHAR_MAX on error
 */
unsigned char ht_get_char(struct ht *ht, const char *key);

/**
 * Get an int entry from a hash table
 *
 * Errors reported via errno:
 *
 * EINVAL - Invalid arguments were supplied
 * ENOENT - No entry found for the given key
 * ERANGE - The item isn't an int
 *
 * \param[in] ht  Hash table
 * \param[in] key Key to find
 * \return the integer value stored at \a key, or UINT_MAX on error
 */
unsigned int ht_get_int(struct ht *ht, const char *key);

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
unsigned long ht_get_long(struct ht *ht, const char *key);

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
const void *ht_get_str(struct ht *ht, const char *key);

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
const void *ht_get_ptr(struct ht *ht, const char *key);

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
 * ENOTSUP - The underlying data is immutable
 *
 * \param[in] ht  Hash table
 * \param[in] key Key to find
 * \return a pointer to the object stored at \a key or NULL on error
 */
void *ht_get_ptr_nc(struct ht *ht, const char *key);

/**
 * Remove an entry from a hash table
 *
 * Returns the following errors:
 *
 * EINVAL  - Invalid arguments
 * ENOMEM  - Out of memory
 *
 * \param[in] ht  Hash table
 * \param[in] key Key to find
 * \return 0 on success, non-zero on error
 */
int ht_rm(struct ht *ht, const char *key);

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
           const void *in);

/**
 * Destroy a hash table
 *
 * \param[in] ht Hash table
 */
void ht_free(struct ht *ht);

#ifdef HT_STATS
void ht_print_stats(struct ht *ht);
#endif

#endif /* HASH_H */

