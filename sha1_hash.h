// ©.
// https://github.com/sizet/sha

#ifndef _SHA1_HASH_H_
#define _SHA1_HASH_H_




#define SHA1_HASH_BUFFER_SIZE 41




void sha1_hash(
    void *data_con,
    size_t data_len,
    char *out_buf,
    size_t out_size);




#endif
