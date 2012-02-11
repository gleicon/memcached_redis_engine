/*
 * redis_engine for memcached 
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <memcached/visibility.h>
#include <memcached/engine.h>
#include <memcached/util.h>
#include <hiredis.h>


#define REDIS_SERVER "127.0.0.1"
// no globals, create pool

redisContext *redis_conn = NULL;

struct redis_engine {
    ENGINE_HANDLE_V1 engine;
};

struct redis_item {
    void *key;
    size_t nkey;
    void *data;
    size_t ndata;
    int flags;
    rel_time_t exptime;
};

static void redis_destroy(ENGINE_HANDLE *h) {
    free(h);
}


static void redis_item_release(ENGINE_HANDLE* handle,
                            const void *cookie,
                            item* item) {
    struct redis_item *it = item;
    free(it->key);
    free(it->data);
    free(it);
}


static ENGINE_ERROR_CODE redis_initialize(ENGINE_HANDLE *h, const char* config_str) {
    redis_conn = redisConnect(REDIS_SERVER, 6379);
    return ENGINE_SUCCESS;
}

static ENGINE_ERROR_CODE redis_allocate(ENGINE_HANDLE* handle,
                                     const void* cookie,
                                     item **item,
                                     const void* key,
                                     const size_t nkey,
                                     const size_t nbytes,
                                     const int flags,
                                     const rel_time_t exptime) {

    struct redis_item *it = malloc(sizeof(struct redis_item));
    if (it == NULL) return ENGINE_ENOMEM;
    it->flags = flags;
    it->exptime = exptime;
    it->nkey = nkey;
    it->ndata = nbytes;
    it->key = malloc(nkey);
    it->data = malloc(nbytes);

    if (it->key == NULL || it->data == NULL) {
        free(it->key);
        free(it->data);
        free(it);
        return ENGINE_ENOMEM;
    }

    memcpy(it->key, key, nkey);
    *item = it;
    return ENGINE_SUCCESS;
}

static bool redis_get_item_info(ENGINE_HANDLE *handle, const void *cookie,
                             const item* item, item_info *item_info) {
    struct redis_item* it = (struct redis_item*)item;
    if (item_info->nvalue < 1) return false;

    item_info->cas = 0; /* Not supported */
    item_info->clsid = 0; /* Not supported */
    item_info->exptime = it->exptime;
    item_info->flags = it->flags;
    item_info->key = it->key;
    item_info->nkey = it->nkey;
    item_info->nbytes = it->ndata; /* Total length of the items data */
    item_info->nvalue = 1; /* Number of fragments used */
    item_info->value[0].iov_base = it->data; /* pointer to fragment 1 */
    item_info->value[0].iov_len = it->ndata; /* Length of fragment 1 */

    return true;
}

static ENGINE_ERROR_CODE redis_store(ENGINE_HANDLE* handle,
                                  const void *cookie,
                                  item* item,
                                  uint64_t *cas,
                                  ENGINE_STORE_OPERATION operation,
                                  uint16_t vbucket) {
    redisReply *reply;
    struct redis_item *it = item;
    reply = redisCommand(redis_conn, "HMSET %s key %s nkey %d data %s ndata %d flags %d exptime %d", it->key, it->key, it->nkey, it->data, it->ndata, it->flags, it->exptime);
    if (reply == NULL) {
        perror("HMSET error");
        return ENGINE_NOT_STORED;
    }

    *cas = 0;
    freeReplyObject(reply);
    return ENGINE_SUCCESS;
}

static ENGINE_ERROR_CODE redis_get(ENGINE_HANDLE* handle,
                                const void* cookie,
                                item** item,
                                const void* key,
                                const int nkey,
                                uint16_t vbucket) {

    redisReply *reply;
    struct redis_item* it = NULL;
    int ndata;

    reply = redisCommand(redis_conn, "HGET %s ndata", key);

    if (reply == NULL) {
        if (redis_conn->err) {
            fprintf(stderr, "Error: %s\n", redis_conn->errstr);
            return ENGINE_FAILED;
        }
        return ENGINE_FAILED;
    }
    if (reply->str == NULL) return ENGINE_KEY_ENOENT;

    fprintf(stderr, "key: %s ndata: %s\n", key, reply->str);

    ndata = strtol(reply->str, NULL, 0);
    freeReplyObject(reply);

    reply = redisCommand(redis_conn, "HGETALL %s", key);
    if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
        if (redis_conn->err) {
            fprintf(stderr, "Error: %s\n", redis_conn->errstr);
            return ENGINE_FAILED;
        }
    }

    ENGINE_ERROR_CODE ret = redis_allocate(handle, cookie, (void**)&it, key, nkey,
                                       ndata, 0, 0);
    
    if (ret != ENGINE_SUCCESS) return ENGINE_ENOMEM;


    if (redis_conn->err) {
      fprintf(stderr, "Error: %s\n", redis_conn->errstr);
      redis_item_release(handle, cookie, it);
      return ENGINE_FAILED;
    }
    
    it->ndata = ndata;

    for (int j = 0; j < reply->elements; j+=2){
        char *k = reply->element[j]->str;
        char *v = reply->element[j+1]->str;

        if(strncmp(k, "nkey", 4)) it->nkey = strtol(v, NULL, 0);
        if(strncmp(k, "exptime", 7)) it->exptime = strtol(v, NULL, 0);
        if(strncmp(k, "flags", 5)) it->flags= strtol(v, NULL, 0);
        if(strncmp(k, "key", 3)) strncpy(it->key, v, strlen(v));
        if(strncmp(k, "data", 4)) strncpy(it->data, v, ndata);
    }
    *item = it;
    freeReplyObject(reply);
    return ENGINE_SUCCESS;
}

static const engine_info* redis_get_info(ENGINE_HANDLE* handle) {
   static engine_info info = {
      .description = "REDIS engine v0.1",
      .num_features = 0
   };

   return &info;
}

static ENGINE_ERROR_CODE redis_item_delete(ENGINE_HANDLE* handle,
                                        const void* cookie,
                                        const void* key,
                                        const size_t nkey,
                                        uint64_t cas,
                                        uint16_t vbucket) {
   return ENGINE_KEY_ENOENT;
}

static ENGINE_ERROR_CODE redis_get_stats(ENGINE_HANDLE* handle,
                                      const void* cookie,
                                      const char* stat_key,
                                      int nkey,
                                      ADD_STAT add_stat) {
   return ENGINE_SUCCESS;
}

static ENGINE_ERROR_CODE redis_flush(ENGINE_HANDLE* handle,
                                  const void* cookie, time_t when) {

   return ENGINE_SUCCESS;
}

static void redis_reset_stats(ENGINE_HANDLE* handle, const void *cookie) {

}

static ENGINE_ERROR_CODE redis_unknown_command(ENGINE_HANDLE* handle,
                                            const void* cookie,
                                            protocol_binary_request_header *request,
                                            ADD_RESPONSE response) {
   return ENGINE_ENOTSUP;
}

static void redis_item_set_cas(ENGINE_HANDLE *handle, const void *cookie,
                            item* item, uint64_t val){

}


MEMCACHED_PUBLIC_API ENGINE_ERROR_CODE create_instance(uint64_t interface, GET_SERVER_API get_server_api, 
        ENGINE_HANDLE **handle) {

            if (interface == 0) return ENGINE_ENOTSUP;
            struct redis_engine *h = calloc(1, sizeof(*h));
            if (h == NULL) return ENGINE_ENOMEM;
            h->engine.interface.interface = 1;

            /* command handlers */
            h->engine.initialize = redis_initialize;
            h->engine.destroy = redis_destroy;
            h->engine.get_info = redis_get_info;
            h->engine.allocate = redis_allocate;
            h->engine.remove = redis_item_delete;
            h->engine.release = redis_item_release;
            h->engine.get = redis_get;
            h->engine.get_stats = redis_get_stats;
            h->engine.reset_stats = redis_reset_stats;
            h->engine.store = redis_store;
            h->engine.flush = redis_flush;
            h->engine.unknown_command = redis_unknown_command;
            h->engine.item_set_cas = redis_item_set_cas;
            h->engine.get_item_info = redis_get_item_info;

            *handle = (ENGINE_HANDLE *) h;
            return ENGINE_SUCCESS;
}

