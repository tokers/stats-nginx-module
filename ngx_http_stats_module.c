
/*
 * Copyright (C) Alex Zhang
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_STATS_VAR_ACCUMULATE  0
#define NGX_HTTP_STATS_VAR_INTACT      1

#define NGX_HTTP_STATS_ECHO_RAW        0
#define NGX_HTTP_STATS_ECHO_HTML       1
#define NGX_HTTP_STATS_ECHO_JSON       2

#define NGX_HTTP_STATS_DELIMITER      "\t"


static ngx_str_t ngx_http_stats_var_accumulate = ngx_string("a");
static ngx_str_t ngx_http_stats_var_intact = ngx_string("i");

typedef struct ngx_http_stats_op_s  ngx_http_stats_op_t;

typedef u_char *(*ngx_http_stats_op_run_pt) (ngx_http_request_t *r, u_char *buf,
    ngx_http_stats_op_t *op, size_t *size);
typedef size_t (*ngx_http_stats_op_getlen_pt) (ngx_http_request_t *r,
    uintptr_t data);


struct ngx_http_stats_op_s {
    size_t                       len;
    uint8_t                      type;
    ngx_http_stats_op_getlen_pt  getlen;
    ngx_http_stats_op_run_pt     run;
    uintptr_t                    data;
};


typedef struct {
    ngx_str_t                    name;
    ngx_array_t                 *ops;    /* array of ngx_http_stats_op_t */
    uint32_t                     hash;
} ngx_http_stats_format_t;


typedef struct {
    off_t                        numeric;
    uint32_t                     len;
    uint8_t                      type;
    u_char                       data[1];
} ngx_http_stats_node_item_t;


typedef struct {
    u_char                       color;
    u_char                       dummy;
    uint32_t                     fmt_hash;
    ngx_queue_t                  queue;
    u_short                      item_count;
    u_short                      len;
    u_char                       data[1];
} ngx_http_stats_node_t;


typedef struct {
    ngx_rbtree_t                 rbtree;
    ngx_rbtree_node_t            sentinel;
    ngx_queue_t                  queue;
    size_t                       total_size;
    uint32_t                     count;
    uint8_t                      version;
} ngx_http_stats_shctx_t;


typedef struct {
    ngx_http_stats_shctx_t      *sh;
    ngx_slab_pool_t             *shpool;

    ngx_http_complex_value_t     key;

    ngx_http_stats_format_t     *fmt;
} ngx_http_stats_ctx_t;


typedef struct {
    ngx_shm_zone_t              *shm_zone;
} ngx_http_stats_t;


typedef struct {
    ngx_array_t                  stats;   /* array of ngx_http_stats_t */
    ngx_array_t                  formats; /* array of ngx_http_stats_format_t */
    ngx_uint_t                   fmt;
    ngx_shm_zone_t              *shm_zone;
    ngx_http_complex_value_t    *echo_key;

    unsigned                     clear:1;
} ngx_http_stats_conf_t;


static ngx_int_t ngx_http_stats_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_stats_echo_handler(ngx_http_request_t *r);
static void ngx_http_stats_echo_walk(ngx_log_t *log, ngx_rbtree_node_t *node,
    ngx_buf_t *buf, ngx_http_stats_ctx_t *ctx, ngx_uint_t clear);
static ngx_int_t ngx_http_stats_echo_walk_specific(ngx_pool_t *pool,
    ngx_buf_t **buf, ngx_http_stats_ctx_t *ctx, ngx_str_t *key,
    ngx_uint_t clear);
static ngx_int_t ngx_http_stats_lookup(ngx_http_request_t *r,
    ngx_http_stats_t *stats, ngx_uint_t hash, ngx_str_t *key);
static ngx_int_t ngx_http_stats_node_merge(ngx_http_request_t *r,
    ngx_http_stats_t *stats, ngx_http_stats_node_t *node);
static void ngx_http_stats_expire(ngx_http_stats_ctx_t *ctx, ngx_uint_t n);
static ngx_int_t ngx_http_stats_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static u_char *ngx_http_stats_copy_short(ngx_http_request_t *r, u_char *buf,
    ngx_http_stats_op_t *op, size_t *size);
static u_char *ngx_http_stats_copy_long(ngx_http_request_t *r, u_char *buf,
    ngx_http_stats_op_t *op, size_t *size);
static u_char *ngx_http_stats_variable(ngx_http_request_t *r, u_char *buf,
    ngx_http_stats_op_t *op, size_t *size);
static void ngx_http_stats_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_stats_variable_compile(ngx_conf_t *cf,
    ngx_http_stats_op_t *op, ngx_str_t *value);
static ngx_int_t ngx_http_stats_check_var_mark(ngx_str_t *mark);
static char *ngx_http_stats_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_stats(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_stats_format(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static size_t ngx_http_stats_variable_getlen(ngx_http_request_t *r,
    uintptr_t data);
static char *ngx_http_stats_compile_format(ngx_conf_t *cf, ngx_array_t *flushes,
    ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s);
static char *ngx_http_stats_echo(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_stats_create_conf(ngx_conf_t *cf);
static char *ngx_http_stats_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_stats_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_stats_commands[] = {

    { ngx_string("stats_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_stats_zone,
      0,
      0,
      NULL },

    { ngx_string("stats"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_stats,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("stats_format"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_stats_format,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("stats_echo"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|
      NGX_CONF_TAKE1234|NGX_CONF_NOARGS,
      ngx_http_stats_echo,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_stats_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_stats_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_stats_create_conf,            /* create location configuration */
    ngx_http_stats_merge_conf,             /* merge location configuration */
};


ngx_module_t  ngx_http_stats_module = {
    NGX_MODULE_V1,
    &ngx_http_stats_module_ctx,            /* module context */
    ngx_http_stats_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_http_stats_echo_walk(ngx_log_t *log, ngx_rbtree_node_t *node,
    ngx_buf_t *buf, ngx_http_stats_ctx_t *ctx, ngx_uint_t clear)
{
    u_char                      *p, *q, *s;
    size_t                       numeric_len, numeric;
    ngx_int_t                    i;
    ngx_http_stats_node_t       *snode;
    ngx_http_stats_node_item_t  *item;

    if (node == ctx->sh->rbtree.sentinel) {
        return;
    }

    snode = (ngx_http_stats_node_t *) &node->color;

    p = buf->last;

    p = ngx_cpymem(p, snode->data, snode->len);
    p = ngx_cpymem(p, NGX_HTTP_STATS_DELIMITER,
                   sizeof(NGX_HTTP_STATS_DELIMITER) - 1);

    q = snode->data + snode->len;

    for (i = 0; i < snode->item_count; i++) {

        item = (ngx_http_stats_node_item_t *) q;

#if (NGX_DEBUG)

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http stats echo walk found item: 0x%Xp", item);

#endif

        if (item->type == NGX_HTTP_STATS_VAR_ACCUMULATE) {
            numeric = item->numeric;
            numeric_len = 0;

            if (numeric == 0) {
                numeric_len = 1;
                *p++ = '0';
            }

            while (numeric > 0) {
                numeric_len++;
                numeric /= 10;
            }

            s = p;
            numeric = item->numeric;

            while (numeric > 0) {
                *(s + numeric_len - 1) = (numeric % 10) + '0';
                numeric /= 10;

                p++;
                numeric_len--;
            }

            q += sizeof(ngx_http_stats_node_item_t);

            if (clear) {
                item->numeric = 0;
            }

        } else {
            p = ngx_cpymem(p, item->data, item->len);
            q = item->data + item->len;
        }
    }

    *p++ = '\n';

    buf->last = p;

    ngx_http_stats_echo_walk(log, node->left, buf, ctx, clear);
    ngx_http_stats_echo_walk(log, node->right, buf, ctx, clear);
}


static ngx_int_t
ngx_http_stats_echo_walk_specific(ngx_pool_t *pool, ngx_buf_t **buf,
    ngx_http_stats_ctx_t *ctx, ngx_str_t *key, ngx_uint_t clear)
{
    u_char                      *p, *q, *s;
    ngx_int_t                    i, rc;
    size_t                       size, numeric;
    uint32_t                     hash;
    ngx_rbtree_node_t           *node;
    ngx_rbtree_node_t           *sentinel;
    ngx_http_stats_node_t       *snode;
    ngx_http_stats_node_item_t  *item;

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, key->data, key->len);
    ngx_crc32_update(&hash, (u_char *) &ctx->sh->version, 1);
    ngx_crc32_final(hash);

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        snode = (ngx_http_stats_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, snode->data, key->len, snode->len);
        if (rc != 0) {
            node = rc < 0 ? node->left : node->right;
            continue;
        }

        /* rc == 0 */

        p = snode->data + snode->len;

        size = snode->len + sizeof(NGX_HTTP_STATS_DELIMITER) - 1;

        for (i = 0; i < snode->item_count; i++) {

            item = (ngx_http_stats_node_item_t *) p;

            if (item->type == NGX_HTTP_STATS_VAR_ACCUMULATE) {
                size += NGX_SIZE_T_LEN;
                p += sizeof(ngx_http_stats_node_item_t);

            } else {
                size += item->len;
                p = item->data + item->len;
            }
        }

        size += sizeof("\n") - 1;

        *buf = ngx_create_temp_buf(pool, size);
        if (*buf == NULL) {
            return NGX_ERROR;
        }

        p = snode->data + snode->len;
        q = (*buf)->last;

        q = ngx_cpymem(q, snode->data, snode->len);
        q = ngx_cpymem(q, NGX_HTTP_STATS_DELIMITER,
                       sizeof(NGX_HTTP_STATS_DELIMITER) - 1);

        for (i = 0; i < snode->item_count; i++) {

            item = (ngx_http_stats_node_item_t *) p;
            if (item->type == NGX_HTTP_STATS_VAR_ACCUMULATE) {

                size = 0;
                numeric = item->numeric;

                if (numeric == 0) {
                    *q++ = '0';
                    size = 1;
                }

                while (numeric > 0) {
                    size++;
                    numeric /= 10;
                }

                numeric = item->numeric;

                s = q;

                while (numeric > 0) {
                    *(s + size - 1) = numeric % 10 + '0';
                    numeric /= 10;
                    size--;
                    q++;
                }

                p += sizeof(ngx_http_stats_node_item_t);

                if (clear) {
                    item->numeric = 0;
                }

            } else {
                q = ngx_cpymem(q, item->data, item->len);
                p = item->data + item->len;
            }
        }

        *q++ = '\n';

        (*buf)->last = q;

        return NGX_OK;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_stats_echo_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc, clear;
    ngx_str_t                 key;
    ngx_chain_t               cl;
    ngx_buf_t                 special;
    ngx_rbtree_node_t        *root;
    ngx_shm_zone_t           *shm_zone;
    ngx_http_stats_conf_t    *scf;
    ngx_http_stats_ctx_t     *ctx;
    ngx_http_complex_value_t *cv;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    scf = ngx_http_get_module_loc_conf(r, ngx_http_stats_module);

    clear = scf->clear;

    key.len = 0;

    cv = scf->echo_key;
    if (cv != NULL) {
        if (ngx_http_complex_value(r, cv, &key) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    r->headers_out.status = NGX_HTTP_OK;

    switch (scf->fmt) {

    case NGX_HTTP_STATS_ECHO_RAW:
        ngx_str_set(&r->headers_out.content_type, "text/plain");
        break;

    default:
        break;
    }

    cl.next = NULL;

    shm_zone = scf->shm_zone;
    ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    if (ctx->sh->count == 0) {
        ngx_memzero(&special, sizeof(ngx_buf_t));
        cl.buf = &special;

        goto send;
    }

    if (key.len == 0) {
        cl.buf = ngx_create_temp_buf(r->pool, ctx->sh->total_size);
        if (cl.buf == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        root = ctx->sh->rbtree.root;

        ngx_http_stats_echo_walk(r->connection->log, root, cl.buf, ctx, clear);

    } else {
        rc = ngx_http_stats_echo_walk_specific(r->pool, &cl.buf, ctx, &key,
                                               clear);
        if (rc == NGX_ERROR) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rc == NGX_DECLINED) {
            /* not found */
            ngx_memzero(&special, sizeof(ngx_buf_t));
            cl.buf = &special;
        }
    }

send:

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    if (r == r->main) {
        cl.buf->last_buf = 1;

    } else {
        cl.buf->last_in_chain = 1;
    }

    r->headers_out.content_length_n = ngx_buf_size(cl.buf);
    if (r->headers_out.content_length_n == 0) {

        /* XXX this is a special buf,
         * so erase flags about in memory and in file
         */

        cl.buf->temporary = 0;
        cl.buf->memory = 0;
        cl.buf->mmap = 0;
        cl.buf->in_file = 0;
    }

#if (NGX_DEBUG)

    ngx_str_t debug_str;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http stats echo got buf: 0x%xp, size: %uz",
                   cl.buf, ngx_buf_size(cl.buf));

    debug_str.data = cl.buf->pos;
    debug_str.len = ngx_buf_size(cl.buf);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http stats echo got \"%V\"",
                   &debug_str);

#endif

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &cl);
}


static ngx_int_t
ngx_http_stats_handler(ngx_http_request_t *r)
{
    ngx_uint_t                i;
    ngx_int_t                 rc;
    uint32_t                  hash;
    ngx_str_t                 key;
    ngx_shm_zone_t           *shm_zone;
    ngx_http_stats_t         *stats;
    ngx_http_stats_ctx_t     *ctx;
    ngx_http_stats_conf_t    *scf;

    scf = ngx_http_get_module_loc_conf(r, ngx_http_stats_module);

    stats = scf->stats.elts;

    for (i = 0; i < scf->stats.nelts; i++) {

        shm_zone = stats[i].shm_zone;
        ctx = shm_zone->data;

        if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
            return NGX_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 65535) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "the value of \"%V\" key "
                          "is more than 65535 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        ngx_crc32_init(hash);
        ngx_crc32_update(&hash, key.data, key.len);
        ngx_crc32_update(&hash, (u_char *) &ctx->sh->version, 1);
        ngx_crc32_final(hash);

        ngx_shmtx_lock(&ctx->shpool->mutex);

        rc = ngx_http_stats_lookup(r, &stats[i], hash, &key);

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_stats_node_merge(ngx_http_request_t *r, ngx_http_stats_t *stats,
    ngx_http_stats_node_t *node)
{
    u_char                     *p, *q;
    off_t                       value;
    size_t                      size, len;
    ngx_int_t                   i;
    ngx_str_t                   temp;
    ngx_http_stats_op_t        *ops;
    ngx_http_stats_ctx_t       *ctx;
    ngx_http_stats_node_item_t *item;

#if (NGX_DEBUG)

    ngx_str_t                   debug_str;

#endif

    ctx = stats->shm_zone->data;

    if (ctx->fmt->hash != node->fmt_hash) {
        return NGX_DECLINED;
    }

    ops = ctx->fmt->ops->elts;

    p = node->data + node->len;

    size = 0;

    for (i = 0; i < node->item_count; i++) {

        item = (ngx_http_stats_node_item_t *) p;

        if (ops[i].type != item->type) {
            return NGX_DECLINED;
        }

        if (ops[i].len) {
            len = ops[i].len;

        } else {
            len = ops[i].getlen(r, ops[i].data);
        }

        if (size < len) {
            size = len;
        }

        if (ops[i].type != NGX_HTTP_STATS_VAR_ACCUMULATE) {
            p = item->data + item->len;

        } else {
            p += sizeof(ngx_http_stats_node_item_t);
        }
    }

    temp.data = ngx_palloc(r->pool, size);
    if (temp.data == NULL) {
        return NGX_ERROR;
    }

    p = node->data + node->len;

    for (i = 0; i < node->item_count; i++) {

        item = (ngx_http_stats_node_item_t *) p;

        q = ops[i].run(r, temp.data, &ops[i], &temp.len);
        if (q == NULL) {
            return NGX_ERROR;
        }

        if (ops[i].type == NGX_HTTP_STATS_VAR_ACCUMULATE) {

            value = ngx_atoof(temp.data, temp.len);
            if (value == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "could not convert \"%V\" to numeric", temp);
                return NGX_ERROR;
            }

            item->numeric += value;

#if (NGX_DEBUG)

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http stats merged numeric value: %uz, item: 0x%xp",
                            item->numeric, item);

#endif
        } else {
#if (NGX_DEBUG)

            debug_str.len = item->len;
            debug_str.data = item->data;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http stats kept literal: \"%V\", item: 0x%xp",
                            &debug_str, item);

#endif
        }

        if (ops[i].type != NGX_HTTP_STATS_VAR_ACCUMULATE) {
            p = item->data + item->len;

        } else {
            p += sizeof(ngx_http_stats_node_item_t);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_stats_lookup(ngx_http_request_t *r, ngx_http_stats_t *stats,
    ngx_uint_t hash, ngx_str_t *key)
{
    u_char                      *p;
    ngx_int_t                    rc;
    ngx_uint_t                   i;
    ngx_str_t                    temp;
    size_t                       size, len, total_size;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_stats_ctx_t        *ctx;
    ngx_http_stats_node_t       *snode;
    ngx_http_stats_op_t         *ops, op;
    ngx_http_stats_node_item_t  *item;

    static u_char                s[NGX_SIZE_T_LEN];

    ctx = stats->shm_zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        snode = (ngx_http_stats_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, snode->data, key->len, snode->len);
        if (rc == 0) {
            ngx_queue_remove(&snode->queue);
            ngx_queue_insert_head(&ctx->sh->queue, &snode->queue);

            rc = ngx_http_stats_node_merge(r, stats, snode);
            if (rc == NGX_ERROR || rc == NGX_OK) {
                return rc;
            }

            /* rc == NGX_DECLINED or rc == NGX_ABORT */

            ngx_crc32_init(hash);
            ngx_crc32_update((uint32_t *) &hash, key->data, key->len);
            ngx_crc32_update((uint32_t *) &hash, (u_char *) &ctx->sh->version,
                             1);
            ngx_crc32_final(hash);

            break;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    ops = ctx->fmt->ops->elts;

    len = 0;
    total_size = 0;

    for (i = 0; i < ctx->fmt->ops->nelts; i++) {

        len += sizeof(ngx_http_stats_node_item_t);

        op = ops[i];
        if (op.type == NGX_HTTP_STATS_VAR_ACCUMULATE) {
            total_size += NGX_SIZE_T_LEN;
            continue;
        }

        if (op.len) {
            size = op.len;

        } else {
            size = op.getlen(r, op.data);
        }

        len += size;
        total_size += size;
    }

    total_size += key->len;

    total_size += sizeof(NGX_HTTP_STATS_DELIMITER) - 1 + sizeof("\n") - 1;

    size = offsetof(ngx_rbtree_node_t, color)
           + offsetof(ngx_http_stats_node_t, data)
           + key->len
           + len;

    ngx_http_stats_expire(ctx, 1);

    node = ngx_slab_alloc_locked(ctx->shpool, size);
    if (node == NULL) {
        ngx_http_stats_expire(ctx, 0);

        node = ngx_slab_alloc_locked(ctx->shpool, size);
        if (node == NULL) {
            ngx_log_error(NGX_LOG_ALERT,  r->connection->log, 0,
                          "could not allocate node%s", ctx->shpool->log_ctx);
            return NGX_ERROR;
        }
    }

    node->key = hash;
    snode = (ngx_http_stats_node_t *) &node->color;

    snode->len = key->len;
    ngx_memcpy(snode->data, key->data, snode->len);

    snode->item_count = ctx->fmt->ops->nelts;
    snode->fmt_hash = ctx->fmt->hash;

    p = snode->data + snode->len;

    for (i = 0; i < ctx->fmt->ops->nelts; i++) {

        op = ops[i];

        item = (ngx_http_stats_node_item_t *) p;

        item->type = op.type;

        if (op.type == NGX_HTTP_STATS_VAR_ACCUMULATE) {

            (void) op.run(r, s, &op, &size);

            item->len = 0;

            item->numeric = ngx_atoof(s, size);
            if (item->numeric == NGX_ERROR) {
                temp.data = p;
                temp.len = size;

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "could not convert \"%V\" to numeric", temp);

                goto failed;
            }

#if (NGX_DEBUG)

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http stats got numeric: %uz, item: 0x%xp",
                           item->numeric, item);
#endif

            p += sizeof(ngx_http_stats_node_item_t);

            continue;
        }

        /* op->type == NGX_HTTP_STATS_VAR_INTACT */

        p = op.run(r, item->data, &op, &size);

        item->len = size;
        item->numeric = -1;

#if (NGX_DEBUG)

        temp.data = item->data;
        temp.len = item->len;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http stats got literal: \"%V\", item: 0x%xp",
                       &temp, item);
#endif

    }

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->queue, &snode->queue);

    ctx->sh->count++;
    ctx->sh->total_size += total_size;

    return NGX_OK;

failed:

    ngx_slab_free_locked(ctx->shpool, node);

    return NGX_ERROR;
}


static void
ngx_http_stats_expire(ngx_http_stats_ctx_t *ctx, ngx_uint_t n)
{
    ngx_queue_t           *q;
    ngx_rbtree_node_t     *node;
    ngx_http_stats_node_t *snode;
    /*
     * n == 1 deletes one or two zero rate entries
     * n == 0 deletes oldest entry by force
     *        and one or two zero rate entries
     */

    while (n < 3) {

        if (ngx_queue_empty(&ctx->sh->queue)) {
            return;
        }

        q = ngx_queue_last(&ctx->sh->queue);

        snode = ngx_queue_data(q, ngx_http_stats_node_t, queue);

        if (++n != 0 && snode->item_count > 0) {
            return;
        }

        ngx_queue_remove(q);

        node = (ngx_rbtree_node_t *)
                        ((u_char *) snode - offsetof(ngx_rbtree_node_t, color));

        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        ngx_slab_free_locked(ctx->shpool, node);

        ctx->sh->count--;
    }
}


static char *
ngx_http_stats_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                           *p;
    ssize_t                           size;
    ngx_uint_t                        i, n;
    ngx_str_t                        *value, name, s, fmt_name;
    ngx_shm_zone_t                   *shm_zone;
    ngx_http_stats_ctx_t             *ctx;
    ngx_http_stats_conf_t            *scf;
    ngx_http_stats_format_t          *fmt, *formats;
    ngx_http_compile_complex_value_t  ccv;

    value = cf->args->elts;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_stats_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    scf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_stats_module);

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    fmt = NULL;
    size = 0;
    name.len = 0;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');
            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);
            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            /* mimic ngx_http_limit_req_module */
            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "format=", 7) == 0) {

            fmt_name.len = value[i].len - 7;
            fmt_name.data = value[i].data + 7;

            formats = scf->formats.elts;

            for (n = 0; n < scf->formats.nelts; n++) {

                if (formats[n].name.len == fmt_name.len
                    && ngx_strncmp(formats[n].name.data, fmt_name.data,
                                   fmt_name.len)
                    == 0)
                {
                    fmt = &formats[n];
                    break;
                }

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid format \"%V\"", &name);
                return NGX_CONF_ERROR;
            }
        }
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    if (fmt == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"format\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_stats_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &name, &ctx->key.value);
        return NGX_CONF_ERROR;
    }

    ctx->fmt = fmt;

    shm_zone->init = ngx_http_stats_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_stats(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_stats_conf_t *scf = conf;

    ngx_uint_t               i;
    ngx_str_t               *value, s;
    ngx_shm_zone_t          *shm_zone;
    ngx_http_stats_t        *stats, *cur;

    shm_zone = NULL;
    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            shm_zone = ngx_shared_memory_add(cf, &s, 0, &ngx_http_stats_module);
            if (shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }
    }

    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    stats = scf->stats.elts;
    if (stats == NULL) {
        if (ngx_array_init(&scf->stats, cf->pool, 1,
                           sizeof(ngx_http_stats_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        stats = scf->stats.elts;
    }

    for (i = 0; i < scf->stats.nelts; i++) {
        if (stats[i].shm_zone == shm_zone) {
            return "is duplicate";
        }
    }

    cur = ngx_array_push(&scf->stats);
    if (cur == NULL) {
        return NGX_CONF_ERROR;
    }

    cur->shm_zone = shm_zone;

    return NGX_CONF_OK;
}


static char *
ngx_http_stats_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_stats_conf_t *scf = conf;

    u_char                   *buf, *p;
    char                     *conf_rc;
    size_t                    size;
    ngx_uint_t                i;
    ngx_str_t                *value;
    ngx_http_stats_format_t  *fmt;

    value = cf->args->elts;

    fmt = scf->formats.elts;
    if (fmt == NULL) {
        if (ngx_array_init(&scf->formats, cf->pool, 1,
                           sizeof(ngx_http_stats_format_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        fmt = scf->formats.elts;
    }

    for (i = 0; i < scf->formats.nelts; i++) {
        if (fmt[i].name.len == value[1].len
            && ngx_strcmp(fmt[i].name.data, value[1].data) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"stats_format\" name \"%V\"",
                               &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    fmt = ngx_array_push(&scf->formats);
    if (fmt == NULL) {
        return NGX_CONF_ERROR;
    }

    fmt->name = value[1];
    fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_http_stats_op_t));
    if (fmt->ops == NULL) {
        return NGX_CONF_ERROR;
    }

    conf_rc = ngx_http_stats_compile_format(cf, NULL, fmt->ops, cf->args, 2);
    if (conf_rc != NGX_CONF_OK) {
        return conf_rc;
    }

    /* NGX_CONF_OK */

    value = cf->args->elts;

    for (size = 0, i = 2; i < cf->args->nelts; i++) {
        size += value[i].len;
    }

    buf = ngx_alloc(size, cf->log);
    if (buf == NULL) {
        return NGX_CONF_ERROR;
    }

    p = buf;

    for (i = 2; i < cf->args->nelts; i++) {
        buf = ngx_cpymem(buf, value[i].data, value[i].len);
    }

    fmt->hash = ngx_murmur_hash2(p, size);

    ngx_free(p);

    return NGX_CONF_OK;
}


static char *
ngx_http_stats_compile_format(ngx_conf_t *cf, ngx_array_t *flushes,
    ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s)
{
    u_char                ch, *data, *p;
    size_t                i, len;
    ngx_int_t             mark;
    ngx_uint_t            bracket;
    ngx_str_t            *value, var, type, debug_str;
    ngx_http_stats_op_t  *op;

    value = args->elts;

    mark = 0;

    for ( /* void */ ; s < args->nelts; s++) {

        i = 0;

        while (i < value[s].len) {

            op = ngx_array_push(ops);
            if (op == NULL) {
                return NGX_CONF_ERROR;
            }

            data = value[s].data + i;

            if (value[s].data[i] == '$') {
                if (++i == value[s].len) {
                    goto invalid;
                }

                if (value[s].data[i] == '{') {
                    bracket = 1;
                    mark = 0;

                    if (++i == value[s].len) {
                        goto invalid;
                    }

                    var.data = value[s].data + i;

                } else {
                    bracket = 0;
                    var.data = value[s].data + i;
                    type = ngx_http_stats_var_accumulate;
                }

                for (var.len = 0; i < value[s].len; i++) {
                    ch = value[s].data[i];
                    if (ch == '}' && bracket) {
                        i++;
                        bracket = 0;

                        if (mark) {
                            mark = 0;

                            if (type.len == 0) {
                                goto invalid;
                            }
                        }

                        break;
                    }

                    if (mark) {
                        if (type.len == 0) {
                            type.data = value[s].data + i;
                        }

                        type.len++;

                        continue;
                    }

                    if ((ch >= 'A' && ch <= 'Z')
                        || (ch >= 'a' && ch <= 'z')
                        || (ch >= '0' && ch <= '9')
                        || (ch == '_'))
                    {
                        var.len++;
                        continue;
                    }

                    /* we use the our own format ${var:type} to mark whether
                     * this variable should be accumulated or kept intact or
                     * just cover the previous value
                     */
                    if (bracket && ch == ':') {
                        mark = 1;
                        type.len = 0;

                        continue;
                    }

                    break;
                }

                if (bracket) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "the closing bracket in \"%V\" "
                                       "variable is missing", &var);
                    return NGX_CONF_ERROR;
                }

                if (var.len == 0) {
                    goto invalid;
                }

                mark = ngx_http_stats_check_var_mark(&type);

                if (mark < NGX_HTTP_STATS_VAR_ACCUMULATE) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid variable mark \"%V\"in "
                                       "\"${%V:%V}\"",
                                       &type, &var, &type);
                    return NGX_CONF_ERROR;
                }

                op->type = mark;

                if (ngx_http_stats_variable_compile(cf, op, &var)
                    != NGX_OK)
                {
                    return NGX_CONF_ERROR;
                }

                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                                   "http stats var \"%V\", index: %d, type: %d",
                                    &var, op->data, mark);

                continue;
            }

            i++;

            while (i < value[s].len && value[s].data[i] != '$') {
                i++;
            }

            len = &value[s].data[i] - data;
            if (len) {
                debug_str.len = len;
                debug_str.data = data;

                op->len = len;
                op->getlen = NULL;
                op->type = NGX_HTTP_STATS_VAR_INTACT;

                if (len <= sizeof(uintptr_t)) {
                    op->run = ngx_http_stats_copy_short;
                    op->data = 0;

                    while (len--) {
                        op->data <<= 8;
                        op->data |= data[len];
                    }

                } else {
                    op->run = ngx_http_stats_copy_long;

                    p = ngx_pnalloc(cf->pool, len);
                    if (p == NULL) {
                        return NGX_CONF_ERROR;
                    }

                    ngx_memcpy(p, data, len);
                    op->data = (uintptr_t) p;
                }

                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                                   "http stats get literal: \"%V\", type: %d",
                                   &debug_str, op->type);
            }
        }
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

    return NGX_CONF_ERROR;
}


static void
ngx_http_stats_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t     **p;
    ngx_http_stats_node_t  *snode, *snodet;

    for ( ;; ) {

        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {
            snode = (ngx_http_stats_node_t *) &node->color;
            snodet = (ngx_http_stats_node_t *) &temp->color;

            p = (ngx_memn2cmp(snode->data, snodet->data, snode->len,
                              snodet->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}



static ngx_inline ngx_int_t
ngx_http_stats_check_var_mark(ngx_str_t *mark)
{
    if (mark->len == ngx_http_stats_var_accumulate.len
        && ngx_strncmp(mark->data, ngx_http_stats_var_accumulate.data,
                       mark->len)
        == 0)
    {
        return NGX_HTTP_STATS_VAR_ACCUMULATE;
    }

    if (mark->len == ngx_http_stats_var_intact.len
        && ngx_strncmp(mark->data, ngx_http_stats_var_intact.data, mark->len)
        == 0)
    {
        return NGX_HTTP_STATS_VAR_INTACT;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_stats_variable_compile(ngx_conf_t *cf, ngx_http_stats_op_t *op,
    ngx_str_t *value)
{
    ngx_int_t  index;

    index = ngx_http_get_variable_index(cf, value);
    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    op->len = 0;
    op->getlen = ngx_http_stats_variable_getlen;
    op->run = ngx_http_stats_variable;
    op->data = index;

    return NGX_OK;
}


static size_t
ngx_http_stats_variable_getlen(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t *value;

    value = ngx_http_get_indexed_variable(r, data);
    if (value == NULL || value->not_found) {
        return 0;
    }

    return value->len;
}


static u_char *
ngx_http_stats_copy_short(ngx_http_request_t *r, u_char *buf,
    ngx_http_stats_op_t *op, size_t *size)
{
    size_t    len;
    uintptr_t data;

    len = op->len;
    data = op->data;
    *size = len;

    while (len--) {
        *buf++ = (u_char) (data & 0xff);
        data >>= 8;
    }

    return buf;
}


static u_char *
ngx_http_stats_copy_long(ngx_http_request_t *r, u_char *buf,
    ngx_http_stats_op_t *op, size_t *size)
{
    *size = op->len;

    return ngx_cpymem(buf, (u_char *) op->data, op->len);
}


static u_char *
ngx_http_stats_variable(ngx_http_request_t *r, u_char *buf,
    ngx_http_stats_op_t *op, size_t *size)
{
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, op->data);
    if (value == NULL || value->not_found) {
        return NULL;
    }

    *size = value->len;

    return ngx_cpymem(buf, value->data, value->len);
}


static ngx_int_t
ngx_http_stats_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_stats_ctx_t *octx = data;

    size_t                 len;
    ngx_http_stats_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {

        if (ctx->key.value.len != octx->key.value.len
            || ngx_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "stats \"%V\" uses the \"%V\" key "
                          " while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return NGX_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        /* it's safe to compare the format hash and change ctx->sh->version,
         * since workers never change this.
         */
        if (ctx->fmt->hash != octx->fmt->hash) {
            ctx->sh->version++;
        }

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_stats_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_stats_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->queue);

    ctx->sh->total_size = 0;
    ctx->sh->count = 0;
    ctx->sh->version = 0;

    len = sizeof(" in stats zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in stats zone \"%V\"%Z",
                &shm_zone->shm.name);

    ctx->shpool->log_nomem = 0;

    return NGX_OK;
}


static char *
ngx_http_stats_echo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_stats_conf_t *scf = conf;

    ngx_uint_t                        i;
    ngx_str_t                        *value, key;
    ngx_shm_zone_t                   *shm_zone;
    ngx_http_core_loc_conf_t         *clcf;
    ngx_http_compile_complex_value_t  ccv;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->handler) {
        return "is duplicate";
    }

    scf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_stats_module);

    value = cf->args->elts;

    shm_zone = NULL;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "key=", 4) == 0) {
            key.data = value[i].data + 4;
            key.len = value[i].len - 4;

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            scf->echo_key = ngx_palloc(cf->pool,
                                       sizeof(ngx_http_complex_value_t));
            if (scf->echo_key == NULL) {
                return NGX_CONF_ERROR;
            }

            ccv.cf = cf;
            ccv.value = &key;
            ccv.complex_value = scf->echo_key;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

        if (ngx_strncmp(value[i].data, "format=", 7) == 0) {
            key.data = value[i].data + 7;
            key.len = value[i].len - 7;

            if (key.len == sizeof("json") - 1
                && ngx_strncmp(key.data, "json", sizeof("json") - 1) == 0)
            {
                scf->fmt = NGX_HTTP_STATS_ECHO_JSON;

            } else if (key.len == sizeof("html") - 1
                       && ngx_strncmp(key.data, "html", sizeof("html") - 1)
                       == 0)
            {
                scf->fmt = NGX_HTTP_STATS_ECHO_HTML;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid stats_echo format \"%V\"", &key);
                return NGX_CONF_ERROR;
            }
        }

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            key.data = value[i].data + 5;
            key.len = value[i].len - 5;

            shm_zone = ngx_shared_memory_add(cf, &key, 0,
                                             &ngx_http_stats_module);
            if (shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "clear", 5) == 0) {
            scf->clear = 1;
        }
    }

    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "command \"%V\" must have \"zone\" parameter");
        return NGX_CONF_ERROR;
    }

    scf->shm_zone = shm_zone;

    clcf->handler = ngx_http_stats_echo_handler;

    return NGX_CONF_OK;
}


static void *
ngx_http_stats_create_conf(ngx_conf_t *cf)
{
    ngx_http_stats_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_stats_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     * conf->stats.elts = NULL;
     * conf->formats.elts = NULL;
     * conf->fmt = 0;
     * conf->clear = 0;
     * conf->shm_zone = NULL;
     * conf->echo_key = NULL;
     */

    return conf;
}


static char *
ngx_http_stats_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_stats_conf_t *prev = parent;
    ngx_http_stats_conf_t *conf = child;

    if (conf->stats.elts == NULL) {
        conf->stats = prev->stats;
    }

    if (conf->formats.elts == NULL) {
        conf->formats = prev->formats;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_stats_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt       *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_stats_handler;

    return NGX_OK;
}
