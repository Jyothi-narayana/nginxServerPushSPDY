/*
 * ngx_http_spdy_serverpush_filter_module.c
 *
 *  Created on: Oct 20, 2013
 *      Author: ashu
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include <ngx_http_spdy_module.h>
#include <ngx_http_request.h>
#include <zlib.h>
#define NGX_SPDY_WRITE_BUFFERED  NGX_HTTP_WRITE_BUFFERED

#define ngx_http_spdy_nv_nsize(h)  (NGX_SPDY_NV_NLEN_SIZE + sizeof(h) - 1)
#define ngx_http_spdy_nv_vsize(h)  (NGX_SPDY_NV_VLEN_SIZE + sizeof(h) - 1)

#define ngx_http_spdy_nv_write_num   ngx_spdy_frame_write_uint16
#define ngx_http_spdy_nv_write_nlen  ngx_spdy_frame_write_uint16
#define ngx_http_spdy_nv_write_vlen  ngx_spdy_frame_write_uint16


#define ngx_http_spdy_nv_write_name(p, h)                                     \
    ngx_cpymem(ngx_http_spdy_nv_write_nlen(p, sizeof(h) - 1), h, sizeof(h) - 1)

#define ngx_http_spdy_nv_write_val(p, h)                                      \
    ngx_cpymem(ngx_http_spdy_nv_write_vlen(p, sizeof(h) - 1), h, sizeof(h) - 1)

#define ngx_http_spdy_stream_index(sscf, sid)                                 \
    ((sid >> 1) & sscf->streams_index_mask)



static ngx_inline ngx_int_t ngx_http_spdy_serverpush_filter_send(
    ngx_connection_t *fc, ngx_http_spdy_stream_t *stream);

static ngx_http_spdy_out_frame_t *ngx_http_spdy_filter_get_data_frame(
    ngx_http_spdy_stream_t *stream, size_t len, ngx_uint_t flags,
    ngx_chain_t *first, ngx_chain_t *last);

static ngx_http_spdy_stream_t *ngx_http_spdy_create_stream(
    ngx_http_spdy_connection_t *sc, ngx_uint_t id, ngx_uint_t priority);
static ngx_int_t ngx_http_spdy_syn_frame_handler(
    ngx_http_spdy_connection_t *sc, ngx_http_spdy_out_frame_t *frame);

static ngx_int_t ngx_http_spdy_data_frame_handler(
    ngx_http_spdy_connection_t *sc, ngx_http_spdy_out_frame_t *frame);

static ngx_inline void ngx_http_spdy_handle_frame(
    ngx_http_spdy_stream_t *stream, ngx_http_spdy_out_frame_t *frame);
static ngx_inline void ngx_http_spdy_handle_stream(
    ngx_http_spdy_connection_t *sc, ngx_http_spdy_stream_t *stream);

static void ngx_http_spdy_filter_cleanup(void *data);

static ngx_int_t ngx_http_spdy_serverpush_filter_init(ngx_conf_t *cf);

#if 1
static ngx_int_t even_stream_id = 0;
static ngx_int_t get_next_even_stream_id();
static ngx_http_spdy_stream_t *myStream;
static ngx_chain_t* myChain;
#endif


static ngx_int_t ngx_http_static_handler(ngx_http_request_t *r);
static ngx_http_module_t  ngx_http_spdy_serverpush_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_spdy_serverpush_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_spdy_serverpush_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_spdy_serverpush_filter_module_ctx,      /* module context */
    NULL,                                  /* module directives */
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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static u_char* value;
static size_t valueLen=0;


static ngx_int_t
ngx_http_spdy_serverpush_header_filter(ngx_http_request_t *r)
{
    int                           rc;
    size_t                        len;
    u_char                       *p, *buf, *last;
    ngx_buf_t                    *b;
    ngx_str_t                     host;
    ngx_uint_t                    i, j, count, port;
    ngx_chain_t                  *cl;
    ngx_list_part_t              *part, *pt;
    ngx_table_elt_t              *header, *h;
    ngx_connection_t             *c;
    ngx_http_cleanup_t           *cln;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_core_srv_conf_t     *cscf;
    ngx_http_spdy_stream_t       *stream;
    ngx_http_spdy_out_frame_t    *frame;
    ngx_http_spdy_connection_t   *sc;
    struct sockaddr_in           *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6          *sin6;
#endif
    u_char                        addr[NGX_SOCKADDR_STRLEN];
    ngx_int_t index=-1;
    if (!r->spdy_stream) {
        return ngx_http_next_header_filter(r);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy serverpush module header filter");

    if (r->header_sent) {
        return NGX_OK;
    }

    r->header_sent = 1;

    if (r != r->main) {
        return NGX_OK;
    }

    c = r->connection;
    part = &r->headers_out.headers.part;
    header = part->elts;
    int isSet = 0;
    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }
	 ngx_str_t xac = ngx_string("X-Associated-Content");
	if(ngx_strncmp(&header[i].key, &xac, 20) == 0 )
        {
	    isSet=1;
	    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "KEY-Value Pair:  \"%V\"  and   \"%V\"", &header[i].key,&header[i].value);
	    index=i;
	
  	    value=ngx_pstrdup(r->pool,&header[i].value);
	    /*int count1=17;
	    while(count1)
 	    {
		value++;
		count1--;
	    }
	    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "Value is : \"%s\" ", value);
	    valueLen=header[i].value.len - 17;*/
	    ngx_int_t countSlash=0;
	    ngx_int_t countLen=0;
	    while(*value!='\0' && countSlash!=3)
	    {	
		if(*value=='/')
			countSlash++;
		if(countSlash!=3)
			value++;
		countLen++;
	    }
	    countLen--;
	    valueLen=header[i].value.len - countLen;
	    if(index!=-1)
	    {
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		           "key-value : %d  and   %d", countLen,valueLen);
	    }
	}
    }
    if(!isSet)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy serverpush module header filter !isSet cond");
        return ngx_http_next_header_filter(r);
    }
    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }

    switch (r->headers_out.status) {

    case NGX_HTTP_OK:
    case NGX_HTTP_PARTIAL_CONTENT:
        break;

    case NGX_HTTP_NOT_MODIFIED:
        r->header_only = 1;
        break;

    case NGX_HTTP_NO_CONTENT:
        r->header_only = 1;

        ngx_str_null(&r->headers_out.content_type);

        r->headers_out.content_length = NULL;
        r->headers_out.content_length_n = -1;

        /* fall through */

    default:
        r->headers_out.last_modified_time = -1;
        r->headers_out.last_modified = NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy serverpush module header filter 2");

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "From header spdy body filter \"%V?%V\"", &r->uri, &r->args);

    len = NGX_SPDY_NV_NUM_SIZE
          + ngx_http_spdy_nv_nsize("version")
          + ngx_http_spdy_nv_vsize("HTTP/1.1")
          + ngx_http_spdy_nv_nsize("status")
          + ngx_http_spdy_nv_vsize("418");

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /*len += ngx_http_spdy_nv_nsize("url")
               +ngx_http_spdy_nv_vsize("https://localhost/test1.js");*/
    len += ngx_http_spdy_nv_nsize("url")
               +ngx_http_spdy_nv_vsize(&header[index].value);

    if (r->headers_out.server == NULL) {
        len += ngx_http_spdy_nv_nsize("server");
        len += clcf->server_tokens ? ngx_http_spdy_nv_vsize(NGINX_VER)
                                   : ngx_http_spdy_nv_vsize("nginx");
    }

    if (r->headers_out.date == NULL) {
        len += ngx_http_spdy_nv_nsize("date")
               + ngx_http_spdy_nv_vsize("Wed, 31 Dec 1986 10:00:00 GMT");
    }

    if (r->headers_out.content_type.len) {
        len += ngx_http_spdy_nv_nsize("content-type")
               + NGX_SPDY_NV_VLEN_SIZE + r->headers_out.content_type.len;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        len += ngx_http_spdy_nv_nsize("content-length")
               + NGX_SPDY_NV_VLEN_SIZE + NGX_OFF_T_LEN;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += ngx_http_spdy_nv_nsize("last-modified")
               + ngx_http_spdy_nv_vsize("Wed, 31 Dec 1986 10:00:00 GMT");
    }

    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        r->headers_out.location->hash = 0;

        if (clcf->server_name_in_redirect) {
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            host = cscf->server_name;

        } else if (r->headers_in.server.len) {
            host = r->headers_in.server;

        } else {
            host.len = NGX_SOCKADDR_STRLEN;
            host.data = addr;

            if (ngx_connection_local_sockaddr(c, &host, 0) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
            port = ntohs(sin6->sin6_port);
            break;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            port = 0;
            break;
#endif
        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;
            port = ntohs(sin->sin_port);
            break;
        }

        len += ngx_http_spdy_nv_nsize("location")
               + ngx_http_spdy_nv_vsize("https://")
               + host.len
               + r->headers_out.location->value.len;

        if (clcf->port_in_redirect) {

#if (NGX_HTTP_SSL)
            if (c->ssl)
                port = (port == 443) ? 0 : port;
            else
#endif
                port = (port == 80) ? 0 : port;

        } else {
            port = 0;
        }

        if (port) {
            len += sizeof(":65535") - 1;
        }

    } else {
        ngx_str_null(&host);
        port = 0;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy serverpush module header filter 3");

    part = &r->headers_out.headers.part;
    header = part->elts;
    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }
        len += NGX_SPDY_NV_NLEN_SIZE + header[i].key.len
               + NGX_SPDY_NV_VLEN_SIZE  + header[i].value.len;
    }

    buf = ngx_alloc(len, r->pool->log);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    last = buf + NGX_SPDY_NV_NUM_SIZE;

    last = ngx_http_spdy_nv_write_name(last, "version");
    last = ngx_http_spdy_nv_write_val(last, "HTTP/1.1");

    last = ngx_http_spdy_nv_write_name(last, "status");
    last = ngx_spdy_frame_write_uint16(last, 3);
    last = ngx_sprintf(last, "%03ui", r->headers_out.status);

    count = 2;
	
    last = ngx_http_spdy_nv_write_name(last, "url");
    //last = ngx_http_spdy_nv_write_val(last, "https://localhost/test1.js");
    #if 1
    last = ngx_http_spdy_nv_write_vlen(last, header[index].value.len);

    last = ngx_cpymem(last, header[index].value.data,
                          header[index].value.len);
    #endif
    count++;
    if (r->headers_out.server == NULL) {
        last = ngx_http_spdy_nv_write_name(last, "server");
        last = clcf->server_tokens
               ? ngx_http_spdy_nv_write_val(last, NGINX_VER)
               : ngx_http_spdy_nv_write_val(last, "nginx");

        count++;
    }

    if (r->headers_out.date == NULL) {
        last = ngx_http_spdy_nv_write_name(last, "date");

        last = ngx_http_spdy_nv_write_vlen(last, ngx_cached_http_time.len);

        last = ngx_cpymem(last, ngx_cached_http_time.data,
                          ngx_cached_http_time.len);

        count++;
    }

    if (r->headers_out.content_type.len) {

        last = ngx_http_spdy_nv_write_name(last, "content-type");

        p = last + NGX_SPDY_NV_VLEN_SIZE;

        last = ngx_cpymem(p, r->headers_out.content_type.data,
                          r->headers_out.content_type.len);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            last = ngx_cpymem(last, "; charset=", sizeof("; charset=") - 1);

            last = ngx_cpymem(last, r->headers_out.charset.data,
                              r->headers_out.charset.len);

            /* update r->headers_out.content_type for possible logging */

            r->headers_out.content_type.len = last - p;
            r->headers_out.content_type.data = p;
        }

        (void) ngx_http_spdy_nv_write_vlen(p - NGX_SPDY_NV_VLEN_SIZE,
                                           r->headers_out.content_type.len);

        count++;
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        last = ngx_http_spdy_nv_write_name(last, "content-length");

        p = last + NGX_SPDY_NV_VLEN_SIZE;

        last = ngx_sprintf(p, "%O", r->headers_out.content_length_n);

        (void) ngx_http_spdy_nv_write_vlen(p - NGX_SPDY_NV_VLEN_SIZE,
                                           last - p);

        count++;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        last = ngx_http_spdy_nv_write_name(last, "last-modified");

        p = last + NGX_SPDY_NV_VLEN_SIZE;

        last = ngx_http_time(p, r->headers_out.last_modified_time);

        (void) ngx_http_spdy_nv_write_vlen(p - NGX_SPDY_NV_VLEN_SIZE,
                                           last - p);

        count++;
    }

    if (host.data) {

        last = ngx_http_spdy_nv_write_name(last, "location");

        p = last + NGX_SPDY_NV_VLEN_SIZE;

        last = ngx_cpymem(p, "http", sizeof("http") - 1);

#if (NGX_HTTP_SSL)
        if (c->ssl) {
            *last++ ='s';
        }
#endif

        *last++ = ':'; *last++ = '/'; *last++ = '/';

        last = ngx_cpymem(last, host.data, host.len);

        if (port) {
            last = ngx_sprintf(last, ":%ui", port);
        }

        last = ngx_cpymem(last, r->headers_out.location->value.data,
                          r->headers_out.location->value.len);

        /* update r->headers_out.location->value for possible logging */

        r->headers_out.location->value.len = last - p;
        r->headers_out.location->value.data = p;
        ngx_str_set(&r->headers_out.location->key, "location");

        (void) ngx_http_spdy_nv_write_vlen(p - NGX_SPDY_NV_VLEN_SIZE,
                                           r->headers_out.location->value.len);

        count++;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy serverpush module header filter 4");

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0 || header[i].hash == 2) {
            continue;
        }

        if ((header[i].key.len == 6
             && ngx_strncasecmp(header[i].key.data,
                                (u_char *) "status", 6) == 0)
            || (header[i].key.len == 7
                && ngx_strncasecmp(header[i].key.data,
                                   (u_char *) "version", 7) == 0))
        {
            header[i].hash = 0;
            continue;
        }

        last = ngx_http_spdy_nv_write_nlen(last, header[i].key.len);

        ngx_strlow(last, header[i].key.data, header[i].key.len);
        last += header[i].key.len;

        p = last + NGX_SPDY_NV_VLEN_SIZE;

        last = ngx_cpymem(p, header[i].value.data, header[i].value.len);

        pt = part;
        h = header;

        for (j = i + 1; /* void */; j++) {

            if (j >= pt->nelts) {
                if (pt->next == NULL) {
                    break;
                }

                pt = pt->next;
                h = pt->elts;
                j = 0;
            }

            if (h[j].hash == 0 || h[j].hash == 2
                || h[j].key.len != header[i].key.len
                || ngx_strncasecmp(header[i].key.data, h[j].key.data,
                                   header[i].key.len))
            {
                continue;
            }

            *last++ = '\0';

            last = ngx_cpymem(last, h[j].value.data, h[j].value.len);

            h[j].hash = 2;
        }

        (void) ngx_http_spdy_nv_write_vlen(p - NGX_SPDY_NV_VLEN_SIZE,
                                           last - p);

        count++;
    }

    (void) ngx_spdy_frame_write_uint16(buf, count);

    stream = r->spdy_stream;
    sc = stream->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy serverpush module header filter 5");

    myStream = ngx_http_spdy_create_stream(sc, get_next_even_stream_id(), 0);
	
    len = last - buf;
    b = ngx_create_temp_buf(r->pool, NGX_SPDY_FRAME_HEADER_SIZE
	                             + NGX_SPDY_SYN_STREAM_SIZE
	                             + deflateBound(&sc->zstream_out, len));
    if (b == NULL) {
	ngx_free(buf);
	return NGX_ERROR;
    }

    b->last += NGX_SPDY_FRAME_HEADER_SIZE + NGX_SPDY_SYN_STREAM_SIZE;
    sc->zstream_out.next_in = buf;
    sc->zstream_out.avail_in = len;
    sc->zstream_out.next_out = b->last;
    sc->zstream_out.avail_out = b->end - b->last;
    rc = deflate(&sc->zstream_out, Z_SYNC_FLUSH);
    ngx_free(buf);

    if (rc != Z_OK) {
	ngx_log_error(NGX_LOG_ALERT, c->log, 0,
	              "spdy deflate() failed: %d", rc);
	return NGX_ERROR;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, c->log, 0,
	           "spdy deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
	           sc->zstream_out.next_in, sc->zstream_out.next_out,
	           sc->zstream_out.avail_in, sc->zstream_out.avail_out,
	           rc);

    b->last = sc->zstream_out.next_out;

    p = b->pos;
    p = ngx_spdy_frame_write_head(p, NGX_SPDY_SYN_STREAM);

    len = b->last - b->pos;

    r->header_size = len;

    if (r->header_only) {
	b->last_buf = 1;
	p = ngx_spdy_frame_write_flags_and_len(p, NGX_SPDY_FLAG_FIN,
	                                     len - NGX_SPDY_FRAME_HEADER_SIZE);
    } else {
	p = ngx_spdy_frame_write_flags_and_len(p, NGX_SPDY_FLAG_UNIDIRECTIONAL,
	                                     len - NGX_SPDY_FRAME_HEADER_SIZE);
    }

    p= ngx_spdy_frame_write_sid(p, myStream->id);
    (void) ngx_spdy_frame_write_associated_sid(p, stream->id);
    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
	return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    frame = ngx_palloc(r->pool, sizeof(ngx_http_spdy_out_frame_t));
    if (frame == NULL) {
	return NGX_ERROR;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy serverpush module header filter 6");

    frame->first = cl;
    frame->last = cl;
    frame->handler = ngx_http_spdy_syn_frame_handler;
    frame->free = NULL;
    frame->stream = myStream;
    frame->size = len;
    frame->priority = myStream->priority;
    frame->blocked = 1;
    frame->fin = r->header_only;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, stream->request->connection->log, 0,
	           "spdy:%ui create SYN_STREAM  frame %p: size:%uz",
	           myStream->id, frame, frame->size);

    ngx_http_spdy_queue_blocked_frame(sc, frame);

    r->blocked++;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
	return NGX_ERROR;
    }

    cln->handler = ngx_http_spdy_filter_cleanup;
    cln->data = myStream;

    myStream->waiting = 1;

    ngx_http_spdy_serverpush_filter_send(c, myStream);
    return ngx_http_next_header_filter(r);
}


static ngx_http_spdy_stream_t *
ngx_http_spdy_create_stream(ngx_http_spdy_connection_t *sc, ngx_uint_t id,
    ngx_uint_t priority)
{
    ngx_log_t                 *log;
    ngx_uint_t                 index;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *fc;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_request_t        *r;
    ngx_http_spdy_stream_t    *stream;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_spdy_srv_conf_t  *sscf;

    fc = sc->free_fake_connections;

    if (fc) {
        sc->free_fake_connections = fc->data;

        rev = fc->read;
        wev = fc->write;
        log = fc->log;
        ctx = log->data;

    } else {
        fc = ngx_palloc(sc->pool, sizeof(ngx_connection_t));
        if (fc == NULL) {
            return NULL;
        }

        rev = ngx_palloc(sc->pool, sizeof(ngx_event_t));
        if (rev == NULL) {
            return NULL;
        }

        wev = ngx_palloc(sc->pool, sizeof(ngx_event_t));
        if (wev == NULL) {
            return NULL;
        }

        log = ngx_palloc(sc->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            return NULL;
        }

        ctx = ngx_palloc(sc->pool, sizeof(ngx_http_log_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ctx->connection = fc;
        ctx->request = NULL;
    }

    ngx_memcpy(log, sc->connection->log, sizeof(ngx_log_t));

    log->data = ctx;

    ngx_memzero(rev, sizeof(ngx_event_t));

    rev->data = fc;
    rev->ready = 1;
    rev->handler = ngx_http_empty_handler;
    rev->log = log;

    ngx_memcpy(wev, rev, sizeof(ngx_event_t));

    wev->write = 1;

    ngx_memcpy(fc, sc->connection, sizeof(ngx_connection_t));

    fc->data = sc->http_connection;
    fc->read = rev;
    fc->write = wev;
    fc->sent = 0;
    fc->log = log;
    fc->buffered = 0;
    fc->sndlowat = 1;
    fc->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

    r = ngx_http_create_request(fc);
    if (r == NULL) {
        return NULL;
    }

    r->valid_location = 1;

    fc->data = r;
    sc->connection->requests++;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    r->header_in = ngx_create_temp_buf(r->pool,
                                       cscf->client_header_buffer_size);
    if (r->header_in == NULL) {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;

    stream = ngx_pcalloc(r->pool, sizeof(ngx_http_spdy_stream_t));
    if (stream == NULL) {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->spdy_stream = stream;

    stream->id = id;
    stream->request = r;
    stream->connection = sc;
    stream->priority = priority;

    sscf = ngx_http_get_module_srv_conf(r, ngx_http_spdy_module);

    index = ngx_http_spdy_stream_index(sscf, id);

    stream->index = sc->streams_index[index];
    sc->streams_index[index] = stream;

    sc->processing++;

    return stream;
}

static ngx_int_t
ngx_http_static_handler(ngx_http_request_t *r)
{
    u_char                    *last, *location;
    size_t                     root, len;
    ngx_str_t                  path;
    ngx_int_t                  rc;
    ngx_uint_t                 level;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;
    //ngx_str_t temp = ngx_string("/test1.js");
    //r->uri= temp;
    myChain=&out;
    r->uri.data=value;
    r->uri.len=valueLen;
/*in=&out;
in =in;*/
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    log = r->connection->log;

    /*
     * ngx_http_map_uri_to_path() allocates memory for terminating '\0'
     * so we do not need to reserve memory for '/' for possible redirect
     */

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    r->root_tested = !r->error_page;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");

        ngx_http_clear_location(r);

        r->headers_out.location = ngx_palloc(r->pool, sizeof(ngx_table_elt_t));
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        len = r->uri.len + 1;

        if (!clcf->alias && clcf->root_lengths == NULL && r->args.len == 0) {
            location = path.data + clcf->root.len;

            *last = '/';

        } else {
            if (r->args.len) {
                len += r->args.len + 1;
            }

            location = ngx_pnalloc(r->pool, len);
            if (location == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            last = ngx_copy(location, r->uri.data, r->uri.len);

            *last = '/';

            if (r->args.len) {
                *++last = '?';
                ngx_memcpy(++last, r->args.data, r->args.len);
            }
        }

        /*
         * we do not need to set the r->headers_out.location->hash and
         * r->headers_out.location->key fields
         */

        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = location;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

#if !(NGX_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NGX_HTTP_NOT_FOUND;
    }

#endif

    if (r->method & NGX_HTTP_POST) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    log->action = "sending response to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && of.size == 0) {
        return ngx_http_send_header(r);
    }

    r->allow_ranges = 1;

    /* we need to allocate all before the header would be sent */

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "GZIP HANDLER 1");
    return 1;
}

static ngx_int_t
ngx_http_spdy_serverpush_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
   
    off_t                       size;
    ngx_buf_t                  *b;
    ngx_chain_t                *cl, *ll, *out, **ln;
    ngx_http_spdy_stream_t     *stream;
    ngx_http_spdy_out_frame_t  *frame;
    //ngx_int_t                   static_handler_return_value;
    ngx_output_chain_ctx_t       *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_output_chain_ctx_t));
    ngx_http_set_ctx(r, ctx, ngx_http_spdy_serverpush_filter_module);    
    ngx_int_t ret_SH = ngx_http_static_handler(r);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "static_handler return : %d", ret_SH);

    stream = myStream;
    if (stream == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy body filter \"%V?%V\"", &r->uri, &r->args);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "Data in server Push ");

    if (myChain == NULL || r->header_only) {

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "Ending");
        if (stream->waiting) {
            return NGX_AGAIN;
        }

        r->connection->buffered &= ~NGX_SPDY_WRITE_BUFFERED;

        return NGX_OK;
    }

    size = 0;
    ln = &out;
    ll = myChain;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "into for ");
    for ( ;; ) {
        b = ll->buf;
//#if 1
	if(b->file)
	{	
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "file detected push : %d",(b->file_last-b->file_pos));
		ngx_int_t my_size = b->file_last-b->file_pos;
		u_char* my_buf = ngx_pcalloc(r->pool,sizeof(u_char)*my_size);
		ngx_read_file(b->file, my_buf, my_size, 0);
		b->start = my_buf;
		b->pos = my_buf;
		b->last = my_buf+my_size;//+NGX_SPDY_FRAME_HEADER_SIZE;

	}
        if (ngx_buf_size(b) == 0 && !ngx_buf_special(b)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "zero size buf in spdy body filter "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          b->temporary,
                          b->recycled,
                          b->in_file,
                          b->start,
                          b->pos,
                          b->last,
                          b->file,
                          b->file_pos,
                          b->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
//#endif
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "out of for");
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }
	
        size += ngx_buf_size(b);
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "Size %d ",size);
        
        cl->buf = b;

        *ln = cl;
        ln = &cl->next;

        if (ll->next == NULL) {
            break;
        }

        ll = ll->next;
    }

    if (size > NGX_SPDY_MAX_FRAME_SIZE) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "FIXME: chain too big in spdy filter: %O", size);
        return NGX_ERROR;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ONE ");
    frame = ngx_http_spdy_filter_get_data_frame(stream, (size_t) size,
                                                b->last_buf, out, cl);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "FOUR ");
    if (frame == NULL) {
        return NGX_ERROR;
    }

    ngx_http_spdy_queue_frame(stream->connection, frame);

    stream->waiting++;

    r->main->blocked++;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "Data in server Push end");
    ngx_http_spdy_serverpush_filter_send(r->connection, stream);
    return ngx_http_next_body_filter(r,in);
}


static ngx_http_spdy_out_frame_t *
ngx_http_spdy_filter_get_data_frame(ngx_http_spdy_stream_t *stream,
    size_t len, ngx_uint_t fin, ngx_chain_t *first, ngx_chain_t *last)
{
    u_char                     *p;
    ngx_buf_t                  *buf;
    ngx_uint_t                  flags;
    ngx_chain_t                *cl;
    ngx_http_spdy_out_frame_t  *frame;

    frame = stream->free_frames;

    if (frame) {
        stream->free_frames = frame->free;
	
    } else {
        frame = ngx_palloc(stream->request->pool,
                           sizeof(ngx_http_spdy_out_frame_t));
        if (frame == NULL) {
            return NULL;
        }
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, stream->request->connection->log, 0,
                   "spdy:%ui create DATA frame %p: len:%uz fin:%ui",
                   stream->id, frame, len, fin);

    if (len || fin) {

        flags = fin ? NGX_SPDY_FLAG_FIN : 0;

        cl = ngx_chain_get_free_buf(stream->request->pool,
                                    &stream->free_data_headers);
        if (cl == NULL) {
            return NULL;
        }

        buf = cl->buf;

        if (buf->start) {
            p = buf->start;
            buf->pos = p;

            p += sizeof(uint32_t);

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, stream->request->connection->log, 0,
                           "IF:%ui DATA frame",
                           stream->id);
            (void) ngx_spdy_frame_write_flags_and_len(p, flags, len);

        } else {
            p = ngx_palloc(stream->request->pool, NGX_SPDY_FRAME_HEADER_SIZE);
            if (p == NULL) {
                return NULL;
            }

            buf->pos = p;
            buf->start = p;

            p = ngx_spdy_frame_write_sid(p, stream->id);
            p = ngx_spdy_frame_write_flags_and_len(p, flags, len);

            buf->last = p;
            buf->end = p;

            buf->tag = (ngx_buf_tag_t) &ngx_http_spdy_serverpush_filter_module;
            buf->memory = 1;
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, stream->request->connection->log, 0,
                           "ELSE:%ui DATA frame",
                           stream->id);
	
	    if(buf->pos == buf->last)
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, stream->request->connection->log, 0,
                           "EQUAL !!!!!!");
        }

        cl->next = first;
        first = cl;
    }

    frame->first = first;
    frame->last = last;
    frame->handler = ngx_http_spdy_data_frame_handler;
    frame->free = NULL;
    frame->stream = stream;
    frame->size = NGX_SPDY_FRAME_HEADER_SIZE + len;
    frame->priority = stream->priority;
    frame->blocked = 0;
    frame->fin = fin;
//ngx_chain_t *cl1;
 //cl = frame->first;
//frame->first->buf->pos = frame->first->buf->last;
if (frame->first->buf->pos != frame->first->buf->last)
{
 ngx_log_debug1(NGX_LOG_DEBUG_HTTP, stream->request->connection->log, 0,
                           "spdy:%ui DATA frame",
                           stream->id);
}
    return frame;
}


static ngx_inline ngx_int_t
ngx_http_spdy_serverpush_filter_send(ngx_connection_t *fc, ngx_http_spdy_stream_t *stream)
{
    if (ngx_http_spdy_send_output_queue(stream->connection) == NGX_ERROR) {
        fc->error = 1;
        return NGX_ERROR;
    }

    if (stream->waiting) {
        fc->buffered |= NGX_SPDY_WRITE_BUFFERED;
        fc->write->delayed = 1;
        return NGX_AGAIN;
    }

    fc->buffered &= ~NGX_SPDY_WRITE_BUFFERED;

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_syn_frame_handler(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_out_frame_t *frame)
{
    ngx_buf_t               *buf;
    ngx_http_spdy_stream_t  *stream;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return NGX_AGAIN;
    }

    stream = frame->stream;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy:%ui SYN_REPLY frame %p was sent", stream->id, frame);

    ngx_free_chain(stream->request->pool, frame->first);

    ngx_http_spdy_handle_frame(stream, frame);

    ngx_http_spdy_handle_stream(sc, stream);

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_data_frame_handler(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_out_frame_t *frame)
{
    ngx_chain_t             *cl, *ln;
    ngx_http_spdy_stream_t  *stream;

    stream = frame->stream;

    cl = frame->first;

    if (cl->buf->tag == (ngx_buf_tag_t) &ngx_http_spdy_serverpush_filter_module) {

        if (cl->buf->pos != cl->buf->last) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                           "spdy:%ui DATA frame %p was sent partially",
                           stream->id, frame);

            return NGX_AGAIN;
        }

        ln = cl->next;

        cl->next = stream->free_data_headers;
        stream->free_data_headers = cl;

        if (cl == frame->last) {
            goto done;
        }

        cl = ln;
    }

    for ( ;; ) {
        if (ngx_buf_size(cl->buf) != 0) {

            if (cl != frame->first) {
                frame->first = cl;
                ngx_http_spdy_handle_stream(sc, stream);
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                           "spdy:%ui DATA frame %p was sent partially",
                           stream->id, frame);

            return NGX_AGAIN;
        }

        ln = cl->next;

        ngx_free_chain(stream->request->pool, cl);

        if (cl == frame->last) {
            goto done;
        }

        cl = ln;
    }

done:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy:%ui DATA frame %p was sent", stream->id, frame);

    stream->request->header_size += NGX_SPDY_FRAME_HEADER_SIZE;

    ngx_http_spdy_handle_frame(stream, frame);

    ngx_http_spdy_handle_stream(sc, stream);

    return NGX_OK;
}


static ngx_inline void
ngx_http_spdy_handle_frame(ngx_http_spdy_stream_t *stream,
    ngx_http_spdy_out_frame_t *frame)
{
    ngx_http_request_t  *r;

    r = stream->request;

    r->connection->sent += frame->size;
    r->blocked--;

    if (frame->fin) {
        stream->out_closed = 1;
    }

    frame->free = stream->free_frames;
    stream->free_frames = frame;

    stream->waiting--;
}


static ngx_inline void
ngx_http_spdy_handle_stream(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_stream_t *stream)
{
    ngx_connection_t  *fc;

    fc = stream->request->connection;

    fc->write->delayed = 0;

    if (stream->handled) {
        return;
    }

    if (sc->blocked == 2) {
        stream->handled = 1;

        stream->next = sc->last_stream;
        sc->last_stream = stream;
    }
}


static void
ngx_http_spdy_filter_cleanup(void *data)
{
    ngx_http_spdy_stream_t *stream = data;

    ngx_http_request_t         *r;
    ngx_http_spdy_out_frame_t  *frame, **fn;

    if (stream->waiting == 0) {
        return;
    }

    r = stream->request;

    fn = &stream->connection->last_out;

    for ( ;; ) {
        frame = *fn;

        if (frame == NULL) {
            break;
        }

        if (frame->stream == stream && !frame->blocked) {

            stream->waiting--;
            r->blocked--;

            *fn = frame->next;
            continue;
        }

        fn = &frame->next;
    }
}

static ngx_int_t get_next_even_stream_id()
{
    even_stream_id = even_stream_id + 2;
    return even_stream_id;	
}

static ngx_int_t
ngx_http_spdy_serverpush_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_spdy_serverpush_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_spdy_serverpush_body_filter;

    return NGX_OK;
}




