/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#define _GNU_SOURCE

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_time.h>

#include "syslog.h"
#include "syslog_conn.h"

#include <string.h>

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

#define DYNAMIC_TAG_MAX 128

// find and fill the value by msgpack format, e.g. \xA5ident\xA7my-appX...
// https://github.com/msgpack/msgpack/blob/master/spec.md#str-format-family
static int fill_field_value(char const *data, size_t const data_size, char const *name, char *out_val, char const *out_limit) {
    size_t name_len = strlen(name);
    unsigned char name_buf[1 + 31];
    name_buf[0] = 0xA0 + name_len;
    memcpy(name_buf + 1, name, name_len);
    unsigned char *key_start = memmem(data, data_size, name_buf, name_len + 1);
    if (key_start == NULL) {
        flb_warn("[in_syslog] field '%s' missing in syslog parser definition", name);
        return -1;
    }
    unsigned char *val_header_ptr = key_start + 1 + name_len;
    unsigned char val_header = *val_header_ptr;
    int val_len;
    unsigned char *val_ptr;
    if ((val_header & 0xA0) == 0xA0) {
        val_len = val_header & ~0xA0;
        val_ptr = key_start + 1 + name_len + 1;
    } else if (val_header == 0xD9) {
        val_len = *((unsigned char *) val_header_ptr + 1);
        val_ptr = key_start + 2 + name_len + 1;
    } else {
        flb_warn("[in_syslog] field '%s' has invalid value header: 0x%02X", name, val_header);
        return -1;
    }
    if (val_len > out_limit - out_val) {
        val_len = out_limit - out_val;
    }
    memcpy(out_val, val_ptr, val_len);
    return val_len;
}

static int tag_compose(char *tag, char *data, size_t data_size, char *out_tag, size_t out_tag_max) {
    enum { FIELD_IDENT, FIELD_MSGID }; // first * is <ident>, second * is <msgid>
    char *in = tag;
    char *in_end = tag + strlen(tag);
    char *out = out_tag;
    char *out_limit = out_tag + out_tag_max - 1;
    int next_field = FIELD_IDENT;
    while (in < in_end && out < out_limit) {
        char *e = strchr(in, '*');
        if (e == NULL) {
            e = in_end;
        }
        int len = e - in;
        if (len > 0) {
            memcpy(out, in, len);
            in += len;
            out += len;
        }
        if (*in == '*') {
            int field_len = 0;
            switch (next_field) {
            case FIELD_IDENT:
                field_len = fill_field_value(data, data_size, "ident", out, out_limit);
                break;
            case FIELD_MSGID:
                field_len = fill_field_value(data, data_size, "msgid", out, out_limit);
                break;
            }
            if (field_len > 0) {
                out += field_len;
            }
            next_field++;
            in++;
        }
    }
    *out = '\0';
    return out - out_tag;
}

static inline int pack_line(struct flb_syslog *ctx,
                            struct flb_time *time, char *data, size_t data_size)
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_time_append_to_msgpack(time, &mp_pck, 0);
    msgpack_sbuffer_write(&mp_sbuf, data, data_size);

    if (ctx->dynamic_tag) {
        char tag[DYNAMIC_TAG_MAX];
        int tag_len = tag_compose(ctx->ins->tag, mp_sbuf.data, mp_sbuf.size, tag, DYNAMIC_TAG_MAX);
        flb_input_chunk_append_raw(ctx->ins, tag, tag_len, mp_sbuf.data, mp_sbuf.size);
    } else {
        flb_input_chunk_append_raw(ctx->ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    }
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

int syslog_prot_process(struct syslog_conn *conn)
{
    int len;
    int ret;
    char *p;
    char *eof;
    char *end;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time;
    struct flb_syslog *ctx = conn->ctx;

    eof = conn->buf_data;
    end = conn->buf_data + conn->buf_len;

    /* Always parse while some remaining bytes exists */
    while (eof < end) {
        /* Lookup the ending byte */
        eof = p = conn->buf_data + conn->buf_parsed;
        while (*eof != '\n' && *eof != '\0' && eof < end) {
            eof++;
        }

        /* Incomplete message */
        if (eof == end || (*eof != '\n' && *eof != '\0')) {
            break;
        }

        /* No data ? */
        len = (eof - p);
        if (len == 0) {
            consume_bytes(conn->buf_data, 1, conn->buf_len);
            conn->buf_len--;
            conn->buf_parsed = 0;
            conn->buf_data[conn->buf_len] = '\0';
            end = conn->buf_data + conn->buf_len;

            if (conn->buf_len == 0) {
                break;
            }

            continue;
        }

        /* Process the string */
        ret = flb_parser_do(ctx->parser, p, len,
                            &out_buf, &out_size, &out_time);
        if (ret >= 0) {
            pack_line(ctx, &out_time, out_buf, out_size);
            flb_free(out_buf);
        }
        else {
            flb_plg_warn(ctx->ins, "error parsing log message with parser '%s'",
                         ctx->parser->name);
            flb_plg_debug(ctx->ins, "unparsed log message: %.*s", len, p);
        }

        conn->buf_parsed += len + 1;
        end = conn->buf_data + conn->buf_len;
        eof = conn->buf_data + conn->buf_parsed;
    }

    if (conn->buf_parsed > 0) {
        consume_bytes(conn->buf_data, conn->buf_parsed, conn->buf_len);
        conn->buf_len -= conn->buf_parsed;
        conn->buf_parsed = 0;
        conn->buf_data[conn->buf_len] = '\0';
    }

    return 0;
}

int syslog_prot_process_udp(char *buf, size_t size, struct flb_syslog *ctx)
{
    int ret;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time = {0};

    ret = flb_parser_do(ctx->parser, buf, size,
                        &out_buf, &out_size, &out_time);
    if (ret >= 0) {
        if (flb_time_to_double(&out_time) == 0) {
            flb_time_get(&out_time);
        }
        pack_line(ctx, &out_time, out_buf, out_size);
        flb_free(out_buf);
    }
    else {
        flb_plg_warn(ctx->ins, "error parsing log message with parser '%s'",
                     ctx->parser->name);
        flb_plg_debug(ctx->ins, "unparsed log message: %.*s", size, buf);
        return -1;
    }

    return 0;
}
