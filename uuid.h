/*
**  OSSP uuid - Universally Unique Identifier
**  Copyright (c) 2004 Ralf S. Engelschall <rse@engelschall.com>
**  Copyright (c) 2004 The OSSP Project <http://www.ossp.org/>
**
**  This file is part of OSSP uuid, a library for the generation
**  of UUIDs which can found at http://www.ossp.org/pkg/lib/uuid/
**
**  Permission to use, copy, modify, and distribute this software for
**  any purpose with or without fee is hereby granted, provided that
**  the above copyright notice and this permission notice appear in all
**  copies.
**
**  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
**  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
**  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
**  IN NO EVENT SHALL THE AUTHORS AND COPYRIGHT HOLDERS AND THEIR
**  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
**  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
**  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
**  USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
**  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
**  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
**  OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
**  SUCH DAMAGE.
**
**  uuid.h: library API definition
*/

#ifndef __UUID_H__
#define __UUID_H__

/* encoding octet stream lengths */
#define UUID_LEN_BIN (128 / 8 /*bytes*/)
#define UUID_LEN_STR (128 / 4 /*nibbles*/ + 4 /*hyphens*/)

/* return codes */
typedef enum {
    UUID_RC_OK  = 0,
    UUID_RC_ARG = 1,
    UUID_RC_MEM = 2,
    UUID_RC_SYS = 3,
    UUID_RC_INT = 4
} uuid_rc_t;

/* generation mode flags */
enum {
    UUID_VERSION1      = (1 << 0),
    UUID_VERSION3      = (1 << 1),
    UUID_VERSION4      = (1 << 2),
    UUID_MCASTRND      = (1 << 3)
};

/* abstract data type */
struct uuid_st;
typedef struct uuid_st uuid_t;

/* object handling */
extern uuid_rc_t  uuid_create   (uuid_t **_uuid);
extern uuid_rc_t  uuid_destroy  (uuid_t  *_uuid);
extern uuid_rc_t  uuid_nil      (uuid_t  *_uuid);

/* UUID comparison */
extern uuid_rc_t  uuid_isnil    (uuid_t  *_uuid,                 int *_result);
extern uuid_rc_t  uuid_compare  (uuid_t  *_uuid, uuid_t *_uuid2, int *_result);

/* UUID binary representation handling */
extern uuid_rc_t  uuid_unpack   (uuid_t  *_uuid, const void  *_buf);
extern uuid_rc_t  uuid_pack     (uuid_t  *_uuid,       void **_buf);

/* UUID string representation handling */
extern uuid_rc_t  uuid_parse    (uuid_t  *_uuid, const char  *_str);
extern uuid_rc_t  uuid_format   (uuid_t  *_uuid,       char **_str);

/* UUID generation and dumping */
extern uuid_rc_t  uuid_generate (uuid_t  *_uuid, unsigned int _mode, ...);
extern uuid_rc_t  uuid_dump     (uuid_t  *_uuid, char **_str);

/* error handling */
extern char      *uuid_error    (uuid_rc_t _rc);

#endif /* __UUID_H__ */

