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
**  uuid.c: library API implementation
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>

#include "config.h"
#include "uuid.h"
#include "uuid_md5.h"
#include "uuid_prng.h"
#include "uuid_mac.h"
#include "uuid_ui64.h"

/* determine types of 8-bit size */
#if SIZEOF_CHAR == 1
typedef char uuid_int8_t;
#else
#error uexpected: sizeof(char) != 1 !?
#endif
#if SIZEOF_UNSIGNED_CHAR == 1
typedef unsigned char uuid_uint8_t;
#else
#error uexpected: sizeof(unsigned char) != 1 !?
#endif

/* determine types of 16-bit size */
#if SIZEOF_SHORT == 2
typedef short uuid_int16_t;
#elif SIZEOF_INT == 2
typedef int uuid_int16_t;
#elif SIZEOF_LONG == 2
typedef long uuid_int16_t;
#else
#error unexpected: no type found for uuid_int16_t
#endif
#if SIZEOF_UNSIGNED_SHORT == 2
typedef unsigned short uuid_uint16_t;
#elif SIZEOF_UNSIGNED_INT == 2
typedef unsigned int uuid_uint16_t;
#elif SIZEOF_UNSIGNED_LONG == 2
typedef unsigned long uuid_uint16_t;
#else
#error unexpected: no type found for uuid_uint16_t
#endif

/* determine types of 32-bit size */
#if SIZEOF_SHORT == 4
typedef short uuid_int32_t;
#elif SIZEOF_INT == 4
typedef int uuid_int32_t;
#elif SIZEOF_LONG == 4
typedef long uuid_int32_t;
#elif SIZEOF_LONG_LONG == 4
typedef long long uuid_int32_t;
#else
#error unexpected: no type found for uuid_int32_t
#endif
#if SIZEOF_UNSIGNED_SHORT == 4
typedef unsigned short uuid_uint32_t;
#elif SIZEOF_UNSIGNED_INT == 4
typedef unsigned int uuid_uint32_t;
#elif SIZEOF_UNSIGNED_LONG == 4
typedef unsigned long uuid_uint32_t;
#elif SIZEOF_UNSIGNED_LONG_LONG == 4
typedef unsigned long long uuid_uint32_t;
#else
#error unexpected: no type found for uuid_uint32_t
#endif

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE !FALSE
#endif

/* UUID binary representation according to UUID standards */
typedef struct {
    uuid_uint32_t   time_low;
    uuid_uint16_t   time_mid;
    uuid_uint16_t   time_hi_and_version;
    uuid_uint8_t    clock_seq_hi_and_reserved;
    uuid_uint8_t    clock_seq_low;
    uuid_uint8_t    node[6];
} uuid_obj_t;

/* abstract data type (ADT) of API */
struct uuid_st {
    uuid_obj_t     obj;       /* inlined UUID object */
    prng_t        *prng;      /* RPNG sub-object */
    md5_t         *md5;       /* MD5 sub-object */
    uuid_uint8_t   mac[6];    /* pre-determined MAC address */
    struct timeval time_last; /* last retrieved timestamp */
    unsigned long  time_seq;  /* last timestamp sequence counter */
};

/* create UUID object */
uuid_rc_t uuid_create(uuid_t **uuid)
{
    /* argument sanity check */
    if (uuid == NULL)
        return UUID_RC_ARG;

    /* allocate UUID object */
    if ((*uuid = (uuid_t *)malloc(sizeof(uuid_t))) == NULL)
        return UUID_RC_MEM;

    /* set UUID object initially to "nil UUID" */
    uuid_nil(*uuid);

    /* create PRNG and MD5 sub-objects */
    if (prng_create(&(*uuid)->prng) != PRNG_RC_OK)
        return UUID_RC_INT;
    if (md5_create(&(*uuid)->md5) != MD5_RC_OK)
        return UUID_RC_INT;

    /* resolve MAC address for insertion into node field of UUIDs */
    if (!mac_address((unsigned char *)((*uuid)->mac), sizeof((*uuid)->mac))) {
        memset((*uuid)->mac, '\0', sizeof((*uuid)->mac));
        (*uuid)->mac[0] = 0x80;
    }

    /* initialize time attributes */
    (*uuid)->time_last.tv_sec  = 0;
    (*uuid)->time_last.tv_usec = 0;
    (*uuid)->time_seq = 0;

    return UUID_RC_OK;
}

/* destroy UUID object */
uuid_rc_t uuid_destroy(uuid_t *uuid)
{
    /* argument sanity check */
    if (uuid == NULL)
        return UUID_RC_ARG;

    /* destroy PRNG and MD5 sub-objects */
    prng_destroy(uuid->prng);
    md5_destroy(uuid->md5);

    /* free UUID object */
    free(uuid);

    return UUID_RC_OK;
}

/* set UUID object to represents 'nil UUID' */
uuid_rc_t uuid_nil(uuid_t *uuid)
{
    /* argument sanity check */
    if (uuid == NULL)
        return UUID_RC_ARG;

    /* clear all octets to create "nil UUID" */
    memset((void *)&(uuid->obj), '\0', sizeof(uuid->obj));

    return UUID_RC_OK;
}

/* compare UUID objects */
uuid_rc_t uuid_compare(uuid_t *uuid1, uuid_t *uuid2, int *result)
{
    int r;

    /* argument sanity check */
    if (result == NULL)
        return UUID_RC_ARG;

    /* convinience macro for setting result */
#   define RESULT(r) \
    do { \
        *result = (r); \
        goto result_exit; \
    } while (0)

    /* special cases: NULL or equal UUIDs */
    if (uuid1 == uuid2)
        RESULT(0);
    if (uuid1 == NULL && uuid2 == NULL)
        RESULT(0);
    if (uuid1 == NULL)
        RESULT((uuid_isnil(uuid2, &r), r) ? 0 : -1);
    if (uuid2 == NULL)
        RESULT((uuid_isnil(uuid1, &r), r) ? 0 : 1);

    /* standard cases: regular different UUIDs */
    if (uuid1->obj.time_low != uuid2->obj.time_low)
        RESULT((uuid1->obj.time_low < uuid2->obj.time_low) ? -1 : 1);
    if ((r = (int)uuid1->obj.time_mid
           - (int)uuid2->obj.time_mid) != 0)
        RESULT((r < 0) ? -1 : 1);
    if ((r = (int)uuid1->obj.time_hi_and_version
           - (int)uuid2->obj.time_hi_and_version) != 0)
        RESULT((r < 0) ? -1 : 1);
    if ((r = (int)uuid1->obj.clock_seq_hi_and_reserved
           - (int)uuid2->obj.clock_seq_hi_and_reserved) != 0)
        RESULT((r < 0) ? -1 : 1);
    if ((r = (int)uuid1->obj.clock_seq_low
           - (int)uuid2->obj.clock_seq_low) != 0)
        RESULT((r < 0) ? -1 : 1);
    if ((r = memcmp(uuid1->obj.node, uuid2->obj.node, sizeof(uuid1->obj.node))) != 0)
        RESULT((r < 0) ? -1 : 1);

    /* default case: the keys are equal */
    *result = 0;

    result_exit:
    return UUID_RC_OK;
}

/* check whether UUID object represents 'nil UUID' */
uuid_rc_t uuid_isnil(uuid_t *uuid, int *result)
{
    const unsigned char *ucp;
    int i;

    /* sanity check argument(s) */
    if (uuid == NULL || result == NULL)
        return UUID_RC_ARG;

    /* a "nil UUID" is defined as all octets zero, so check for this case */
    *result = TRUE;
    for (i = 0, ucp = (unsigned char *)&(uuid->obj); i < UUID_LEN_BIN; i++) {
        if (*ucp++ != '\0') {
            *result = FALSE;
            break;
        }
    }

    return UUID_RC_OK;
}

/* unpack UUID binary presentation into UUID object
   (allows in-place operation for internal efficiency!) */
uuid_rc_t uuid_unpack(uuid_t *uuid, const void *buf)
{
    const uuid_uint8_t *in;
    uuid_uint32_t tmp32;
    uuid_uint16_t tmp16;
    int i;

    /* sanity check argument(s) */
    if (uuid == NULL || buf == NULL)
        return UUID_RC_ARG;

    /* treat input buffer as octet stream */
    in = (const uuid_uint8_t *)buf;

    /* unpack "time_low" field */
    tmp32 = *in++;
    tmp32 = (tmp32 << 8) | *in++;
    tmp32 = (tmp32 << 8) | *in++;
    tmp32 = (tmp32 << 8) | *in++;
    uuid->obj.time_low = tmp32;

    /* unpack "time_mid" field */
    tmp16 = *in++;
    tmp16 = (tmp16 << 8) | *in++;
    uuid->obj.time_mid = tmp16;

    /* unpack "time_hi_and_version" field */
    tmp16 = *in++;
    tmp16 = (tmp16 << 8) | *in++;
    uuid->obj.time_hi_and_version = tmp16;

    /* unpack "clock_seq_hi_and_reserved" field */
    uuid->obj.clock_seq_hi_and_reserved = *in++;

    /* unpack "clock_seq_low" field */
    uuid->obj.clock_seq_low = *in++;

    /* unpack "node" field */
    for (i = 0; i < sizeof(uuid->obj.node); i++)
        uuid->obj.node[i] = *in++;

    return UUID_RC_OK;
}

/* pack UUID object into binary representation
   (allows in-place operation for internal efficiency!) */
uuid_rc_t uuid_pack(uuid_t *uuid, void **buf)
{
    uuid_uint8_t *out;
    uuid_uint32_t tmp32;
    uuid_uint16_t tmp16;
    int i;

    /* sanity check argument(s) */
    if (uuid == NULL || buf == NULL)
        return UUID_RC_ARG;

    /* optionally allocate octet buffer */
    if (*buf == NULL)
        if ((*buf = malloc(sizeof(uuid_t))) == NULL)
            return UUID_RC_MEM;

    /* treat output buffer as octet stream */
    out = (uuid_uint8_t *)(*buf);

    /* pack "time_low" field */
    tmp32 = uuid->obj.time_low;
    out[3] = (uuid_uint8_t)(tmp32 & 0xff); tmp32 >>= 8;
    out[2] = (uuid_uint8_t)(tmp32 & 0xff); tmp32 >>= 8;
    out[1] = (uuid_uint8_t)(tmp32 & 0xff); tmp32 >>= 8;
    out[0] = (uuid_uint8_t)(tmp32 & 0xff);

    /* pack "time_mid" field */
    tmp16 = uuid->obj.time_mid;
    out[5] = (uuid_uint8_t)(tmp16 & 0xff); tmp16 >>= 8;
    out[4] = (uuid_uint8_t)(tmp16 & 0xff);

    /* pack "time_hi_and_version" field */
    tmp16 = uuid->obj.time_hi_and_version;
    out[7] = (uuid_uint8_t)(tmp16 & 0xff); tmp16 >>= 8;
    out[6] = (uuid_uint8_t)(tmp16 & 0xff);

    /* pack "clock_seq_hi_and_reserved" field */
    out[8] = uuid->obj.clock_seq_hi_and_reserved;

    /* pack "clock_seq_low" field */
    out[9] = uuid->obj.clock_seq_low;

    /* pack "node" field */
    for (i = 0; i < sizeof(uuid->obj.node); i++)
        out[10+i] = uuid->obj.node[i];

    return UUID_RC_OK;
}

/* INTERNAL: check for valid UUID string representation syntax */
static int uuid_isstr(const char *str)
{
    int i;
    const char *cp;

    /* example reference:
       f81d4fae-7dec-11d0-a765-00a0c91e6bf6
       012345678901234567890123456789012345
       0         1         2         3       */
    if (str == NULL)
        return FALSE;
    if (strlen(str) != UUID_LEN_STR)
        return FALSE;
    for (i = 0, cp = str; i <= UUID_LEN_STR; i++, cp++) {
        if ((i == 8) || (i == 13) || (i == 18) || (i == 23)) {
            if (*cp == '-')
                continue;
            else
                return FALSE;
        }
        if (i == UUID_LEN_STR)
            if (*cp == '\0')
                continue;
        if (!isxdigit((int)(*cp)))
            return FALSE;
    }
    return TRUE;
}

/* parse string representation into UUID object */
uuid_rc_t uuid_parse(uuid_t *uuid, const char *str)
{
    uuid_uint16_t tmp16;
    const char *cp;
    char hexbuf[3];
    int i;

    /* sanity check argument(s) */
    if (uuid == NULL || str == NULL)
        return UUID_RC_ARG;

    /* check for correct UUID string representation syntax */
    if (!uuid_isstr(str))
        return UUID_RC_ARG;

    /* parse hex values of "time" parts */
    uuid->obj.time_low            = (uuid_uint32_t)strtoul(str,    NULL, 16);
    uuid->obj.time_mid            = (uuid_uint16_t)strtoul(str+9,  NULL, 16);
    uuid->obj.time_hi_and_version = (uuid_uint16_t)strtoul(str+14, NULL, 16);

    /* parse hex values of "clock" parts */
    tmp16 = (uuid_uint16_t)strtoul(str+19, NULL, 16);
    uuid->obj.clock_seq_low             = (uuid_uint8_t)(tmp16 & 0xff); tmp16 >>= 8;
    uuid->obj.clock_seq_hi_and_reserved = (uuid_uint8_t)(tmp16 & 0xff);

    /* parse hex values of "node" part */
    cp = str+24;
    hexbuf[2] = '\0';
    for (i = 0; i < sizeof(uuid->obj.node); i++) {
        hexbuf[0] = *cp++;
        hexbuf[1] = *cp++;
        uuid->obj.node[i] = strtoul(hexbuf, NULL, 16);
    }

    return UUID_RC_OK;
}

/* format UUID object into string representation */
uuid_rc_t uuid_format(uuid_t *uuid, char **str)
{
    /* sanity check argument(s) */
    if (uuid == NULL || str == NULL)
        return UUID_RC_ARG;

    /* optionally allocate string buffer */
    if (*str == NULL)
        if ((*str = (char *)malloc(UUID_LEN_STR+1)) == NULL)
            return UUID_RC_MEM;

    /* format UUID into string representation */
    sprintf(*str,
        "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        (unsigned long)uuid->obj.time_low,
        (unsigned int)uuid->obj.time_mid,
        (unsigned int)uuid->obj.time_hi_and_version,
        (unsigned int)uuid->obj.clock_seq_hi_and_reserved,
        (unsigned int)uuid->obj.clock_seq_low,
        (unsigned int)uuid->obj.node[0],
        (unsigned int)uuid->obj.node[1],
        (unsigned int)uuid->obj.node[2],
        (unsigned int)uuid->obj.node[3],
        (unsigned int)uuid->obj.node[4],
        (unsigned int)uuid->obj.node[5]);

    return UUID_RC_OK;
}

/* INTERNAL: brand UUID with version and variant */
static void uuid_brand(uuid_t *uuid, int version)
{
    /* set version (as given) */
    uuid->obj.time_hi_and_version &= 0x0fff;
    uuid->obj.time_hi_and_version |= (((uuid_uint16_t)version & 0x0fff) << 12);

    /* set variant (always DCE 1.1 only) */
    uuid->obj.clock_seq_hi_and_reserved &= ~((0x03) << 6);
    uuid->obj.clock_seq_hi_and_reserved |= (0x02 << 6);
    return;
}

/* maximum number of 100ns ticks of the actual resolution of system clock
   (which in our case is 1us (= 1000ns) because we use gettimeofday(2) */
#define UUIDS_PER_TICK 10

/* INTERNAL: generate UUID version 1: time, clock and node based */
static uuid_rc_t uuid_generate_v1(uuid_t *uuid, unsigned int mode, va_list ap)
{
    struct timeval time_now;
#ifdef HAVE_NANOSLEEP
    struct timespec ts;
#else
    struct timeval tv;
#endif
    ui64_t t;
    ui64_t offset;
    ui64_t ov;
    uuid_uint16_t clck;

    /*
     *  GENERATE TIME
     */

    /* determine current system time and sequence counter */
    while (1) {
        /* determine current system time */
        if (gettimeofday(&time_now, NULL) == -1)
            return UUID_RC_SYS;

        /* check whether system time changed since last retrieve */
        if (!(   time_now.tv_sec  == uuid->time_last.tv_sec
              && time_now.tv_usec == uuid->time_last.tv_usec))
            /* reset time sequence counter */
            uuid->time_seq = 0;

        /* until we are out of UUIDs per tick, increment
           the time/tick sequence counter and continue */
        if (uuid->time_seq < UUIDS_PER_TICK) {
            uuid->time_seq++;
            break;
        }

        /* stall the UUID generation until the system clock (which
           has a gettimeofday(2) resolution of 1us) catches up */
#ifdef HAVE_NANOSLEEP
        /* sleep for 500ns (1/2us) */
        ts.tv_sec  = 0;
        ts.tv_nsec = 500;
        nanosleep(&ts, NULL);
#else
        /* sleep for 1000ns (1us) */
        tv.tv_sec  = 0;
        tv.tv_usec = 1;
        select(0, NULL, NULL, NULL, &tv);
#endif
    }

    /* convert from timeval (sec,usec) to OSSP ui64 (100*nsec) format */
    t = ui64_n2i(time_now.tv_sec);
    t = ui64_muln(t, 1000000, NULL);
    t = ui64_addn(t, time_now.tv_usec, NULL);
    t = ui64_muln(t, 10, NULL);

    /* adjust for offset between UUID and Unix Epoch time through adding
       the magic offset 01B21DD213814000 from draft-leach-uuids-guids-01.
       (UUID UTC base time is October 15, 1582
        Unix UTC base time is January  1, 1970) */
    offset = ui64_s2i("01B21DD213814000", NULL, 16);
    t = ui64_add(t, offset, NULL);

    /* compensate for low resolution system clock by adding
       the time/tick sequence counter */
    if (uuid->time_seq > 0)
        t = ui64_addn(t, uuid->time_seq, NULL);

    /* store the 60 LSB of the time in the UUID */
    t = ui64_rol(t, 16, &ov);
    uuid->obj.time_hi_and_version =
        (uuid_uint16_t)(ui64_i2n(ov) & 0x00000fff); /* 12 of 16 bit only! */
    t = ui64_rol(t, 16, &ov);
    uuid->obj.time_mid =
        (uuid_uint16_t)(ui64_i2n(ov) & 0x0000ffff); /* all 16 bit */
    t = ui64_rol(t, 32, &ov);
    uuid->obj.time_low =
        (uuid_uint32_t)(ui64_i2n(ov) & 0xffffffff); /* all 32 bit */

    /*
     *  GENERATE CLOCK
     */

    /* retrieve current clock sequence */
    clck = ((uuid->obj.clock_seq_hi_and_reserved & ~((0x03) << 6)) << 8)
           + uuid->obj.clock_seq_low;

    /* generate new random clock sequence (initially or if the
       time has stepped backwards) or else just increase it */
    if (   clck == 0
        || (   time_now.tv_sec < uuid->time_last.tv_sec
            || (   time_now.tv_sec == uuid->time_last.tv_sec
                && time_now.tv_usec < uuid->time_last.tv_usec)))
        prng_data(uuid->prng, (void *)&clck, sizeof(clck));
    else
        clck++;
    clck &= ~((0x03) << 6);

    /* store back new clock sequence */
    uuid->obj.clock_seq_hi_and_reserved =
        (uuid->obj.clock_seq_hi_and_reserved & ((0x03) << 6))
        | (uuid_uint8_t)((clck >> 8) & 0xff);
    uuid->obj.clock_seq_low =
        (uuid_uint8_t)(clck & 0xff);

    /*
     *  GENERATE NODE
     */

    if ((mode & UUID_MCASTRND) || (uuid->mac[0] & 0x80)) {
        /* use random multi-cast MAC address */
        prng_data(uuid->prng, (void *)&(uuid->obj.node), sizeof(uuid->obj.node));
        uuid->obj.node[0] |= 0x80;
    }
    else {
        /* use real regular MAC address */
        memcpy(uuid->obj.node, uuid->mac, sizeof(uuid->mac));
    }

    /*
     *  FINISH
     */

    /* remember current system time for next iteration */
    uuid->time_last.tv_sec  = time_now.tv_sec;
    uuid->time_last.tv_usec = time_now.tv_usec;

    /* brand with version and variant */
    uuid_brand(uuid, 1);

    return UUID_RC_OK;
}

/* INTERNAL: UUID Namespace Ids as pre-defined by draft-leach-uuids-guids-01.txt
   (defined here as network byte ordered octet stream for direct MD5 feeding) */
static struct {
    char *name;
    uuid_uint8_t uuid[UUID_LEN_BIN];
} uuid_ns_table[] = {
    { "DNS",  /* 6ba7b810-9dad-11d1-80b4-00c04fd430c8 */
      { 0x6b,0xa7,0xb8,0x10,0x9d,0xad,0x11,0xd1,0x80,0xb4,0x00,0xc0,0x4f,0xd4,0x30,0xc8 } },
    { "URL",  /* 6ba7b811-9dad-11d1-80b4-00c04fd430c8 */
      { 0x6b,0xa7,0xb8,0x11,0x9d,0xad,0x11,0xd1,0x80,0xb4,0x00,0xc0,0x4f,0xd4,0x30,0xc8 } },
    { "OID",  /* 6ba7b812-9dad-11d1-80b4-00c04fd430c8 */
      { 0x6b,0xa7,0xb8,0x12,0x9d,0xad,0x11,0xd1,0x80,0xb4,0x00,0xc0,0x4f,0xd4,0x30,0xc8 } },
    { "X500", /* 6ba7b814-9dad-11d1-80b4-00c04fd430c8 */
      { 0x6b,0xa7,0xb8,0x14,0x9d,0xad,0x11,0xd1,0x80,0xb4,0x00,0xc0,0x4f,0xd4,0x30,0xc8 } }
};

/* INTERNAL: generate UUID version 3: name based */
static uuid_rc_t uuid_generate_v3(uuid_t *uuid, unsigned int mode, va_list ap)
{
    char *str;
    char *ns;
    void *uuid_octets;
    uuid_t *uuid_object;
    uuid_rc_t rc;
    int i;

    /* determine namespace UUID name and argument name string */
    if ((ns = (char *)va_arg(ap, char *)) == NULL)
        return UUID_RC_ARG;
    if ((str = (char *)va_arg(ap, char *)) == NULL)
        return UUID_RC_ARG;

    /* initialize MD5 context */
    if (md5_init(uuid->md5) != MD5_RC_OK)
        return UUID_RC_MEM;

    /* load the namespace UUID into MD5 context */
    if (uuid_isstr(ns)) {
        /* custom namespace via UUID string representation */
        if ((rc = uuid_create(&uuid_object)) != UUID_RC_OK)
            return rc;
        if ((rc = uuid_parse(uuid_object, ns)) != UUID_RC_OK)
            return rc;
        uuid_octets = (void *)&(uuid_object->obj);
        uuid_pack(uuid_object, &uuid_octets);
        md5_update(uuid->md5, uuid_octets, UUID_LEN_BIN);
        uuid_destroy(uuid_object);
    }
    else {
        /* standard namespace via UUID namespace id */
        uuid_octets = NULL;
        for (i = 0; i < sizeof(uuid_ns_table)/sizeof(uuid_ns_table[0]); i++) {
             if (strcmp(uuid_ns_table[i].name, ns) == 0) {
                 uuid_octets = uuid_ns_table[i].uuid;
                 break;
             }
        }
        if (uuid_octets == NULL)
            return UUID_RC_ARG;
        md5_update(uuid->md5, uuid_octets, UUID_LEN_BIN);
    }

    /* load the argument name string into MD5 context */
    md5_update(uuid->md5, str, strlen(str));

    /* store MD5 result into UUID
       (requires MD5_LEN_BIN space, UUID_LEN_BIN space is available,
       and both are equal in size, so we are safe!) */
    uuid_octets = (void *)&(uuid->obj);
    md5_store(uuid->md5, &uuid_octets, NULL);

    /* fulfill requirement of standard and convert UUID data into
       local/host byte order (this uses fact that uuid_unpack() is
       able to operate in-place!) */
    uuid_unpack(uuid, (void *)&(uuid->obj));

    /* brand UUID with version and variant */
    uuid_brand(uuid, 3);

    return UUID_RC_OK;
}

/* INTERNAL: generate UUID version 4: random number based */
static uuid_rc_t uuid_generate_v4(uuid_t *uuid, unsigned int mode, va_list ap)
{
    /* fill UUID with random data */
    prng_data(uuid->prng, (void *)&(uuid->obj), sizeof(uuid->obj));

    /* brand UUID with version and variant */
    uuid_brand(uuid, 4);

    return UUID_RC_OK;
}

/* generate UUID */
uuid_rc_t uuid_generate(uuid_t *uuid, unsigned int mode, ...)
{
    va_list ap;
    uuid_rc_t rc;

    /* sanity check argument(s) */
    if (uuid == NULL)
        return UUID_RC_ARG;

    /* dispatch into version dependent generation functions */
    va_start(ap, mode);
    if (mode & UUID_VERSION1)
        rc = uuid_generate_v1(uuid, mode, ap);
    else if (mode & UUID_VERSION3)
        rc = uuid_generate_v3(uuid, mode, ap);
    else if (mode & UUID_VERSION4)
        rc = uuid_generate_v4(uuid, mode, ap);
    else
        rc = UUID_RC_ARG;
    va_end(ap);

    return rc;
}

/* dump UUID object as descriptive text */
uuid_rc_t uuid_dump(uuid_t *uuid, char **str)
{
    /* sanity check argument(s) */
    if (uuid == NULL || str == NULL)
        return UUID_RC_ARG;
    /* FIXME */
    return UUID_RC_OK;
}

/* translate UUID API error code into corresponding error string */
char *uuid_error(uuid_rc_t rc)
{
    char *str;

    switch (rc) {
        case UUID_RC_OK:  str = "everything ok";    break;
        case UUID_RC_ARG: str = "invalid argument"; break;
        case UUID_RC_MEM: str = "out of memory";    break;
        case UUID_RC_SYS: str = "system error";     break;
        default:          str = NULL;               break;
    }
    return str;
}

