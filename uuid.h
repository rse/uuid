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

/*
 *  UUID Binary Representation:
 *
 *  0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 0|                          time_low                             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 1|       time_mid                |         time_hi_and_version   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 2|clk_seq_hi_res |  clk_seq_low  |         node (0-1)            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 3|                         node (2-5)                            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  UUID ASCII String Representation:
 *
 *  uuid                   = <time_low> "-" <time_mid> "-"
 *                           <time_high_and_version> "-"
 *                           <clock_seq_and_reserved>
 *                           <clock_seq_low> "-" <node>
 *  time_low               = 4*<hexOctet>
 *  time_mid               = 2*<hexOctet>
 *  time_high_and_version  = 2*<hexOctet>
 *  clock_seq_and_reserved = <hexOctet>
 *  clock_seq_low          = <hexOctet>
 *  node                   = 6*<hexOctet>
 *  hexOctet               = <hexDigit> <hexDigit>
 *  hexDigit =               "0"|"1"|"2"|"3"|"4"|"5"|"6"|"7"|"8"|"9"
 *                          |"a"|"b"|"c"|"d"|"e"|"f"
 *                          |"A"|"B"|"C"|"D"|"E"|"F"
 *
 *  Example string representation of a UUID:
 *
 *  "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
 */

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
extern uuid_rc_t  uuid_create   (uuid_t **uuid);
extern uuid_rc_t  uuid_destroy  (uuid_t  *uuid);
extern uuid_rc_t  uuid_nil      (uuid_t  *uuid);

/* UUID comparison */
extern uuid_rc_t  uuid_compare  (uuid_t  *uuid, uuid_t *uuid2, int *result);
extern uuid_rc_t  uuid_isnil    (uuid_t  *uuid,                int *result);

/* binary representation handling */
extern uuid_rc_t  uuid_unpack   (uuid_t  *uuid, const void  *buf);
extern uuid_rc_t  uuid_pack     (uuid_t  *uuid,       void **buf);

/* string representation handling */
extern uuid_rc_t  uuid_parse    (uuid_t  *uuid, const char  *str);
extern uuid_rc_t  uuid_format   (uuid_t  *uuid,       char **str);

/* UUID generation and dumping */
extern uuid_rc_t  uuid_generate (uuid_t  *uuid, unsigned int mode, ...);
extern uuid_rc_t  uuid_dump     (uuid_t  *uuid, char **str);

/* error handling */
extern char      *uuid_error    (uuid_rc_t rc);

#endif /* __UUID_H__ */

