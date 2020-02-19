/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Rubicon Communications, LLC (Netgate)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/nv.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_media.h>
#include <net/route.h>


#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>		/* NB: for offsetof */
#include <locale.h>
#include <langinfo.h>

#include "ifconfig.h"

#define WGC_SETCONF	0x1
#define WGC_GETCONF	0x2

static nvlist_t *nvl_params;

#define WG_KEY_LEN 32
#define WG_KEY_LEN_BASE64 ((((WG_KEY_LEN) + 2) / 3) * 4 + 1)
#define WG_KEY_LEN_HEX (WG_KEY_LEN * 2 + 1)

static void encode_base64(u_int8_t *, u_int8_t *, u_int16_t);
static bool decode_base64(u_int8_t *, u_int16_t, const u_int8_t *);

const static u_int8_t Base64Code[] =
"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const static u_int8_t index_64[128] = {
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 0, 1, 54, 55,
        56, 57, 58, 59, 60, 61, 62, 63, 255, 255,
        255, 255, 255, 255, 255, 2, 3, 4, 5, 6,
        7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        255, 255, 255, 255, 255, 255, 28, 29, 30,
        31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
        51, 52, 53, 255, 255, 255, 255, 255
};
#define CHAR64(c)  ( (c) > 127 ? 255 : index_64[(c)])
static bool
decode_base64(u_int8_t *buffer, u_int16_t len, const u_int8_t *data)
{
        u_int8_t *bp = buffer;
        const u_int8_t *p = data;
        u_int8_t c1, c2, c3, c4;
        while (bp < buffer + len) {
                c1 = CHAR64(*p);
                c2 = CHAR64(*(p + 1));

                /* Invalid data */
                if (c1 == 255 || c2 == 255)
                        break;

                *bp++ = (c1 << 2) | ((c2 & 0x30) >> 4);
                if (bp >= buffer + len)
                        break;

                c3 = CHAR64(*(p + 2));
                if (c3 == 255)
                        break;

                *bp++ = ((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2);
                if (bp >= buffer + len)
                        break;

                c4 = CHAR64(*(p + 3));
                if (c4 == 255)
                        break;
                *bp++ = ((c3 & 0x03) << 6) | c4;

                p += 4;
        }
		return (bp == buffer + len);
}

static void
encode_base64(u_int8_t *buffer, u_int8_t *data, u_int16_t len)
{
        u_int8_t *bp = buffer;
        u_int8_t *p = data;
        u_int8_t c1, c2;
        while (p < data + len) {
                c1 = *p++;
                *bp++ = Base64Code[(c1 >> 2)];
                c1 = (c1 & 0x03) << 4;
                if (p >= data + len) {
                        *bp++ = Base64Code[c1];
                        break;
                }
                c2 = *p++;
                c1 |= (c2 >> 4) & 0x0f;
                *bp++ = Base64Code[c1];
                c1 = (c2 & 0x0f) << 2;
                if (p >= data + len) {
                        *bp++ = Base64Code[c1];
                        break;
                }
                c2 = *p++;
                c1 |= (c2 >> 6) & 0x03;
                *bp++ = Base64Code[c1];
                *bp++ = Base64Code[c2 & 0x3f];
        }
        *bp = '\0';
}

static bool
key_from_base64(uint8_t key[static WG_KEY_LEN], const char *base64)
{

	if (strlen(base64) != WG_KEY_LEN_BASE64 - 1 || base64[WG_KEY_LEN_BASE64 - 2] != '=')
		return false;

	return (decode_base64(key, WG_KEY_LEN, base64));
}

static
DECL_CMD_FUNC(setwglistenport, val, d)
{
	char *endp;
	u_long ul;

	ul = strtoul(val, &endp, 0);
	if (*endp != '\0')
		errx(1, "invalid value for listen-port");

	nvlist_add_number(nvl_params, "listen-port", ul);
}

static
DECL_CMD_FUNC(setwgprivkey, val, d)
{
	uint8_t key[WG_KEY_LEN];

	if (!key_from_base64(key, val))
		errx(1, "invalid key %s", val);
	nvlist_add_binary(nvl_params, "private-key", key, WG_KEY_LEN);
}

static
DECL_CMD_FUNC(setwgpubkey, val, d)
{
	uint8_t key[WG_KEY_LEN];

	if (!key_from_base64(key, val))
		errx(1, "invalid key %s", val);
	nvlist_add_binary(nvl_params, "public-key", key, WG_KEY_LEN);
}

static int
is_match(void)
{
	if (strncmp("wg", name, 2))
		return (-1);
	if (strlen(name) < 3)
		return (-1);
	if (!isdigit(name[2]))
		return (-1);
	return (0);
}

static int
get_nvl_out_size(int sock, u_long op, size_t *size)
{
	struct ifdrv ifd;
	int err;

	memset(&ifd, 0, sizeof(ifd));

	strlcpy(ifd.ifd_name, name, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = op;
	ifd.ifd_len = 0;
	ifd.ifd_data = NULL;

	err = ioctl(sock, SIOCGDRVSPEC, &ifd);
	if (err)
		return (err);
	*size = ifd.ifd_len;
	return (0);
}

static int
do_cmd(int sock, u_long op, void *arg, size_t argsize, int set)
{
	struct ifdrv ifd;

	memset(&ifd, 0, sizeof(ifd));

	strlcpy(ifd.ifd_name, name, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = op;
	ifd.ifd_len = argsize;
	ifd.ifd_data = arg;

	return (ioctl(sock, set ? SIOCSDRVSPEC : SIOCGDRVSPEC, &ifd));
}

static void
wireguard_status(int s)
{
	size_t size;
	void *packed;
	nvlist_t *nvl;

	if (is_match() < 0) {
		/* If it's not a wg interface just return */
		return;
	}
	if (get_nvl_out_size(s, WGC_GETCONF, &size))
		return;
	if ((packed = malloc(size)) == NULL)
		return;
	if (do_cmd(s, WGC_GETCONF, packed, size, 0))
		return;
	nvl = nvlist_unpack(packed, size, 0);
	nvlist_dump(nvl, 1);
}

static struct cmd wireguard_cmds[] = {
    DEF_CLONE_CMD_ARG("listen-port",  setwglistenport),
    DEF_CLONE_CMD_ARG("private-key",  setwgprivkey),
    DEF_CLONE_CMD_ARG("public-key",  setwgpubkey),
};

static struct afswtch af_wireguard = {
	.af_name	= "af_wireguard",
	.af_af		= AF_UNSPEC,
	.af_other_status = wireguard_status,
};

static void
wg_create(int s, struct ifreq *ifr)
{
	struct iovec iov;
	void *packed;
	size_t size;

	setproctitle("ifconfig %s create ...\n", name);
	if (!nvlist_exists_number(nvl_params, "listen-port"))
		errx(1, "must specify a listen-port for wg create");
	if (!nvlist_exists_binary(nvl_params, "public-key"))
		errx(1, "must specify a public-key for wg create");
	if (!nvlist_exists_binary(nvl_params, "private-key"))
		errx(1, "must specify a private-key for wg create");

	packed = nvlist_pack(nvl_params, &size);
	if (packed == NULL)
		errx(1, "failed to setup create request");
	iov.iov_len = size;
	iov.iov_base = packed;
	ifr->ifr_data = (caddr_t)&iov;
	if (ioctl(s, SIOCIFCREATE2, ifr) < 0)
		err(1, "SIOCIFCREATE2");
}

static __constructor void
wireguard_ctor(void)
{
	int i;

	nvl_params = nvlist_create(0);
	for (i = 0; i < nitems(wireguard_cmds);  i++)
		cmd_register(&wireguard_cmds[i]);
	af_register(&af_wireguard);
	clone_setdefcallback("wg", wg_create);
}
