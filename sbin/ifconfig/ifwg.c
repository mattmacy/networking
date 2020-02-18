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
struct nvlist_desc {
	caddr_t nd_data;
	u_long nd_len;
};

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
    DEF_CMD_ARG("listenport",  setwglistenport),
};

static struct afswtch af_wireguard = {
	.af_name	= "af_wireguard",
	.af_af		= AF_UNSPEC,
	.af_other_status = wireguard_status,
};

static void
wg_create(int s, struct ifreq *ifr)
{
	struct nvlist_desc nd;
	void *packed;
	size_t size;

	if (!nvlist_exists_number(nvl_params, "listen-port"))
		errx(1, "must specify a listen-port for wg create");

	packed = nvlist_pack(nvl_params, &size);
	if (packed == NULL)
		errx(1, "failed to setup create request");
	nd.nd_len = size;
	nd.nd_data = packed;
	ifr->ifr_data = (caddr_t)&nd;
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
