/*-
 * Copyright (c) 2003 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef	_G_CONCAT_H_
#define	_G_CONCAT_H_

#include <sys/endian.h>

#define	G_CONCAT_CLASS_NAME	"CONCAT"

#define	G_CONCAT_MAGIC		"GEOM::CONCAT"
#define	G_CONCAT_VERSION	0

#ifdef _KERNEL
#define	G_CONCAT_TYPE_MANUAL	0
#define	G_CONCAT_TYPE_AUTOMATIC	1

#define	G_CONCAT_DEBUG(lvl, ...)	do {				\
	if (g_concat_debug >= (lvl)) {					\
		printf("GEOM_CONCAT[%u]: ", lvl);			\
		printf(__VA_ARGS__);					\
		printf("\n");						\
	}								\
} while (0)
#define	G_CONCAT_LOGREQ(bp, ...)	do {				\
	if (g_concat_debug >= 2) {					\
		printf("GEOM_CONCAT[2]: ");				\
		printf(__VA_ARGS__);					\
		g_print_bio(bp);					\
		printf("\n");						\
	}								\
} while (0)

extern struct sysctl_oid_list sysctl__kern_geom_children;

struct g_concat_disk {
	struct g_consumer	*d_consumer;
	struct g_concat_softc	*d_softc;
	off_t			 d_start;
	off_t			 d_end;
	off_t			 d_length;
	boolean_t		 d_valid;
	LIST_ENTRY(g_concat_path) d_next;
};

struct g_concat_softc {
	u_int		sc_type;	/* provider type */
	struct g_provider *sc_provider;
	char		sc_name[16];	/* concat name */
	uint32_t	sc_id;		/* concat unique ID */

	struct g_concat_disk *sc_disks;
	uint16_t	sc_ndisks;
};
#endif	/* _KERNEL */

struct g_concat_metadata {
	char		md_magic[16];	/* Magic value. */
	uint32_t	md_version;	/* Version number. */
	char		md_name[16];	/* Concat name. */
	uint32_t	md_id;		/* Unique ID. */
	uint16_t	md_no;		/* Disk number. */
	uint16_t	md_all;		/* Number of all disks. */
};
static __inline void
concat_metadata_encode(const struct g_concat_metadata *md, u_char *data)
{

	bcopy(md->md_magic, data, sizeof(md->md_magic));
	le32enc(data + 16, md->md_version);
	bcopy(md->md_name, data + 20, sizeof(md->md_name));
	le32enc(data + 36, md->md_id);
	le16enc(data + 40, md->md_no);
	le16enc(data + 42, md->md_all);
}
static __inline void
concat_metadata_decode(const u_char *data, struct g_concat_metadata *md)
{

	bcopy(data, md->md_magic, sizeof(md->md_magic));
	md->md_version = le32dec(data + 16);
	bcopy(data + 20, md->md_name, sizeof(md->md_name));
	md->md_id = le32dec(data + 36);
	md->md_no = le16dec(data + 40);
	md->md_all = le16dec(data + 42);
}
#endif	/* _G_CONCAT_H_ */
