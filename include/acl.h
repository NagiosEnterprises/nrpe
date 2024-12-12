/****************************************************************************
 *
 * acl.h - header file for acl.c
 *
 * License: GPLv2
 * Copyright (c) 2011 Kaspersky Lab ZAO
 *
 * License Notice:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************************/

#ifndef ACL_H_INCLUDED
#define ACL_H_INCLUDED 1

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <syslog.h>
#include <stdarg.h>

#define CHAR_TO_NUMBER(c)   ((c) - '0')

struct ip_acl {
	int				family;
	struct in_addr	addr;
	struct in_addr	mask;
	struct in6_addr	addr6;
	struct in6_addr	mask6;
	struct ip_acl   *next;
};

struct dns_acl {
        char domain[255];
        struct dns_acl *next;
};

/* Functions */
void parse_allowed_hosts(char *allowed_hosts);
int add_ipv4_to_acl(char *ipv4);
int add_ipv6_to_acl(char *ipv6);
int add_domain_to_acl(char *domain);
//int is_an_allowed_host(struct in_addr);
int is_an_allowed_host(int, void *);
unsigned int prefix_from_mask(struct in_addr mask);
void show_acl_lists(void);

#endif /* ACL_H_INCLUDED */
