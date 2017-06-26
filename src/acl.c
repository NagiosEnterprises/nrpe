/****************************************************************************
 *
 * acl.c - a small library for nrpe.c. It adds IPv4 subnets support to ACL in nrpe.
 *
 * License: GPLv2
 * Copyright (c) 2011 Kaspersky Lab ZAO
 *
 * Description:
 *
 * acl.c creates two linked lists. One is for IPv4 hosts and networks, another 
 * is for domain names. All connecting hosts (if allowed_hosts is defined) 
 * are checked in these two lists.
 *
 * Note:
 *  Only ANCII names are supported in ACL.
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

#include "../include/config.h"
#include "../include/common.h"
#include "../include/utils.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <stdarg.h>

#include "../include/acl.h"

extern int debug;

/* This function checks if a char argument from valid char range.
 * Valid range is: ASCII only, a number or a letter, a space, a dot, a slash, a dash, a comma.
 *
 * Returns:
 *      0 - char isn't from valid group
 *  1 - char is a number
 *  2 - char is a letter
 *  3 - char is a space(' ')
 *  4 - char is a dot('.')
 *  5 - char is a slash('/')
 *  6 - char is a dash('-')
 *  7 - char is a comma(',')
 */

int isvalidchar(int c) {
        if (!isascii(c))
                return 0;

        if (isdigit(c))
                return 1;

        if (isalpha(c))
                return 2;

        if (isspace(c))
                return 3;

        switch (c) {
        case '.':
                return 4;
        case '/':
                return 5;
        case '-':
                return 6;
        case ',':
                return 7;
        default:
                return 0;
        }
}

/*
 * Get substring from allowed_hosts from s position to e position.
 */

char * acl_substring(char *string, int s, int e) {
    char *substring;
    int len = e - s;

        if (len < 0)
                return NULL;

    if ( (substring = malloc(len + 1)) == NULL)
        return NULL;

    memmove(substring, string + s, len + 1);
    return substring;
}

/*
 * Add IPv4 host or network to IP ACL. IPv4 format is X.X.X.X[/X].
 * Host will be added to ACL only if it has passed IPv4 format check.
 *
 * Returns:
 * 1 - on success
 * 0 - on failure
 *
 * States for IPv4 format check:
 *  0 - numbers(-> 1), dot(-> -1), slash(-> -1), other(-> -1)
 *  1 - numbers(-> 1), dot(-> 2),  slash(-> -1), other(-> -1)
 *  2 - numbers(-> 3), dot(-> -1), slash(-> -1), other(-> -1)
 *  3 - numbers(-> 3), dot(-> 4),  slash(-> -1), other(-> -1)
 *  4 - numbers(-> 5), dot(-> -1), slash(-> -1), other(-> -1)
 *  5 - numbers(-> 5), dot(-> 6),  slash(-> -1), other(-> -1)
 *  6 - numbers(-> 7), dot(-> -1), slash(-> -1), other(-> -1)
 *  7 - numbers(-> 7), dor(-> -1), slash(-> 8),  other(-> -1)
 *  8 - numbers(-> 9), dor(-> -1), slash(-> -1), other(-> -1)
 *  9 - numbers(-> 9), dot(-> -1), slash(-> -1), other(-> -1)
 *
 *  Good states are 7(IPv4 host) and 9(IPv4 network)
 */

int add_ipv4_to_acl(char *ipv4) {

        int state = 0;
        int octet = 0;
        int index = 0;  /* position in data array */
        int data[5];    /* array to store ip octets and mask */
        int len = strlen(ipv4);
        int i, c;
        unsigned long ip, mask;
        struct ip_acl *ip_acl_curr;

		if(debug == TRUE)
			logit(LOG_INFO, "add_ipv4_to_acl: checking ip-address >%s<", ipv4);

        /* Check for min and max IPv4 valid length */
		if (len < 7 || len > 18) {
			logit(LOG_INFO, "add_ipv4_to_acl: Error, ip-address >%s< incorrect length", ipv4);
			return 0;
		}

        /* default mask for ipv4 */
        data[4] = 32;

        /* Basic IPv4 format check */
        for (i = 0; i < len; i++) {
			/* Return 0 on error state */
			if (state == -1) {
				if(debug == TRUE)
					logit(LOG_INFO, "add_ipv4_to_acl: Error, ip-address >%s< incorrect "
								"format, continue with next check ...", ipv4);
				return 0;
			}

                c = ipv4[i];

                switch (c) {
                case '0': case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': case '8': case '9':
                        octet = octet * 10 + CHAR_TO_NUMBER(c);
                        switch (state) {
                        case 0: case 2: case 4: case 6: case 8:
                                state++;
                                break;
                        }
                        break;
                case '.':
                        switch (state) {
                        case 1: case 3: case 5:
                                data[index++] = octet;
                                octet = 0;
                                state++;
                                break;
                        default:
                                state = -1;
                        }
                        break;
                case '/':
                        switch (state) {
                        case 7:
                                data[index++] = octet;
                                octet = 0;
                                state++;
                                break;
                        default:
                                state = -1;
                        }
                        break;
                default:
                        state = -1;
                }
        }

        /* Exit state handling */
        switch (state) {
        case 7: case 9:
                data[index] = octet;
                break;
        default:
                /* Bad states */
                logit(LOG_INFO, "add_ipv4_to_acl: Error, ip-address >%s< bad state", ipv4);
                return 0;
        }

        /*
         * Final IPv4 format check.
         */
        for (i=0; i < 4; i++) {
                if (data[i] < 0 || data[i] > 255) {
                        logit(LOG_ERR,"Invalid IPv4 address/network format(%s) in allowed_hosts option\n",ipv4);
                        return 0;
                }
        }

        if (data[4] < 0 || data[4] > 32) {
                logit(LOG_ERR,"Invalid IPv4 network mask format(%s) in allowed_hosts option\n",ipv4);
                return 0;
        }

        /* Convert ip and mask to unsigned long */
        ip = htonl((data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3]);
        mask =  htonl(-1 << (32 - data[4]));

        /* Wrong network address */
        if ( (ip & mask) != ip) {
                logit(LOG_ERR,"IP address and mask do not match in %s\n",ipv4);
                return 0;
        }

        /* Add addr to ip_acl list */
        if ( (ip_acl_curr = malloc(sizeof(*ip_acl_curr))) == NULL) {
                logit(LOG_ERR,"Can't allocate memory for ACL, malloc error\n");
                return 0;
        }

        /* Save result in ACL ip list */
        ip_acl_curr->family = AF_INET;
        ip_acl_curr->addr.s_addr = ip;
        ip_acl_curr->mask.s_addr = mask;
        ip_acl_curr->next = NULL;

        if (ip_acl_head == NULL) {
                ip_acl_head = ip_acl_curr;
        } else {
                ip_acl_prev->next = ip_acl_curr;
        }
        ip_acl_prev = ip_acl_curr;

        if(debug == TRUE)
          logit(LOG_INFO, "add_ipv4_to_acl: ip-address >%s< correct, adding.", ipv4);

        return 1;
}

/*
 * Add IPv6 host or network to IP ACL. Host will be added to ACL only if 
 * it has passed IPv6 format check.
 *
 */

int add_ipv6_to_acl(char *ipv6) {
	char	*ipv6tmp;
	char	*addr_part, *mask_part;
	struct in6_addr addr;
	struct in6_addr mask;
	int		maskval;
	int		byte, bit;
	int		nbytes = sizeof(mask.s6_addr) / sizeof(mask.s6_addr[0]);
	int		x;
	struct ip_acl	*ip_acl_curr;

	/* Save temporary copy of ipv6 so we can use the original in error 
		messages if needed */
	ipv6tmp = strdup(ipv6);
	if(NULL == ipv6tmp) {
		logit(LOG_ERR, "Memory allocation failed for copy of address: %s\n", 
				ipv6);
		return 0;
		}

	addr_part = ipv6tmp;
	mask_part = strchr(ipv6tmp, '/');
	if (mask_part) {
		*mask_part = '\0';
		++mask_part;
	}

	/* Parse the address itself */
	if(inet_pton(AF_INET6, addr_part, &addr) <= 0) {
		free(ipv6tmp);
		return 0;
		}

	/* Check whether there is a netmask */
	if (mask_part && *mask_part) {
		/* If so, build a netmask */
		/* Get the number of bits in the mask */
		maskval = atoi(mask_part);
		if(maskval < 0 || maskval > 128) {
			free(ipv6tmp);
			return 0;
			}

		/* Initialize to zero */
		for(x = 0; x < nbytes; x++) {
			mask.s6_addr[x] = 0;
			}

		/* Set mask based on mask bits */
		byte = 0;
		bit = 7;
		while(maskval > 0) {
			mask.s6_addr[byte] |= 1 << bit;
			bit -= 1;
			if(bit < 0) {
				bit = 7;
				byte++;
				}
			maskval--;
			}
		}
	else {
		/* Otherwise, this is a single address */
		for(x = 0; x < nbytes; x++) {
			mask.s6_addr[x] = 0xFF;
			}
		}

	/* Add address to ip_acl list */
	ip_acl_curr = malloc(sizeof(*ip_acl_curr));
	if(NULL == ip_acl_curr) {
		logit(LOG_ERR, "Memory allocation failed for ACL: %s\n", ipv6);
		return 0;
		}

	/* Save result in ACL ip list */
	ip_acl_curr->family = AF_INET6;
	for(x = 0; x < nbytes; x++) {
		ip_acl_curr->addr6.s6_addr[x] = 
				addr.s6_addr[x] & mask.s6_addr[x];
		ip_acl_curr->mask6.s6_addr[x] = mask.s6_addr[x];
		}
	ip_acl_curr->next = NULL;

	if(NULL == ip_acl_head) {
		ip_acl_head = ip_acl_curr;
		}
	else {
		ip_acl_prev->next = ip_acl_curr;
		}
	ip_acl_prev = ip_acl_curr;

	free(ipv6tmp);
	return 1;
	}

/*
 * Add domain to DNS ACL list
 * Domain will be added only if it has passed domain name check.
 *
 * In this case domain valid format is:
 * 1) Domain names must use only alphanumeric characters and dashes (-).
 * 2) Domain names mustn't begin or end with dashes (-).
 * 3) Domain names mustn't have more than 63 characters.
 *
 * Return:
 * 1 - for success
 * 0 - for failure
 *
 * 0 - alpha(-> 1), number(-> 1), dot(-> -1), dash(-> -1), all other(-> -1)
 * 1 - alpha(-> 1), number(-> 1), dot(-> 2),  dash(-> 6),  all other(-> -1)
 * 2 - alpha(-> 3), number(-> 1), dot(-> -1), dash(-> -1), all other(-> -1)
 * 3 - alpha(-> 4), number(-> 1), dot(-> 2),  dash(-> 6),  all other(-> -1)
 * 4 - alpha(-> 5), number(-> 1), dot(-> 2),  dash(-> 6),  all other(-> -1)
 * 5 - alpha(-> 1), number(-> 1), dot(-> 2),  dash(-> 6),  all other(-> -1)
 * 6 - alpha(-> 1), number(-> 1), dot(-> 2),  dash(-> 6),  all other(-> -1)

 * For real FQDN only 4 and 5 states are good for exit.
 * I don't check if top domain exists (com, ru and etc.)
 * But in real life NRPE could work in LAN,
 * with local domain zones like .local or with names like 'mars' added to /etc/hosts.
 * So 1 is good state too. And maybe this check is not necessary at all...
 */

int add_domain_to_acl(char *domain) {
        int state = 0;
        int len = strlen(domain);
        int i, c;

        struct dns_acl *dns_acl_curr;

        if (len > 63) {
                logit(LOG_INFO,
					   "ADD_DOMAIN_TO_ACL: Error, did not add >%s< to acl list, too long!",
					   domain);
                return 0;
        }

        for (i = 0; i < len; i++) {
                c = domain[i];
                switch (isvalidchar(c)) {
                case 1:
                        state = 1;
                        break;
                case 2:
                        switch (state) {
                        case 0: case 1: case 5: case 6:
                                state = 1;
                                break;
                        case 2: case 3: case 4:
                                state++;
                                break;
                        }
                        break;

                case 4:
                        switch (state) {
                        case 0: case 2:
                                state = -1;
                                break;
                        default:
                                state = 2;
                        }
                        break;
                case 6:
                        switch (state) {
                        case 0: case 2:
                                state = -1;
                                break;
                        default:
                                state = 6;
                        }
                        break;
                default:
                        logit(LOG_INFO,
							   "ADD_DOMAIN_TO_ACL: Error, did not add >%s< to acl list, "
								"invalid chars!", domain);
					/* Not valid chars */
                        return 0;
                }
        }

        /* Check exit code */
        switch (state) {
        case 1: case 4: case 5:
                /* Add name to domain ACL list */
                if ( (dns_acl_curr = malloc(sizeof(*dns_acl_curr))) == NULL) {
                        logit(LOG_ERR,"Can't allocate memory for ACL, malloc error\n");
                        return 0;
                }
                strcpy(dns_acl_curr->domain, domain);
                dns_acl_curr->next = NULL;

                if (dns_acl_head == NULL)
                        dns_acl_head = dns_acl_curr;
                else
                        dns_acl_prev->next = dns_acl_curr;

                dns_acl_prev = dns_acl_curr;
                if(debug == TRUE)
                     logit(LOG_INFO, "ADD_DOMAIN_TO_ACL: added >%s< to acl list!", domain);
                return 1;
        default:
                logit(LOG_INFO,
					   "ADD_DOMAIN_TO_ACL: ERROR, did not add >%s< to acl list, "
						"check allowed_host in config file!", domain);
                return 0;
        }
}

/* Checks connection host in ACL
 *
 * Returns:
 * 1 - on success
 * 0 - on failure
 */

int is_an_allowed_host(int family, void *host)
{
	struct ip_acl		*ip_acl_curr = ip_acl_head;
	int					nbytes;
	int					x;
	struct dns_acl		*dns_acl_curr = dns_acl_head;
	struct sockaddr_in	*addr;
	struct sockaddr_in6	addr6;
	struct addrinfo		*res, *ai;
	struct in_addr		tmp;

	while (ip_acl_curr != NULL) {
		if(ip_acl_curr->family == family) {
			switch(ip_acl_curr->family) {
			case AF_INET:
				if (debug == TRUE) {
					tmp.s_addr = ((struct in_addr*)host)->s_addr;
					logit(LOG_INFO, "is_an_allowed_host (AF_INET): is host >%s< "
							"an allowed host >%s<\n",
						 inet_ntoa(tmp), inet_ntoa(ip_acl_curr->addr));
				}
				if((((struct in_addr *)host)->s_addr & 
						ip_acl_curr->mask.s_addr) == 
						ip_acl_curr->addr.s_addr) {
					if (debug == TRUE)
						logit(LOG_INFO, "is_an_allowed_host (AF_INET): host is in allowed host list!");
					return 1;
					}
				break;
			case AF_INET6:
				nbytes = sizeof(ip_acl_curr->mask6.s6_addr) / 
						sizeof(ip_acl_curr->mask6.s6_addr[0]);
				for(x = 0; x < nbytes; x++) {
					if((((struct in6_addr *)host)->s6_addr[x] & 
							ip_acl_curr->mask6.s6_addr[x]) != 
							ip_acl_curr->addr6.s6_addr[x]) {
						break;
						}
					}
				if(x == nbytes) { 
					/* All bytes in host's address pass the netmask mask */
					return 1;
					}
				break;
				}
			}
		ip_acl_curr = ip_acl_curr->next;
        }

	while(dns_acl_curr != NULL) {
		if (!getaddrinfo(dns_acl_curr->domain, NULL, NULL, &res)) {

			for (ai = res; ai; ai = ai->ai_next) {

				switch(ai->ai_family) {

				case AF_INET:
					if(debug == TRUE) {
						tmp.s_addr=((struct in_addr *)host)->s_addr;
						logit(LOG_INFO, "is_an_allowed_host (AF_INET): is host >%s< "
								"an allowed host >%s<\n",
							 inet_ntoa(tmp), dns_acl_curr->domain);
					}

					addr = (struct sockaddr_in*)(ai->ai_addr);
					if (addr->sin_addr.s_addr == ((struct in_addr*)host)->s_addr) {
						if (debug == TRUE)
							logit(LOG_INFO, "is_an_allowed_host (AF_INET): "
									"host is in allowed host list!");
						return 1;
					}
					break;

				case AF_INET6:
					memcpy((char*)&addr6, ai->ai_addr, sizeof(addr6));
					if (!memcmp(&addr6.sin6_addr, &host, sizeof(addr6.sin6_addr)))
						return 1;
					break;
				}
			}
		}

		dns_acl_curr = dns_acl_curr->next;
	}
	return 0;
}

/* The trim() function takes a source string and copies it to the destination string,
 * stripped of leading and training whitespace. The destination string must be 
 * allocated at least as large as the source string.
 */

void trim( char *src, char *dest) {
	char *sptr, *dptr;

	for( sptr = src; isspace( *sptr) && *sptr; sptr++); /* Jump past leading spaces */
	for( dptr = dest; !isspace( *sptr) && *sptr; ) {
		*dptr = *sptr;
		sptr++;
		dptr++;
	}
	*dptr = '\0';
	return;
}

/* This function splits allowed_hosts to substrings with comma(,) as a delimiter.
 * It doesn't check validness of ACL record (add_ipv4_to_acl() and add_domain_to_acl() do),
 * just trims spaces from ACL records.
 * After this it sends ACL records to add_ipv4_to_acl() or add_domain_to_acl().
 */

void parse_allowed_hosts(char *allowed_hosts) {
	char *hosts = strdup( allowed_hosts);	/* Copy since strtok* modifies original */
	char *saveptr;
	char *tok;
	const char *delim = ",";
	char *trimmed_tok;
    int add_to_acl = 0;

	if (debug == TRUE)
		logit(LOG_INFO,
			 "parse_allowed_hosts: parsing the allowed host string >%s< to add to ACL list\n",
			 allowed_hosts);

#ifdef HAVE_STRTOK_R
	tok = strtok_r(hosts, delim, &saveptr);
#else
	if (debug == TRUE)
		logit(LOG_INFO,"parse_allowed_hosts: using strtok, this might lead to "
				"problems in the allowed_hosts string determination!\n");
	tok = strtok(hosts, delim);
#endif
	while( tok) {
		trimmed_tok = malloc(sizeof(char) * (strlen(tok) + 1));
		trim(tok, trimmed_tok);
		if (debug == TRUE)
			logit(LOG_DEBUG, "parse_allowed_hosts: ADDING this record (%s) to ACL list!\n", trimmed_tok);
		if (strlen(trimmed_tok) > 0) {

            /* lets check the type of the address before we try and add it to the acl */

            if (strchr(trimmed_tok, ':') != NULL) {

                /* its an ipv6 address */
                add_to_acl = add_ipv6_to_acl(trimmed_tok);
                
            } else {

                /* its either a fqdn or an ipv4 address
                   unfortunately, i don't want to re-invent the wheel here
                   the logic exists inside of add_ipv4_to_acl() to detect
                   whether or not it is a ip or not */
                add_to_acl = add_ipv4_to_acl(trimmed_tok);
            }

            /* but we only try to add it to a domain if the other tests have failed */
            if (!add_to_acl && !add_domain_to_acl(trimmed_tok)) {
				logit(LOG_ERR,"Can't add to ACL this record (%s). Check allowed_hosts option!\n",trimmed_tok);
			} else if (debug == TRUE)    
				logit(LOG_DEBUG,"parse_allowed_hosts: Record added to ACL list!\n");
		}
		free( trimmed_tok);
#ifdef HAVE_STRTOK_R
		tok = strtok_r(NULL, delim, &saveptr);
#else
		tok = strtok(NULL, delim);
#endif
	}

	free( hosts);
}

/*
 * Converts mask in unsigned long format to two digit prefix
 */

unsigned int prefix_from_mask(struct in_addr mask) {
        int prefix = 0;
        unsigned long bit = 1;
        int i;

        for (i = 0; i < 32; i++) {
                if (mask.s_addr & bit)
                        prefix++;

                bit = bit << 1;
        }
        return (prefix);
}

/*
 * It shows all hosts in ACL lists
 */

void show_acl_lists(void)
{
	struct ip_acl *ip_acl_curr = ip_acl_head;
	struct dns_acl *dns_acl_curr = dns_acl_head;

	logit(LOG_INFO, "Showing ACL lists for both IP and DOMAIN acl's:\n" );

	while (ip_acl_curr != NULL) {
		logit(LOG_INFO, "   IP ACL: %s/%u %u\n", inet_ntoa(ip_acl_curr->addr),
			 prefix_from_mask(ip_acl_curr->mask), ip_acl_curr->addr.s_addr);
		ip_acl_curr = ip_acl_curr->next;
	}

	while (dns_acl_curr != NULL) {
		logit(LOG_INFO, "  DNS ACL: %s\n", dns_acl_curr->domain);
		dns_acl_curr = dns_acl_curr->next;
	}
}
