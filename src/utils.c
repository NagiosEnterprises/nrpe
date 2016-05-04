/****************************************************************************
 *
 * UTILS.C - NRPE Utility Functions
 *
 * License: GPL
 * Copyright (c) 1999-2006 Ethan Galstad (nagios@nagios.org)
 *
 * Last Modified: 12-11-2006
 *
 * Description:
 *
 * This file contains common network functions used in nrpe and check_nrpe.
 *
 * License Information:
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

#include "../include/common.h"
#include "../include/utils.h"

#ifndef HAVE_ASPRINTF
extern int asprintf(char **ptr, const char *format, ...);
#endif

#ifndef NI_MAXSERV
# define NI_MAXSERV 32
#endif

#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif

extern char **environ;

static unsigned long crc32_table[256];

static int my_create_socket(struct addrinfo *ai, const char *bind_address);


/* build the crc table - must be called before calculating the crc value */
void generate_crc32_table(void)
{
	unsigned long crc, poly;
	int i, j;

	poly = 0xEDB88320L;
	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 8; j > 0; j--) {
			if (crc & 1)
				crc = (crc >> 1) ^ poly;
			else
				crc >>= 1;
		}
		crc32_table[i] = crc;
	}

	return;
}

/* calculates the CRC 32 value for a buffer */
unsigned long calculate_crc32(char *buffer, int buffer_size)
{
	register unsigned long crc = 0xFFFFFFFF;
	int this_char;
	int current_index;

	for (current_index = 0; current_index < buffer_size; current_index++) {
		this_char = (int)buffer[current_index];
		crc = ((crc >> 8) & 0x00FFFFFF) ^ crc32_table[(crc ^ this_char) & 0xFF];
	}

	return (crc ^ 0xFFFFFFFF);
}

/* fill a buffer with semi-random data */
void randomize_buffer(char *buffer, int buffer_size)
{
	FILE *fp;
	int x;
	int seed;

	/**** FILL BUFFER WITH RANDOM ALPHA-NUMERIC CHARACTERS ****/

	/***************************************************************
	   Only use alpha-numeric characters because plugins usually
	   only generate numbers and letters in their output.  We
	   want the buffer to contain the same set of characters as
	   plugins, so its harder to distinguish where the real output
	   ends and the rest of the buffer (padded randomly) starts.
	 ***************************************************************/

	/* try to get seed value from /dev/urandom, as its a better source of entropy */
	fp = fopen("/dev/urandom", "r");
	if (fp != NULL) {
		seed = fgetc(fp);
		fclose(fp);
	}
	/* else fallback to using the current time as the seed */
	else
		seed = (int)time(NULL);

	srand(seed);
	for (x = 0; x < buffer_size; x++)
		buffer[x] = (int)'0' + (int)(72.0 * rand() / (RAND_MAX + 1.0));

	return;
}

/* opens a connection to a remote host */
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
int my_connect(const char *host, struct sockaddr_storage *hostaddr, u_short port,
			   int address_family, const char *bind_address)
#else
int my_connect(const char *host, struct sockaddr *hostaddr, u_short port,
			   int address_family, const char *bind_address)
#endif
{
	struct addrinfo hints, *ai, *aitop;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
	int gaierr;
	int sock = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = address_family;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, sizeof strport, "%u", port);
	if ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		fprintf(stderr, "Could not resolve hostname %.100s: %s\n", host, gai_strerror(gaierr));
		exit(1);
	}

	/*
	 * Loop through addresses for this host, and try each one in
	 * sequence until the connection succeeds.
	 */
	for (ai = aitop; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		if (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, sizeof(ntop),
						strport, sizeof(strport), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
			fprintf(stderr, "my_connect: getnameinfo failed\n");
			continue;
		}

		/* Create a socket for connecting. */
		sock = my_create_socket(ai, bind_address);
		if (sock < 0)
			continue;			/* Any error is already output */

		if (connect(sock, ai->ai_addr, ai->ai_addrlen) >= 0) {
			/* Successful connection. */
			memcpy(hostaddr, ai->ai_addr, ai->ai_addrlen);
			break;
		} else {
			fprintf(stderr, "connect to address %s port %s: %s\n", ntop, strport,
					strerror(errno));
			close(sock);
			sock = -1;
		}
	}

	freeaddrinfo(aitop);

	/* Return failure if we didn't get a successful connection. */
	if (sock == -1) {
		fprintf(stderr, "connect to host %s port %s: %s\n", host, strport, strerror(errno));
		return -1;
	}
	return sock;
}

/* Creates a socket for the connection. */
int my_create_socket(struct addrinfo *ai, const char *bind_address)
{
	int sock, gaierr;
	struct addrinfo hints, *res;

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock < 0)
		fprintf(stderr, "socket: %.100s\n", strerror(errno));

	/* Bind the socket to an alternative local IP address */
	if (bind_address == NULL)
		return sock;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ai->ai_family;
	hints.ai_socktype = ai->ai_socktype;
	hints.ai_protocol = ai->ai_protocol;
	hints.ai_flags = AI_PASSIVE;
	gaierr = getaddrinfo(bind_address, NULL, &hints, &res);
	if (gaierr) {
		fprintf(stderr, "getaddrinfo: %s: %s\n", bind_address, gai_strerror(gaierr));
		close(sock);
		return -1;
	}
	if (bind(sock, res->ai_addr, res->ai_addrlen) < 0) {
		fprintf(stderr, "bind: %s: %s\n", bind_address, strerror(errno));
		close(sock);
		freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);
	return sock;
}

void add_listen_addr(struct addrinfo **listen_addrs, int address_family, char *addr, int port)
{
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	int gaierr;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == NULL) ? AI_PASSIVE : 0;
	snprintf(strport, sizeof strport, "%d", port);
	if ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		syslog(LOG_ERR, "bad addr or host: %s (%s)\n", addr ? addr : "<NULL>",
			   gai_strerror(gaierr));
		exit(1);
	}
	for (ai = aitop; ai->ai_next; ai = ai->ai_next) ;
	ai->ai_next = *listen_addrs;
	*listen_addrs = aitop;
}

int clean_environ(const char *keep_env_vars, const char *nrpe_user)
{
#ifdef HAVE_PATHS_H
	static char	*path = _PATH_STDPATH;
#else
	static char	*path = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
#endif
	struct passwd *pw;
	size_t len, var_sz = 0;
	char **kept = NULL, *value, *var, *keep = NULL;
	int i, j, keepcnt = 0;

	if (keep_env_vars && *keep_env_vars)
		asprintf(&keep, "%s,NRPE_MULTILINESUPPORT,NRPE_PROGRAMVERSION", keep_env_vars);
	else
		asprintf(&keep, "NRPE_MULTILINESUPPORT,NRPE_PROGRAMVERSION");
	if (keep == NULL) {
		syslog(LOG_ERR, "Could not sanitize the environment. Aborting!");
		return ERROR;
	}

	++keepcnt;
	i = strlen(keep);
	while (i--) {
		if (keep[i] == ',')
			++keepcnt;
	}

	if ((kept = calloc(keepcnt + 1, sizeof(char *))) == NULL) {
		syslog(LOG_ERR, "Could not sanitize the environment. Aborting!");
		return ERROR;
	}
	for (i = 0, var = my_strsep(&keep, ","); var != NULL; var = my_strsep(&keep, ","))
		kept[i++] = strip(var);

	var = NULL;
	i = 0;
	while (environ[i]) {
		value = environ[i];
		if ((len = strcspn(value, "=")) == 0) {
			free(keep);
			free(kept);
			free(var);
			syslog(LOG_ERR, "Could not sanitize the environment. Aborting!");
			return ERROR;
		}
		if (len >= var_sz) {
			var_sz = len + 1;
			var = realloc(var, var_sz);
		}
		strncpy(var, environ[i], var_sz);
		var[len] = 0;

		for (j = 0; kept[j]; ++j) {
			if (!strncmp(var, kept[j], strlen(kept[j])))
				break;
		}
		if (kept[j]) {
			++i;
			continue;
		}

		unsetenv(var);
	}

	free(var);
	free(keep);
	free(kept);

	pw = (struct passwd *)getpwnam(nrpe_user);
	if (pw == NULL)
		return OK;

	setenv("PATH", path, 1);
	setenv("IFS", " \t\n", 1);
	setenv("HOME", pw->pw_dir, 0);
	setenv("SHELL", pw->pw_shell, 0);
	setenv("LOGNAME", nrpe_user, 0);
	setenv("USER", nrpe_user, 0);

	return OK;
}

char *strip(char *buffer)
{
	int x;
	int index;
	char *buf = buffer;

	for (x = strlen(buffer); x >= 1; x--) {
		index = x - 1;
		if (buffer[index] == ' ' || buffer[index] == '\r' || buffer[index] == '\n'
			|| buffer[index] == '\t')
			buffer[index] = '\x0';
		else
			break;
	}

	while (*buf == ' ' || *buf == '\r' || *buf == '\n' || *buf == '\t') {
		++buf;
		--x;
	}
	if (buf != buffer) {
		memmove(buffer, buf, x);
		buffer[x] = '\x0';
	}

	return buffer;
}

/* sends all data - thanks to Beej's Guide to Network Programming */
int sendall(int s, char *buf, int *len)
{
	int total = 0;
	int bytesleft = *len;
	int n = 0;

	/* send all the data */
	while (total < *len) {
		n = send(s, buf + total, bytesleft, 0);	/* send some data */
		if (n == -1)			/* break on error */
			break;
		/* apply bytes we sent */
		total += n;
		bytesleft -= n;
	}

	*len = total;				/* return number of bytes actually sent here */
	return n == -1 ? -1 : 0;	/* return -1 on failure, 0 on success */
}

/* receives all data - modelled after sendall() */
int recvall(int s, char *buf, int *len, int timeout)
{
	time_t start_time;
	time_t current_time;
	int total = 0;
	int bytesleft = *len;
	int n = 0;

	bzero(buf, *len);			/* clear the receive buffer */
	time(&start_time);

	/* receive all data */
	while (total < *len) {
		n = recv(s, buf + total, bytesleft, 0);	/* receive some data */

		if (n == -1 && errno == EAGAIN) {
			/* no data has arrived yet (non-blocking socket) */
			time(&current_time);
			if (current_time - start_time > timeout)
				break;
			sleep(1);
			continue;
		} else if (n <= 0)
			break;				/* receive error or client disconnect */

		/* apply bytes we received */
		total += n;
		bytesleft -= n;
	}

	/* return number of bytes actually received here */
	*len = total;

	/* return <=0 on failure, bytes received on success */
	return (n <= 0) ? n : total;
}


/* fixes compiler problems under Solaris, since strsep() isn't included */

/* this code is taken from the glibc source */
char *my_strsep(char **stringp, const char *delim)
{
	char *begin, *end;

	begin = *stringp;
	if (begin == NULL)
		return NULL;

	/* A frequent case is when the delimiter string contains only one
	   character.  Here we don't need to call the expensive `strpbrk'
	   function and instead work using `strchr'.  */
	if (delim[0] == '\0' || delim[1] == '\0') {
		char ch = delim[0];

		if (ch == '\0')
			end = NULL;
		else {
			if (*begin == ch)
				end = begin;
			else
				end = strchr(begin + 1, ch);
		}

	} else
		end = strpbrk(begin, delim);	/* Find the end of the token.  */

	if (end) {
		/* Terminate the token and set *STRINGP past NUL character.  */
		*end++ = '\0';
		*stringp = end;
	} else
		/* No more delimiters; this is the last token.  */
		*stringp = NULL;

	return begin;
}

int b64_decode(unsigned char *encoded)
{
	static const char *b64 = {
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	};
	int i, j, l, padding = 0;
	unsigned char c[4], *outp = encoded;

	union {
		unsigned c3;
		struct {
			unsigned f1:6;
			unsigned f2:6;
			unsigned f3:6;
			unsigned f4:6;
		} fields;
	} enc;

	enc.c3 = 0;
	l = strlen((char *)encoded);
	for (i = 0; i < l; i += 4) {
		for (j = 0; j < 4; ++j) {
			if (encoded[i + j] == '=') {
				c[j] = 0;
				++padding;
			} else if (encoded[i + j] >= 'A' && encoded[i + j] <= 'Z')
				c[j] = encoded[i + j] - 'A';
			else if (encoded[i + j] >= 'a' && encoded[i + j] <= 'z')
				c[j] = encoded[i + j] - 'a' + 26;
			else if (encoded[i + j] >= '0' && encoded[i + j] <= '9')
				c[j] = encoded[i + j] - '0' + 52;
			else if (encoded[i + j] == '+')
				c[j] = encoded[i + j] - '+' + 62;
			else
				c[j] = encoded[i + j] - '/' + 63;
		}
		enc.fields.f1 = c[3];
		enc.fields.f2 = c[2];
		enc.fields.f3 = c[1];
		enc.fields.f4 = c[0];
		*outp++ = (enc.c3 >> 16) & 0xff;
		*outp++ = (enc.c3 >> 8) & 0xff;
		*outp++ = (enc.c3) & 0xff;
	}
	*outp = '\0';

	return outp - encoded - padding;
}

/* show license */
void display_license(void)
{
	printf("This program is released under the GPL (see below) with the additional\n");
	printf("exemption that compiling, linking, and/or using OpenSSL is allowed.\n\n");

	printf("This program is free software; you can redistribute it and/or modify\n");
	printf("it under the terms of the GNU General Public License as published by\n");
	printf("the Free Software Foundation; either version 2 of the License, or\n");
	printf("(at your option) any later version.\n\n");
	printf("This program is distributed in the hope that it will be useful,\n");
	printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
	printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
	printf("GNU General Public License for more details.\n\n");
	printf("You should have received a copy of the GNU General Public License\n");
	printf("along with this program; if not, write to the Free Software\n");
	printf("Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n\n");

	return;
}
