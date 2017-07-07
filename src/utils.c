/****************************************************************************
 *
 * utils.c - NRPE Utility Functions
 *
 * License: GPLv2
 * Copyright (c) 2009-2017 Nagios Enterprises
 *               1999-2008 Ethan Galstad (nagios@nagios.org)
 *
 * Description:
 *
 * This file contains common network functions used in nrpe and check_nrpe.
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

#include "../include/common.h"
#include "../include/utils.h"
#include <stdarg.h>
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#ifndef HAVE_ASPRINTF
extern int asprintf(char **ptr, const char *format, ...);
#endif
#ifndef HAVE_VASPRINTF
extern int vasprintf(char **ptr, const char *format, va_list ap);
#endif

#ifndef NI_MAXSERV
# define NI_MAXSERV 32
#endif

#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif

extern char **environ;

static unsigned long crc32_table[256];

char *log_file = NULL;
FILE *log_fp = NULL;

static int my_create_socket(struct addrinfo *ai, const char *bind_address, int redirect_stderr);


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
			   int address_family, const char *bind_address, int redirect_stderr)
#else
int my_connect(const char *host, struct sockaddr *hostaddr, u_short port,
			   int address_family, const char *bind_address, int redirect_stderr)
#endif
{
	struct addrinfo hints, *ai, *aitop;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
	int gaierr;
	int sock = -1;

	FILE *output = stderr;
	if (redirect_stderr)
		output = stdout;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = address_family;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, sizeof strport, "%u", port);
	if ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		fprintf(output, "Could not resolve hostname %.100s: %s\n", host, gai_strerror(gaierr));
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
			fprintf(output, "my_connect: getnameinfo failed\n");
			continue;
		}

		/* Create a socket for connecting. */
		sock = my_create_socket(ai, bind_address, redirect_stderr);
		if (sock < 0)
			continue;			/* Any error is already output */

		if (connect(sock, ai->ai_addr, ai->ai_addrlen) >= 0) {
			/* Successful connection. */
			memcpy(hostaddr, ai->ai_addr, ai->ai_addrlen);
			break;
		} else {
			fprintf(output, "connect to address %s port %s: %s\n", ntop, strport,
					strerror(errno));
			close(sock);
			sock = -1;
		}
	}

	freeaddrinfo(aitop);

	/* Return failure if we didn't get a successful connection. */
	if (sock == -1) {
		fprintf(output, "connect to host %s port %s: %s\n", host, strport, strerror(errno));
		return -1;
	}
	return sock;
}

/* Creates a socket for the connection. */
int my_create_socket(struct addrinfo *ai, const char *bind_address, int redirect_stderr)
{
	int sock, gaierr;
	struct addrinfo hints, *res;

	FILE *output = stderr;
	if (redirect_stderr)
		output = stdout;

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock < 0)
		fprintf(output, "socket: %.100s\n", strerror(errno));

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
		fprintf(output, "getaddrinfo: %s: %s\n", bind_address, gai_strerror(gaierr));
		close(sock);
		return -1;
	}
	if (bind(sock, res->ai_addr, res->ai_addrlen) < 0) {
		fprintf(output, "bind: %s: %s\n", bind_address, strerror(errno));
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
		logit(LOG_ERR, "bad addr or host: %s (%s)\n", addr ? addr : "<NULL>",
			   gai_strerror(gaierr));
		exit(1);
	}
	for (ai = aitop; ai->ai_next; ai = ai->ai_next) ;
	ai->ai_next = *listen_addrs;
	*listen_addrs = aitop;
}

int clean_environ(const char *keep_env_vars, const char *nrpe_user)
{
#if defined(HAVE_PATHS_H) && defined(_PATH_STDPATH)
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
		logit(LOG_ERR, "Could not sanitize the environment. Aborting!");
		return ERROR;
	}

	++keepcnt;
	i = strlen(keep);
	while (i--) {
		if (keep[i] == ',')
			++keepcnt;
	}

	if ((kept = calloc(keepcnt + 1, sizeof(char *))) == NULL) {
		logit(LOG_ERR, "Could not sanitize the environment. Aborting!");
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
			logit(LOG_ERR, "Could not sanitize the environment. Aborting!");
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


	char * user = NULL;

	if (nrpe_user != NULL) {
		user = strdup(nrpe_user);
		pw = (struct passwd *)getpwnam(nrpe_user);
	}

	if (nrpe_user == NULL || pw == NULL) {
		pw = (struct passwd *)getpwuid(getuid());
		if (pw != NULL) {
			user = strdup(pw->pw_name);
		}
	}
	
	if (pw == NULL) {
		free(user);
		return OK;
	}

	setenv("PATH", path, 1);
	setenv("IFS", " \t\n", 1);
	setenv("LOGNAME", user, 0);
	setenv("USER", user, 0);
	setenv("HOME", pw->pw_dir, 0);
	setenv("SHELL", pw->pw_shell, 0);

	free(user);

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

void open_log_file()
{
	int fh;
	int flags = O_RDWR|O_APPEND|O_CREAT;
	struct stat st;

	close_log_file();

	if (!log_file)
		return;

#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif
	if ((fh = open(log_file, flags, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) == -1) {
		printf("Warning: Cannot open log file '%s' for writing\n", log_file);
		logit(LOG_WARNING, "Warning: Cannot open log file '%s' for writing", log_file);
		return;
	}
	log_fp = fdopen(fh, "a+");
	if(log_fp == NULL) {
		printf("Warning: Cannot open log file '%s' for writing\n", log_file);
		logit(LOG_WARNING, "Warning: Cannot open log file '%s' for writing", log_file);
		return;
		}

	if ((fstat(fh, &st)) == -1) {
		log_fp = NULL;
		close(fh);
		printf("Warning: Cannot fstat log file '%s'\n", log_file);
		logit(LOG_WARNING, "Warning: Cannot fstat log file '%s'", log_file);
		return;
	}
	if (st.st_nlink != 1 || (st.st_mode & S_IFMT) != S_IFREG) {
		log_fp = NULL;
		close(fh);
		printf("Warning: log file '%s' has an invalid mode\n", log_file);
		logit(LOG_WARNING, "Warning: log file '%s' has an invalid mode", log_file);
		return;
	}

	(void)fcntl(fileno(log_fp), F_SETFD, FD_CLOEXEC);
}

void logit(int priority, const char *format, ...)
{
	time_t	log_time = 0L;
	va_list	ap;
	char	*buffer = NULL;

	if (!format || !*format)
		return;

	va_start(ap, format);
	if(vasprintf(&buffer, format, ap) > 0) {
		if (log_fp) {
			time(&log_time);
			/* strip any newlines from the end of the buffer */
			strip(buffer);

			/* write the buffer to the log file */
			fprintf(log_fp, "[%llu] %s\n", (unsigned long long)log_time, buffer);
			fflush(log_fp);

		} else
			syslog(priority, "%s", buffer);

		free(buffer);
	}
	va_end(ap);
}

void close_log_file()
{
	if(!log_fp)
		return;

	fflush(log_fp);
	fclose(log_fp);
	log_fp = NULL;
	return;
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
