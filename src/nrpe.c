/****************************************************************************
 *
 * nrpe.c - Nagios Remote Plugin Executor
 *
 * License: GPLv2
 * Copyright (c) 2009-2017 Nagios Enterprises
 *               1999-2008 Ethan Galstad (nagios@nagios.org)
 *
 * Command line: nrpe -c <config_file> [--inetd | --daemon]
 *
 * Description:
 *
 * This program is designed to run as a background process and
 * handle incoming requests (from the host running Nagios) for
 * plugin execution.  It is useful for running "local" plugins
 * such as check_users, check_load, check_disk, etc. without
 * having to use rsh or ssh.
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include "common.h"
#include "nrpe.h"
#include "utils.h"
#include "acl.h"
#include "nrpe-ssl.h"

#ifdef HAVE_SSL
# if defined(USE_SSL_DH) && !defined(AUTO_SSL_DH)
#  include "dh.h"
# endif
#endif

#ifndef HAVE_ASPRINTF
extern int asprintf(char **ptr, const char *format, ...);
#endif

#ifdef HAVE_LIBWRAP
int       allow_severity = LOG_INFO;
int       deny_severity = LOG_WARNING;
# ifndef HAVE_RFC931_TIMEOUT
int       rfc931_timeout=15;
# endif
#endif


#define DEFAULT_COMMAND_TIMEOUT			60	/* default timeout for execution of plugins */
#define MAXFD							64
#define NASTY_METACHARS					"|`&><'\\[]{};\r\n"
#define MAX_LISTEN_SOCKS				16
#define DEFAULT_LISTEN_QUEUE_SIZE		5
#define DEFAULT_SSL_SHUTDOWN_TIMEOUT	15

#define how_many(x,y) (((x)+((y)-1))/(y))

struct addrinfo *listen_addrs = NULL;
int       listen_socks[MAX_LISTEN_SOCKS];
char      remote_host[MAX_HOST_ADDRESS_LENGTH];
char     *macro_argv[MAX_COMMAND_ARGUMENTS];
char      config_file[MAX_INPUT_BUFFER] = "nrpe.cfg";
char      server_address[NI_MAXHOST] = "";
char     *command_name = NULL;
int       log_facility = LOG_DAEMON;
int       server_port = DEFAULT_SERVER_PORT;
int       num_listen_socks = 0;
int       address_family = AF_UNSPEC;
int       socket_timeout = DEFAULT_SOCKET_TIMEOUT;
int       command_timeout = DEFAULT_COMMAND_TIMEOUT;
int       connection_timeout = DEFAULT_CONNECTION_TIMEOUT;
int       ssl_shutdown_timeout = DEFAULT_SSL_SHUTDOWN_TIMEOUT;
char     *command_prefix = NULL;
int       packet_ver = 0;
command  *command_list = NULL;
char     *nrpe_user = NULL;
char     *nrpe_group = NULL;
char     *allowed_hosts = NULL;
char     *keep_env_vars = NULL;
char     *pid_file = NULL;
int       wrote_pid_file = FALSE;
int       allow_arguments = FALSE;
int       allow_bash_cmd_subst = FALSE;
int       allow_weak_random_seed = FALSE;
int       sigrestart = FALSE;
int       sigshutdown = FALSE;
int       show_help = FALSE;
int       show_license = FALSE;
int       show_version = FALSE;
int       use_inetd = TRUE;
int 	  commands_running = 0;
int       max_commands = 0;
int       debug = FALSE;
int       use_src = FALSE;		/* Define parameter for SRC option */
int       no_forking = FALSE;
int       listen_queue_size = DEFAULT_LISTEN_QUEUE_SIZE;
char     *nasty_metachars = NULL;
extern char *log_file;


SslParms sslprm = {
#if OPENSSL_VERSION_NUMBER >= 0x10100000
NULL, NULL, NULL, "ALL:!MD5:@STRENGTH:@SECLEVEL=0", TLSv1_plus, TRUE, 0, SSL_NoLogging
#else
NULL, NULL, NULL, "ALL:!MD5:@STRENGTH", TLSv1_plus, TRUE, 0, SSL_NoLogging
#endif
};

#ifdef HAVE_SSL
static int verify_callback(int ok, X509_STORE_CTX * ctx);
static void my_disconnect_sighandler(int sig);
static void complete_SSL_shutdown(SSL *);
#endif

int disable_syslog = FALSE;

int main(int argc, char **argv)
{
	int       result = OK;
	int       x;
	char      buffer[MAX_INPUT_BUFFER];

	init();

	/* process command-line args */
	result = process_arguments(argc, argv);
	if (result != OK || show_help == TRUE || show_license == TRUE || show_version == TRUE)
		usage(result);

	/* make sure the config file uses an absolute path */
	if (config_file[0] != '/') {

		/* save the name of the config file */
		strncpy(buffer, config_file, sizeof(buffer));
		buffer[sizeof(buffer) - 1] = '\x0';

		/* get absolute path of current working directory */
		config_file[0] = '\0';
		if (getcwd(config_file, sizeof(config_file)) == NULL) {
			printf("ERROR: getcwd(): %s, bailing out...\n", strerror(errno));
			exit(STATE_CRITICAL);
		}

		/* append a forward slash */
		strncat(config_file, "/", sizeof(config_file) - 2);
		config_file[sizeof(config_file) - 1] = '\x0';

		/* append the config file to the path */
		strncat(config_file, buffer, sizeof(config_file) - strlen(config_file) - 1);
		config_file[sizeof(config_file) - 1] = '\x0';
	}

	/* read the config file */
	result = read_config_file(config_file);
	/* exit if there are errors... */
	if (result == ERROR) {
		logit(LOG_ERR, "Config file '%s' contained errors, aborting...", config_file);
		return STATE_CRITICAL;
	}

	if (!nasty_metachars)
		nasty_metachars = strdup(NASTY_METACHARS);

	/* initialize macros */
	for (x = 0; x < MAX_COMMAND_ARGUMENTS; x++)
		macro_argv[x] = NULL;

	init_ssl();

	/* if we're running under inetd... */
	if (use_inetd == TRUE)
		run_inetd();

	else if (use_src == TRUE || no_forking == TRUE)
		run_src();

	else
		run_daemon();

#ifdef HAVE_SSL
	if (use_ssl == TRUE)
		SSL_CTX_free(ctx);
#endif

	/* We are now running in daemon mode, or the connection handed over by inetd has
	   been completed, so the parent process exits */
	return STATE_OK;
}

int init(void)
{
	char     *env_string = NULL;
	int       result = OK;

	/* set some environment variables */
	asprintf(&env_string, "NRPE_MULTILINESUPPORT=1");
	putenv(env_string);
	asprintf(&env_string, "NRPE_PROGRAMVERSION=%s", PROGRAM_VERSION);
	putenv(env_string);

	/* open a connection to the syslog facility */
	/* facility name may be overridden later */
	get_log_facility(NRPE_LOG_FACILITY);
	openlog("nrpe", LOG_PID, log_facility);

	/* generate the CRC 32 table */
	generate_crc32_table();

	return result;
}

void init_ssl(void)
{
#ifdef HAVE_SSL
	char          seedfile[FILENAME_MAX];
	char          errstr[256] = { "" };
	int           i, c, x, vrfy;
	unsigned long ssl_opts = SSL_OP_ALL | SSL_OP_SINGLE_DH_USE;

	if (use_ssl == FALSE) {
		if (debug == TRUE)
			logit(LOG_INFO, "INFO: SSL/TLS NOT initialized. Network encryption DISABLED.");
		return;
	}

#ifndef USE_SSL_DH
	ssl_opts = SSL_OP_ALL;
	sslprm.allowDH = 0;
#endif
#ifdef SSL_OP_NO_RENEGOTIATION
	ssl_opts |= SSL_OP_NO_RENEGOTIATION;
#endif
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
	ssl_opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;
#endif

	if (sslprm.log_opts & SSL_LogStartup)
		ssl_log_startup(TRUE);

	ssl_initialize();

	/* use week random seed if necessary */
	if (allow_weak_random_seed && (RAND_status() == 0)) {
		if (RAND_file_name(seedfile, sizeof(seedfile) - 1))
			if (RAND_load_file(seedfile, -1))
				RAND_write_file(seedfile);

		if (RAND_status() == 0) {
			logit(LOG_ERR,
				   "Warning: SSL/TLS uses a weak random seed which is highly discouraged");
			srand(time(NULL));
			for (i = 0; i < 500 && RAND_status() == 0; i++) {
				for (c = 0; c < sizeof(seedfile); c += sizeof(int)) {
					*((int *)(seedfile + c)) = rand();
				}
				RAND_seed(seedfile, sizeof(seedfile));
			}
		}
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000
	meth = TLS_server_method();
#else		/* OPENSSL_VERSION_NUMBER >= 0x10100000 */
	meth = SSLv23_server_method();
# ifndef OPENSSL_NO_SSL2
	if (sslprm.ssl_proto_ver == SSLv2)
		meth = SSLv2_server_method();
# endif
# ifndef OPENSSL_NO_SSL3
	if (sslprm.ssl_proto_ver == SSLv3)
		meth = SSLv3_server_method();
# endif
	if (sslprm.ssl_proto_ver == TLSv1)
		meth = TLSv1_server_method();
# ifdef SSL_TXT_TLSV1_1
	if (sslprm.ssl_proto_ver == TLSv1_1)
		meth = TLSv1_1_server_method();
#  ifdef SSL_TXT_TLSV1_2
	if (sslprm.ssl_proto_ver == TLSv1_2)
		meth = TLSv1_2_server_method();
#  ifdef SSL_TXT_TLSV1_3
	if (sslprm.ssl_proto_ver == TLSv1_3)
		meth = TLSv1_3_server_method();
#  endif	/* ifdef SSL_TXT_TLSV1_3 */
#  endif	/* ifdef SSL_TXT_TLSV1_2 */
# endif		/* SSL_TXT_TLSV1_1 */

#endif		/* OPENSSL_VERSION_NUMBER >= 0x10100000 */

	ctx = SSL_CTX_new(meth);
	if (ctx == NULL) {
		while ((x = ERR_get_error()) != 0) {
			ERR_error_string(x, errstr);
			logit(LOG_ERR, "Error: could not create SSL context : %s", errstr);
		}
		exit(STATE_CRITICAL);
	}

	ssl_set_protocol_version(sslprm.ssl_proto_ver, &ssl_opts);
	SSL_CTX_set_options(ctx, ssl_opts);

	if (!ssl_load_certificates()) {
		SSL_CTX_free(ctx);
		exit(STATE_CRITICAL);
	}

	if (sslprm.client_certs != 0) {
		if (sslprm.cacert_file == NULL) {
			logit(LOG_ERR, "Error: CA certificate required for client verification.");
			if ((sslprm.client_certs & Require_Cert) != 0) {
				SSL_CTX_free(ctx);
				exit(STATE_CRITICAL);
			}
		}
		vrfy = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
		if ((sslprm.client_certs & Require_Cert) != 0)
			vrfy |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		SSL_CTX_set_verify(ctx, vrfy, verify_callback);
	}

#ifdef AUTO_SSL_DH
	SSL_CTX_set_dh_auto(ctx, 1);
#else
# ifdef USE_SSL_DH
	{
#  if OPENSSL_VERSION_NUMBER >= 0x30000000
		EVP_PKEY *pkey = get_dh2048_key();
		if (pkey) {
				if (!SSL_CTX_set0_tmp_dh_pkey(ctx, pkey))
					EVP_PKEY_free(pkey);
		}
#  else
		DH *dh = get_dh2048();
		SSL_CTX_set_tmp_dh(ctx, dh);
		DH_free(dh);
#  endif
	}
# endif
#endif

	if (!ssl_set_ciphers()) {
		SSL_CTX_free(ctx);
		exit(STATE_CRITICAL);
	}

	if (debug == TRUE)
		logit(LOG_INFO, "INFO: SSL/TLS initialized. All network traffic will be encrypted.");
#endif
}

void usage(int result)
{
	if (result != OK) {
		printf("\n");
		printf("Incorrect command line arguments supplied\n");
		printf("\n");
	}
	printf("NRPE - Nagios Remote Plugin Executor\n");
	printf("Version: %s\n", PROGRAM_VERSION);
	printf("\n");
	if (result != OK || show_help == TRUE) {
		printf("Copyright (c) 2009-2017 Nagios Enterprises\n");
		printf("              1999-2008 Ethan Galstad (nagios@nagios.org)\n");
		printf("\n");
		printf("Last Modified: %s\n", MODIFICATION_DATE);
		printf("\n");
		printf("License: GPL v2 with exemptions (-l for more info)\n");
		printf("\n");
#ifdef HAVE_SSL
		printf("SSL/TLS Available, OpenSSL 0.9.6 or higher required\n");
		printf("\n");
#endif
#ifdef HAVE_LIBWRAP
		printf("TCP Wrappers Available\n");
		printf("\n");
#endif
#ifdef ENABLE_COMMAND_ARGUMENTS
		printf("***************************************************************\n");
		printf("** POSSIBLE SECURITY RISK - COMMAND ARGUMENTS ARE SUPPORTED! **\n");
		printf("**      Read the NRPE SECURITY file for more information     **\n");
		printf("***************************************************************\n");
		printf("\n");
#endif
#ifndef HAVE_LIBWRAP
		printf("***************************************************************\n");
		printf("** POSSIBLE SECURITY RISK - TCP WRAPPERS ARE NOT AVAILABLE!  **\n");
		printf("**      Read the NRPE SECURITY file for more information     **\n");
		printf("***************************************************************\n");
		printf("\n");
#endif
		printf("Usage: nrpe [-V] [-n] -c <config_file> [-4|-6] <mode>\n");
		printf("\n");
		printf("Options:\n");
		printf(" -V, --version         Print version info and quit\n");
		printf(" -n, --no-ssl          Do not use SSL\n");
		printf(" -c, --config=FILE     Name of config file to use\n");
		printf(" -4, --ipv4            Use ipv4 only\n");
		printf(" -6, --ipv6            Use ipv6 only\n");
		printf(" <mode> (One of the following operating modes)\n");
		printf("   -i, --inetd         Run as a service under inetd or xinetd\n");
		printf("   -d, --daemon        Run as a standalone daemon\n");
		printf("   -s, --src           Run as a subsystem under AIX\n");
		printf("   -f, --no-forking    Don't fork() (for systemd, launchd, etc.)\n");
		printf("\n");
		printf("Notes:\n");
		printf("This program is designed to process requests from the check_nrpe\n");
		printf("plugin on the host(s) running Nagios.  It can run as a service\n");
		printf("under inetd or xinetd (read the docs for info on this), or as a\n");
		printf("standalone daemon. Once a request is received from an authorized\n");
		printf("host, NRPE will execute the command/plugin (as defined in the\n");
		printf("config file) and return the plugin output and return code to the\n");
		printf("check_nrpe plugin.\n");
		printf("\n");
	}

	if (show_license == TRUE)
		display_license();

	exit(STATE_UNKNOWN);
}

void run_inetd(void)
{
	check_privileges();			/* make sure we're not root */
	close(2);					/* redirect STDERR to /dev/null */
	open("/dev/null", O_WRONLY);
	handle_connection(0);		/* handle the connection */
}

void run_src(void)
{
	/* if we're running under SRC we don't fork but does drop-privileges */

	set_stdio_sigs();

	do {
		/* reset flags */
		sigrestart = FALSE;
		sigshutdown = FALSE;

		wait_for_connections();	/* wait for connections */
		cleanup();
	} while (sigrestart == TRUE && sigshutdown == FALSE);
}

/* daemonize and start listening for requests... */
void run_daemon(void)
{
	pid_t     pid;

	pid = fork();

	if (pid != 0) {
		if (pid == -1) {
			logit(LOG_ERR, "fork() failed with error %d, bailing out...", errno);
			exit(STATE_CRITICAL);
		}

		return;
	}

	setsid();					/* we're a daemon - set up a new process group */
	set_stdio_sigs();

	do {
		/* reset flags */
		sigrestart = FALSE;
		sigshutdown = FALSE;

		wait_for_connections();	/* wait for connections */
		cleanup();
	} while (sigrestart == TRUE && sigshutdown == FALSE);
}

void set_stdio_sigs(void)
{
#ifdef HAVE_SIGACTION
	struct sigaction sig_action;
#endif

	if (chdir("/") == -1) {
		printf("ERROR: chdir(): %s, bailing out...\n", strerror(errno));
		exit(STATE_CRITICAL);
	}

	close(0);					/* close standard file descriptors */
	close(1);
	close(2);
	open("/dev/null", O_RDONLY);	/* redirect standard descriptors to /dev/null */
	open("/dev/null", O_WRONLY);
	open("/dev/null", O_WRONLY);

	/* handle signals */
#ifdef HAVE_SIGACTION
	sig_action.sa_sigaction = NULL;
	sig_action.sa_handler = sighandler;
	sigfillset(&sig_action.sa_mask);
	sig_action.sa_flags = SA_NODEFER | SA_RESTART;
	sigaction(SIGQUIT, &sig_action, NULL);
	sigaction(SIGTERM, &sig_action, NULL);
	sigaction(SIGHUP, &sig_action, NULL);
#else	 /* HAVE_SIGACTION */
	signal(SIGQUIT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGHUP, sighandler);
#endif	 /* HAVE_SIGACTION */

	logit(LOG_NOTICE, "Starting up daemon");	/* log info */
	if (write_pid_file() == ERROR)	/* write pid file */
		exit(STATE_CRITICAL);

	clean_environ(keep_env_vars, nrpe_user);

	/* drop and then check privileges */
	drop_privileges(nrpe_user, nrpe_group, 0);
	check_privileges();
}

void cleanup(void)
{
	int       result;

	free_memory();				/* free all memory we allocated */

	if (sigrestart == TRUE && sigshutdown == FALSE) {
		close_log_file();
		result = read_config_file(config_file);	/* read the config file */

		if (result == ERROR) {	/* exit if there are errors... */
			logit(LOG_ERR, "Config file '%s' contained errors, bailing out...", config_file);
			exit(STATE_CRITICAL);
		}
		return;
	}

	remove_pid_file();			/* remove pid file */
	logit(LOG_NOTICE, "Daemon shutdown\n");

	close_log_file();			/* close the log file */
}

#ifdef HAVE_SSL
int verify_callback(int preverify_ok, X509_STORE_CTX * ctx)
{
	return ssl_verify_callback_common(preverify_ok, ctx, !preverify_ok);
}
#endif

/*
 * Given a string, convert any byte pairs representing an escape sequence (e.g. "\\r" into 
 * the single-byte metacharacter (e.g. '\r')
 * Currently, this doesn't support octal/hex numbers or unicode code points (\n, \x, \u, \U)
 */
char* process_metachars(const char* input)
{
	char* copy = strdup(input);
	int i,j;
	int length = strlen(input);
	for (i = 0, j = 0; j < length; i++, j++) {
		if (copy[j] != '\\') {
			copy[i] = copy[j];
			continue;
		}

		j += 1;
		switch (copy[j]) {
			case 'a':
				copy[i] = '\a';
				break;
			case 'b':
				copy[i] = '\b';
				break;
			case 'f':
				copy[i] = '\f';
				break;
			case 'n':
				copy[i] = '\n';
				break;
			case 'r':
				copy[i] = '\r';
				break;
			case 't':
				copy[i] = '\t';
				break;
			case 'v':
				copy[i] = '\v';
				break;
			case '\\':
				copy[i] = '\\';
				break;
			case '\'':
				copy[i] = '\'';
				break;
			case '"':
				copy[i] = '\"';
				break;
			case '?':
				copy[i] = '\?';
				break;
		}
	}
	copy[i] = '\0';

	return copy;
}

/* read in the configuration file */
int read_config_file(char *filename)
{
	FILE     *fp;
	char      config_file[MAX_FILENAME_LENGTH];
	char      input_buffer[MAX_INPUT_BUFFER];
	char     *input_line;
	char     *temp_buffer;
	char     *varname;
	char     *varvalue;
	int       line = 0;
	int       len = 0;
	int       x = 0;

	fp = fopen(filename, "r");	/* open the config file for reading */

	/* exit if we couldn't open the config file */
	if (fp == NULL) {
		logit(LOG_ERR, "Unable to open config file '%s' for reading\n", filename);
		return ERROR;
	}

	while (fgets(input_buffer, MAX_INPUT_BUFFER - 1, fp)) {
		line++;
		input_line = input_buffer;

		/* skip leading whitespace */
		while (isspace(*input_line))
			++input_line;

		/* trim trailing whitespace */
		len = strlen(input_line);
		for (x = len - 1; x >= 0; x--) {
			if (isspace(input_line[x]))
				input_line[x] = '\x0';
			else
				break;
		}

		/* skip comments and blank lines */
		if (input_line[0] == '#' || input_line[0] == '\x0' || input_line[0] == '\n')
			continue;

		/* get the variable name */
		varname = strtok(input_line, "=");
		if (varname == NULL) {
			logit(LOG_ERR, "No variable name specified in config file '%s' - Line %d\n",
				   filename, line);
			return ERROR;
		}

		/* get the variable value */
		varvalue = strtok(NULL, "\n");
		if (varvalue == NULL) {
			logit(LOG_ERR, "No variable value specified in config file '%s' - Line %d\n",
				   filename, line);
			return ERROR;

		} else if (!strcmp(varname, "include_dir")) {
			/* allow users to specify directories to recurse into for config files */

			strncpy(config_file, varvalue, sizeof(config_file) - 1);
			config_file[sizeof(config_file) - 1] = '\x0';

			/* strip trailing / if necessary */
			if (config_file[strlen(config_file) - 1] == '/')
				config_file[strlen(config_file) - 1] = '\x0';

			/* process the config directory... */
			if (read_config_dir(config_file) == ERROR)
				logit(LOG_ERR, "Continuing with errors...");

		} else if (!strcmp(varname, "include") || !strcmp(varname, "include_file")) {
			/* allow users to specify individual config files to include */

			/* process the config file... */
			if (read_config_file(varvalue) == ERROR)
				logit(LOG_ERR, "Continuing with errors...");

		} else if (!strcmp(varname, "max_commands")) {

			max_commands = atoi(varvalue);
			if (max_commands < 0) {
				logit(LOG_WARNING, "max_commands set too low, setting to 0\n");
				max_commands = 0;
			}

		} else if (!strcmp(varname, "server_port")) {
			server_port = atoi(varvalue);
			if (server_port < 1024) {
				logit(LOG_ERR,
					   "Invalid port number specified in config file '%s' - Line %d\n",
					   filename, line);
				return ERROR;
			}

		} else if (!strcmp(varname, "command_prefix"))
			command_prefix = strdup(varvalue);

		else if (!strcmp(varname, "server_address")) {
			strncpy(server_address, varvalue, sizeof(server_address) - 1);
			server_address[sizeof(server_address) - 1] = '\0';

		} else if (!strcmp(varname, "allowed_hosts")) {
			allowed_hosts = strdup(varvalue);
			parse_allowed_hosts(allowed_hosts);
			if (debug == TRUE)
				show_acl_lists();

		} else if (strstr(input_line, "command[")) {
			temp_buffer = strtok(varname, "[");
			temp_buffer = strtok(NULL, "]");
			if (temp_buffer == NULL) {
				logit(LOG_ERR, "Invalid command specified in config file '%s' - Line %d\n",
					   filename, line);
				return ERROR;
			}
			add_command(temp_buffer, varvalue);

		} else if (strstr(input_buffer, "debug")) {
			debug = atoi(varvalue);
			if (debug > 0)
				debug = TRUE;
			else
				debug = FALSE;

		} else if (!strcmp(varname, "nrpe_user"))
			nrpe_user = strdup(varvalue);

		else if (!strcmp(varname, "nrpe_group"))
			nrpe_group = strdup(varvalue);

		else if (!strcmp(varname, "dont_blame_nrpe"))
			allow_arguments = (atoi(varvalue) == 1) ? TRUE : FALSE;

		else if (!strcmp(varname, "disable_syslog"))
			disable_syslog = (atoi(varvalue) == 1) ? TRUE : FALSE;

		else if (!strcmp(varname, "allow_bash_command_substitution"))
			allow_bash_cmd_subst = (atoi(varvalue) == 1) ? TRUE : FALSE;

		else if (!strcmp(varname, "command_timeout")) {
			command_timeout = atoi(varvalue);
			if (command_timeout < 1) {
				logit(LOG_ERR,
					   "Invalid command_timeout specified in config file '%s' - Line %d\n",
					   filename, line);
				return ERROR;
			}
		} else if (!strcmp(varname, "connection_timeout")) {
			connection_timeout = atoi(varvalue);
			if (connection_timeout < 1) {
				logit(LOG_ERR,
					   "Invalid connection_timeout specified in config file '%s' - Line %d\n",
					   filename, line);
				return ERROR;
			}

		} else if (!strcmp(varname, "ssl_shutdown_timeout")) {
			ssl_shutdown_timeout = atoi(varvalue);
			if (ssl_shutdown_timeout < 1) {
				logit(LOG_ERR,
					   "Invalid ssl_shutdown_timeout specified in config file '%s' - Line %d\n",
					   filename, line);
				return ERROR;
			}

		} else if (!strcmp(varname, "allow_weak_random_seed"))
			allow_weak_random_seed = (atoi(varvalue) == 1) ? TRUE : FALSE;

		else if (!strcmp(varname, "pid_file"))
			pid_file = strdup(varvalue);

		else if (!strcmp(varname, "listen_queue_size")) {
			listen_queue_size = atoi(varvalue);
			if (listen_queue_size == 0) {
				logit(LOG_ERR,
					   "Invalid listen queue size specified in config file '%s' - Line %d\n",
					   filename, line);
				return ERROR;
			}

		} else if (!strcmp(varname, "ssl_version")) {
			if (!strcmp(varvalue, "TLSv1.3"))
				sslprm.ssl_proto_ver = TLSv1_3;
			else if (!strcmp(varvalue, "TLSv1.3+"))
				sslprm.ssl_proto_ver = TLSv1_3_plus;
			else if (!strcmp(varvalue, "TLSv1.2"))
				sslprm.ssl_proto_ver = TLSv1_2;
			else if (!strcmp(varvalue, "TLSv1.2+"))
				sslprm.ssl_proto_ver = TLSv1_2_plus;
			else if (!strcmp(varvalue, "TLSv1.1"))
				sslprm.ssl_proto_ver = TLSv1_1;
			else if (!strcmp(varvalue, "TLSv1.1+"))
				sslprm.ssl_proto_ver = TLSv1_1_plus;
			else if (!strcmp(varvalue, "TLSv1"))
				sslprm.ssl_proto_ver = TLSv1;
			else if (!strcmp(varvalue, "TLSv1+"))
				sslprm.ssl_proto_ver = TLSv1_plus;
			else if (!strcmp(varvalue, "SSLv3"))
				sslprm.ssl_proto_ver = SSLv3;
			else if (!strcmp(varvalue, "SSLv3+"))
				sslprm.ssl_proto_ver = SSLv3_plus;
#if OPENSSL_VERSION_NUMBER < 0x10100000
			else if (!strcmp(varvalue, "SSLv2"))
				sslprm.ssl_proto_ver = SSLv2;
			else if (!strcmp(varvalue, "SSLv2+"))
				sslprm.ssl_proto_ver = SSLv2_plus;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */
			else {
				logit(LOG_ERR, "Invalid ssl version specified in config file '%s' - Line %d",
					   filename, line);
				return ERROR;
			}

		} else if (!strcmp(varname, "ssl_use_adh")) {
			sslprm.allowDH = atoi(varvalue);
			if (sslprm.allowDH < 0 || sslprm.allowDH > 2) {
				logit(LOG_ERR,
					   "Invalid use adh value specified in config file '%s' - Line %d",
					   filename, line);
				return ERROR;
			}

		} else if (!strcmp(varname, "ssl_logging"))
			sslprm.log_opts = strtoul(varvalue, NULL, 0);

		else if (!strcmp(varname, "ssl_cipher_list")) {
			strncpy(sslprm.cipher_list, varvalue, sizeof(sslprm.cipher_list) - 1);
			sslprm.cipher_list[sizeof(sslprm.cipher_list) - 1] = '\0';

		} else if (!strcmp(varname, "ssl_cert_file"))
			sslprm.cert_file = strdup(varvalue);

		else if (!strcmp(varname, "ssl_cacert_file"))
			sslprm.cacert_file = strdup(varvalue);

		else if (!strcmp(varname, "ssl_privatekey_file"))
			sslprm.privatekey_file = strdup(varvalue);

		else if (!strcmp(varname, "ssl_client_certs")) {
			sslprm.client_certs = atoi(varvalue);
			if ((int)sslprm.client_certs < 0 || sslprm.client_certs > Require_Cert) {
				logit(LOG_ERR,
					   "Invalid client certs value specified in config file '%s' - Line %d",
					   filename, line);
				return ERROR;
			}
			/* if requiring or logging client certs, make sure "Ask" is turned on */
			if (sslprm.client_certs & Require_Cert)
				sslprm.client_certs |= Ask_For_Cert;

		} else if (!strcmp(varname, "log_facility")) {
			if ((get_log_facility(varvalue)) == OK) {
				/* re-open log using new facility */
				closelog();
				openlog("nrpe", LOG_PID, log_facility);
			} else
				logit(LOG_WARNING,
					   "Invalid log_facility specified in config file '%s' - Line %d\n",
					   filename, line);

		} else if (!strcmp(varname, "keep_env_vars"))
			keep_env_vars = strdup(varvalue);

		else if (!strcmp(varname, "nasty_metachars"))
			nasty_metachars = process_metachars(varvalue);

		else if (!strcmp(varname, "log_file")) {
			log_file = strdup(varvalue);
			open_log_file();

		} else {
			logit(LOG_WARNING, "Unknown option specified in config file '%s' - Line %d\n",
				   filename, line);
			continue;
		}
	}

	fclose(fp);					/* close the config file */
	return OK;
}

/* process all config files in a specific config directory (with directory recursion) */
int read_config_dir(char *dirname)
{
	struct dirent *dirfile;
#ifdef HAVE_SCANDIR
	struct dirent **dirfiles;
	int       x, i, n;
#else
	DIR      *dirp;
	int       x;
#endif
	struct stat buf;
	char      config_file[MAX_FILENAME_LENGTH];
	int       result = OK;
	int rc;

#ifdef HAVE_SCANDIR
	/* read and sort the directory contents */
	n = scandir(dirname, &dirfiles, 0, alphasort);
	if (n < 0) {
		logit(LOG_ERR, "Could not open config directory '%s' for reading.\n", dirname);
		return ERROR;
	}

	for (i = 0; i < n; i++) {
		dirfile = dirfiles[i];
#else
	/* open the directory for reading */
	dirp = opendir(dirname);
	if (dirp == NULL) {
		logit(LOG_ERR, "Could not open config directory '%s' for reading.\n", dirname);
		return ERROR;
	}

	while ((dirfile = readdir(dirp)) != NULL) {
#endif

		/* process all files in the directory... */

		/* create the full path to the config file or subdirectory */
		rc = snprintf(config_file, sizeof(config_file) - 1, "%s/%s", dirname, dirfile->d_name);
		if (rc >= sizeof(config_file) - 1) {
			logit(LOG_ERR, "Config file path too long '%s/%s'.\n", dirname, dirfile->d_name);
			return ERROR;
		}
		config_file[sizeof(config_file) - 1] = '\x0';
		stat(config_file, &buf);

		/* process this if it's a config file... */
		x = strlen(dirfile->d_name);
		if (x > 4 && !strcmp(dirfile->d_name + (x - 4), ".cfg")) {

			/* only process normal files */
			if (!S_ISREG(buf.st_mode))
				continue;

			/* process the config file */
			result |= read_config_file(config_file);
		}

		/* recurse into subdirectories... */
		if (S_ISDIR(buf.st_mode)) {

			/* ignore current, parent and hidden directory entries */
			if (dirfile->d_name[0] == '.')
				continue;

			/* process the config directory */
			result |= read_config_dir(config_file);
		}
	}

#ifdef HAVE_SCANDIR
	for (i = 0; i < n; i++)
		free(dirfiles[i]);
	free(dirfiles);
#else
	closedir(dirp);
#endif

	return result;
}

/* determines facility to use with syslog */
int get_log_facility(char *varvalue)
{
	if (!strcmp(varvalue, "kern"))
		log_facility = LOG_KERN;
	else if (!strcmp(varvalue, "user"))
		log_facility = LOG_USER;
	else if (!strcmp(varvalue, "mail"))
		log_facility = LOG_MAIL;
	else if (!strcmp(varvalue, "daemon"))
		log_facility = LOG_DAEMON;
	else if (!strcmp(varvalue, "auth"))
		log_facility = LOG_AUTH;
	else if (!strcmp(varvalue, "syslog"))
		log_facility = LOG_SYSLOG;
	else if (!strcmp(varvalue, "lrp"))
		log_facility = LOG_LPR;
	else if (!strcmp(varvalue, "news"))
		log_facility = LOG_NEWS;
	else if (!strcmp(varvalue, "uucp"))
		log_facility = LOG_UUCP;
	else if (!strcmp(varvalue, "cron"))
		log_facility = LOG_CRON;
	else if (!strcmp(varvalue, "authpriv"))
		log_facility = LOG_AUTHPRIV;
	else if (!strcmp(varvalue, "ftp"))
		log_facility = LOG_FTP;
	else if (!strcmp(varvalue, "local0"))
		log_facility = LOG_LOCAL0;
	else if (!strcmp(varvalue, "local1"))
		log_facility = LOG_LOCAL1;
	else if (!strcmp(varvalue, "local2"))
		log_facility = LOG_LOCAL2;
	else if (!strcmp(varvalue, "local3"))
		log_facility = LOG_LOCAL3;
	else if (!strcmp(varvalue, "local4"))
		log_facility = LOG_LOCAL4;
	else if (!strcmp(varvalue, "local5"))
		log_facility = LOG_LOCAL5;
	else if (!strcmp(varvalue, "local6"))
		log_facility = LOG_LOCAL6;
	else if (!strcmp(varvalue, "local7"))
		log_facility = LOG_LOCAL7;
	else {
		log_facility = LOG_DAEMON;
		return ERROR;
	}

	return OK;
}

/* adds a new command definition from the config file to the list in memory */
int add_command(char *command_name, char *command_line)
{
	command  *new_command;

	if (command_name == NULL || command_line == NULL)
		return ERROR;

	/* allocate memory for the new command */
	new_command = (command *) malloc(sizeof(command));
	if (new_command == NULL)
		return ERROR;

	new_command->command_name = strdup(command_name);
	if (new_command->command_name == NULL) {
		free(new_command);
		return ERROR;
	}
	new_command->command_line = strdup(command_line);
	if (new_command->command_line == NULL) {
		free(new_command->command_name);
		free(new_command);
		return ERROR;
	}

	/* add new command to head of list in memory */
	new_command->next = command_list;
	command_list = new_command;

	if (debug == TRUE)
		logit(LOG_DEBUG, "Added command[%s]=%s\n", command_name, command_line);

	return OK;
}

/* given a command name, find the structure in memory */
command  *find_command(char *command_name)
{
	command  *temp_command;

	for (temp_command = command_list; temp_command != NULL; temp_command = temp_command->next)
		if (!strcmp(command_name, temp_command->command_name))
			return temp_command;

	return NULL;
}

/* Start listen on a particular port */
void create_listener(struct addrinfo *ai)
{
	int       ret;
	char      ntop[NI_MAXHOST], strport[NI_MAXSERV];
	int       listen_sock;
	int       flag = 1;

	if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
		return;

	if (num_listen_socks >= MAX_LISTEN_SOCKS) {
		logit(LOG_ERR, "Too many listen sockets. Enlarge MAX_LISTEN_SOCKS");
		exit(1);
	}

	if ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, sizeof(ntop),
						   strport, sizeof(strport), NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
		logit(LOG_ERR, "getnameinfo failed: %.100s", gai_strerror(ret));
		return;
	}

	/* Create socket for listening. */
	listen_sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (listen_sock < 0) {
		/* kernel may not support ipv6 */
		logit(LOG_ERR, "socket: %.100s", strerror(errno));
		return;
	}

	/* socket should be non-blocking */
	fcntl(listen_sock, F_SETFL, O_NONBLOCK);

	/* set the reuse address flag so we don't get errors when restarting */
	if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
		logit(LOG_ERR, "setsockopt SO_REUSEADDR: %s", strerror(errno));
		return;
	}
#ifdef IPV6_V6ONLY
	/* Only communicate in IPv6 over AF_INET6 sockets. */
	if (ai->ai_family == AF_INET6) {
		if (setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag)) == -1) {
			fprintf(stderr, "setsockopt IPV6_V6ONLY: %s", strerror(errno));
		}
	}
#endif

	/* Bind the socket to the desired port. */
	if (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) < 0) {
		logit(LOG_ERR, "Bind to port %s on %s failed: %.200s.",
			   strport, ntop, strerror(errno));
		close(listen_sock);
		return;
	}
	listen_socks[num_listen_socks] = listen_sock;
	num_listen_socks++;

	/* Start listening on the port. */
	if (listen(listen_sock, listen_queue_size) < 0) {
		logit(LOG_ERR, "listen on [%s]:%s: %.100s", ntop, strport, strerror(errno));
		exit(1);
	}

	logit(LOG_INFO, "Server listening on %s port %s.", ntop, strport);
}

/* Close all listening sockets */
static void close_listen_socks(void)
{
	int       i;

	for (i = 0; i <= num_listen_socks; i++) {
		close(listen_socks[i]);
		num_listen_socks--;
	}
}

/* wait for incoming connection requests */
void wait_for_connections(void)
{
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
	struct sockaddr_storage from;
#else
	struct sockaddr from;
#endif
	socklen_t fromlen;
	fd_set   *fdset = NULL;
	int       maxfd = 0, new_sd = 0, i, rc, retval;

	setup_wait_conn();

	/* listen for connection requests - fork() if we get one */
	while (1) {
		/* bail out if necessary */
		if (sigrestart == TRUE || sigshutdown == TRUE)
			break;

		for (i = 0; i < num_listen_socks; i++) {
			if (listen_socks[i] > maxfd)
				maxfd = listen_socks[i];
		}

		if (fdset != NULL)
			free(fdset);
		fdset = (fd_set *) calloc(how_many(maxfd + 1, NFDBITS), sizeof(fd_mask));

		for (i = 0; i < num_listen_socks; i++)
			FD_SET(listen_socks[i], fdset);

		/* Wait in select until there is a connection. */
		retval = select(maxfd + 1, fdset, NULL, NULL, NULL);

		/* bail out if necessary */
		if (sigrestart == TRUE || sigshutdown == TRUE)
			break;

		/* error */
		if (retval < 0)
			continue;

		for (i = 0; i < num_listen_socks; i++) {
			if (!FD_ISSET(listen_socks[i], fdset))
				continue;
			fromlen = (socklen_t)sizeof(from);

			/* accept a new connection request */
			new_sd = accept(listen_socks[i], (struct sockaddr *)&from, &fromlen);

			/* some kind of error occurred... */
			if (new_sd < 0) {
				/* bail out if necessary */
				if (sigrestart == TRUE || sigshutdown == TRUE)
					break;
				if (errno == EWOULDBLOCK || errno == EINTR)	/* retry */
					continue;
				/* socket is nonblocking and we don't have a connection yet */
				if (errno == EAGAIN)
					continue;
				if (errno == ENOBUFS)	/* fix for HP-UX 11.0 - just retry */
					continue;

				break;			/* else handle the error later */
			}


			rc = wait_conn_fork(new_sd);
			if (rc == TRUE)
				continue;		/* Continue if this is the parent returning */

			/* grandchild running here */
			conn_check_peer(new_sd);

			/* handle the client connection */
			handle_connection(new_sd);

			/* log info */
			if (debug == TRUE)
				logit(LOG_DEBUG, "Connection from %s closed.", remote_host);

			/* close socket prior to exiting */
			close(new_sd);

			exit(STATE_OK);

		}
	}

	/* close the sockets we're listening on */
	close_listen_socks();
	freeaddrinfo(listen_addrs);
	listen_addrs = NULL;

	return;
}

void setup_wait_conn(void)
{
	struct addrinfo *ai;
	char	addrstr[100];
	void	*ptr;

	add_listen_addr(&listen_addrs, address_family,
					(strcmp(server_address, "") == 0) ? NULL : server_address, server_port);

	for (ai = listen_addrs; ai; ai = ai->ai_next) {
		if (debug == TRUE) {
			char *fam = "";
			inet_ntop (ai->ai_family, ai->ai_addr->sa_data, addrstr, 100);
			ptr = &((struct sockaddr_in *) ai->ai_addr)->sin_addr;
			inet_ntop (ai->ai_family, ptr, addrstr, 100);
			if (ai->ai_family == AF_INET)
				fam = "AF_INET";
			else if (ai->ai_family == AF_INET6)
				fam = "AF_INET6";
			logit(LOG_INFO, "SETUP_WAIT_CONN FOR: %s address: %s (%s)\n", fam, addrstr, ai->ai_canonname);
		}
		create_listener(ai);
	}

	if (!num_listen_socks) {
		logit(LOG_ERR, "Cannot bind to any address.");
		exit(1);
	}

	/* log warning about command arguments */
#ifdef ENABLE_COMMAND_ARGUMENTS
	if (allow_arguments == TRUE)
		logit(LOG_NOTICE,
			   "Warning: Daemon is configured to accept command arguments from clients!");
# ifdef ENABLE_BASH_COMMAND_SUBSTITUTION
	if (TRUE == allow_bash_cmd_subst) {
		if (TRUE == allow_arguments)
			logit(LOG_NOTICE,
				   "Warning: Daemon is configured to accept command arguments with bash command substitutions!");
		else
			logit(LOG_NOTICE,
				   "Warning: Daemon is configured to accept command arguments with bash command substitutions, but is not configured to accept command arguments from clients. Enable command arguments if you wish to allow command arguments with bash command substitutions.");
	}
# endif
#endif

	logit(LOG_INFO, "Listening for connections on port %d", server_port);

	if (allowed_hosts)
		logit(LOG_INFO, "Allowing connections from: %s\n", allowed_hosts);
}

int wait_conn_fork(int sock)
{
#ifdef HAVE_SIGACTION
	struct sigaction sig_action;
#endif
	pid_t     pid;

	/* child process should handle the connection */
	pid = fork();

	if (pid > 0) {
		close(sock);			/* parent doesn't need the new connection */
		waitpid(pid, NULL, 0);	/* parent waits for first child to exit */
		return TRUE;			/* tell caller this is the parent process */
	}

	if (pid < 0) {
		logit(LOG_ERR, "fork() failed with error %d, bailing out...", errno);
		exit(STATE_CRITICAL);
	}

	/* fork again so we don't create zombies */
	pid = fork();

	if (pid < 0) {
		logit(LOG_ERR, "Second fork() failed with error %d, bailing out...", errno);
		exit(STATE_CRITICAL);
	}

	if (pid > 0) {
		/* first child returns immediately, grandchild is inherited by
		   INIT process -> no zombies... */
		exit(STATE_OK);
	}

	/* hey, there was an error... */
	if (sock < 0) {
		/* log error */
		logit(LOG_ERR, "Network server accept failure (%d: %s)",
			   errno, strerror(errno));
		exit(STATE_OK);
	}

	/* all good - handle signals */
#ifdef HAVE_SIGACTION
	sig_action.sa_sigaction = NULL;
	sig_action.sa_handler = child_sighandler;
	sigfillset(&sig_action.sa_mask);
	sig_action.sa_flags = SA_NODEFER | SA_RESTART;
	sigaction(SIGQUIT, &sig_action, NULL);
	sigaction(SIGTERM, &sig_action, NULL);
	sigaction(SIGHUP, &sig_action, NULL);
#else	 /* HAVE_SIGACTION */
	signal(SIGQUIT, child_sighandler);
	signal(SIGTERM, child_sighandler);
	signal(SIGHUP, child_sighandler);
#endif	 /* HAVE_SIGACTION */

	close_listen_socks();		/* grandchild does not need to listen */

	return FALSE;				/* tell caller this isn't the parent process */
}

void conn_check_peer(int sock)
{
#ifdef HAVE_LIBWRAP
	struct request_info     req;
#endif
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
	struct sockaddr_storage addr;
#else
	struct sockaddr			addr;
#endif
	struct sockaddr_in      *nptr;
	struct sockaddr_in6     *nptr6;

	char      ipstr[INET6_ADDRSTRLEN];
	socklen_t addrlen;
	int       rc;

	/* find out who just connected... */
	addrlen = sizeof(addr);
	rc = getpeername(sock, (struct sockaddr *)&addr, &addrlen);

	if (rc < 0) {
		/* log error */
		logit(LOG_ERR, "Error: Network server getpeername() failure (%d: %s)",
			   errno, strerror(errno));

		/* close socket prior to exiting */
		close(sock);
		return;
	}

#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
	switch (addr.ss_family) {
#else
	switch (addr.sa_family) {
#endif

	case AF_INET:
		nptr = (struct sockaddr_in *)&addr;
		strncpy(remote_host, inet_ntoa(nptr->sin_addr), sizeof(remote_host) - 1);
		remote_host[MAX_HOST_ADDRESS_LENGTH - 1] = '\0';
		break;

	case AF_INET6:
		nptr6 = (struct sockaddr_in6 *)&addr;
		if (inet_ntop(AF_INET6, (const void *)&(nptr6->sin6_addr),
					  ipstr, sizeof(ipstr)) == NULL) {
			strncpy(ipstr, "Unknown", sizeof(ipstr));
		}
		strncpy(remote_host, ipstr, sizeof(remote_host) - 1);
		remote_host[MAX_HOST_ADDRESS_LENGTH - 1] = '\0';
		break;
	}

	if (debug == TRUE)
		logit(LOG_INFO, "CONN_CHECK_PEER: checking if host is allowed: %s port %d\n",
			 remote_host, nptr->sin_port);

	/* is this host allowed? */
	if (allowed_hosts) {
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
		switch (addr.ss_family) {
#else
		switch (addr.sa_family) {
#endif

		case AF_INET:
			/* log info */
			if (debug == TRUE || (sslprm.log_opts & SSL_LogIpAddr))
				logit(LOG_DEBUG, "Connection from %s port %d", remote_host, nptr->sin_port);

			if (!is_an_allowed_host(AF_INET, (void *)&(nptr->sin_addr))) {
				/* log error */
				logit(LOG_ERR, "Host %s is not allowed to talk to us!", remote_host);

				/* log info */
				if (debug == TRUE)
					logit(LOG_DEBUG, "Connection from %s closed.", remote_host);

				/* close socket prior to exiting */
				close(sock);
				exit(STATE_OK);

			} else {

				/* log info */
				if (debug == TRUE) {
					logit(LOG_DEBUG, "Host address is in allowed_hosts");
				}

			}
			break;

		case AF_INET6:
			/* log info */
			strncpy(remote_host, ipstr, sizeof(remote_host));
			remote_host[sizeof(remote_host) - 1] = '\0';
			if (debug == TRUE || (sslprm.log_opts & SSL_LogIpAddr)) {
				logit(LOG_DEBUG, "Connection from %s port %d", ipstr, nptr6->sin6_port);
			}

			if (!is_an_allowed_host(AF_INET6, (void *)&(nptr6->sin6_addr))) {
				/* log error */
				logit(LOG_ERR, "Host %s is not allowed to talk to us!", ipstr);

				/* log info */
				if (debug == TRUE)
					logit(LOG_DEBUG, "Connection from %s closed.", ipstr);

				/* close socket prior to exiting */
				close(sock);
				exit(STATE_OK);

			} else {
				/* log info */
				if (debug == TRUE)
					logit(LOG_DEBUG, "Host address is in allowed_hosts");
			}
			break;
		}
	}

#ifdef HAVE_LIBWRAP
	/* Check whether or not connections are allowed from this host */
	request_init(&req, RQ_DAEMON, "nrpe", RQ_FILE, sock, 0);
	fromhost(&req);

	if (!hosts_access(&req)) {
		logit(LOG_DEBUG, "Connection refused by TCP wrapper");
		refuse(&req);			/* refuse the connection */
		/* should not be reached */
		logit(LOG_ERR, "libwrap refuse() returns!");
		close(sock);
		exit(STATE_CRITICAL);
	}
#endif
}

/* handles a client connection */
void handle_connection(int sock)
{
	u_int32_t calculated_crc32;
	command  *temp_command;
	v2_packet receive_packet, send_packet;
	v3_packet *v3_receive_packet = NULL, *v3_send_packet = NULL;
	int       bytes_to_send;
	char      buffer[MAX_INPUT_BUFFER], *send_buff = NULL, *send_pkt;
	char      raw_command[MAX_INPUT_BUFFER];
	char      processed_command[MAX_INPUT_BUFFER];
	int       result = STATE_OK;
	int       early_timeout = FALSE;
	int       rc;
	int       x;
	int32_t   pkt_size;
#ifdef DEBUG
	FILE     *errfp;
#endif
#ifdef HAVE_SSL
	SSL      *ssl = NULL;
#endif

	/* do SSL handshake */
#ifdef HAVE_SSL
	if (use_ssl == TRUE) {
    	if ((ssl = SSL_new(ctx)) == NULL) {
        	logit(LOG_ERR, "Error: Could not create SSL connection structure.");
# ifdef DEBUG
            errfp = fopen("/tmp/err.log", "a");
    		ERR_print_errors_fp(errfp);
        	fclose(errfp);
# endif
    		return;
        }

		if (handle_conn_ssl(sock, ssl) != OK) {
			complete_SSL_shutdown(ssl);
			SSL_free(ssl);
			return;
		}
	}
#endif

#ifdef HAVE_SSL
	rc = read_packet(sock, ssl, &receive_packet, &v3_receive_packet);
#else
	rc = read_packet(sock, NULL, &receive_packet, &v3_receive_packet);
#endif

	/* disable connection alarm - a new alarm will be setup during my_system */
	alarm(0);

	/* recv() error or client disconnect */
	if (rc <= 0) {
		/* log error */
		logit(LOG_ERR, "Could not read request from client %s, bailing out...", remote_host);
		if (v3_receive_packet)
			free(v3_receive_packet);
#ifdef HAVE_SSL
		if (ssl) {
			complete_SSL_shutdown(ssl);
			SSL_free(ssl);
			logit(LOG_INFO, "INFO: SSL Socket Shutdown.\n");
		}
#endif
		return;
	}

	/* make sure the request is valid */
	if (validate_request(&receive_packet, v3_receive_packet) == ERROR) {
		/* log an error */
		logit(LOG_ERR, "Client request from %s was invalid, bailing out...", remote_host);

		/* free memory */
		free(command_name);
		command_name = NULL;
		for (x = 0; x < MAX_COMMAND_ARGUMENTS; x++) {
			free(macro_argv[x]);
			macro_argv[x] = NULL;
		}
		if (v3_receive_packet)
			free(v3_receive_packet);

#ifdef HAVE_SSL
		if (ssl) {
			complete_SSL_shutdown(ssl);
			SSL_free(ssl);
		}
#endif

		return;
	}

	/* log info */
	if (debug == TRUE)
		logit(LOG_DEBUG, "Host %s is asking for command '%s' to be run...",
			   remote_host, command_name);

	/* if this is the version check command, just spew it out */
	if (!strcmp(command_name, NRPE_HELLO_COMMAND)) {
		snprintf(buffer, sizeof(buffer), "NRPE v%s", PROGRAM_VERSION);
		buffer[sizeof(buffer) - 1] = '\x0';
		if (debug == TRUE)		/* log info */
			logit(LOG_DEBUG, "Response to %s: %s", remote_host, buffer);
		if (v3_receive_packet)
			send_buff = strdup(buffer);
		else {
			int size = sizeof(buffer);
			send_buff = calloc(1, size);
			strncpy(send_buff, buffer, size);
		}
		result = STATE_OK;

	} else {

		/* find the command we're supposed to run */
		temp_command = find_command(command_name);
		if (temp_command == NULL) {
			snprintf(buffer, sizeof(buffer), "NRPE: Command '%s' not defined", command_name);
			buffer[sizeof(buffer) - 1] = '\x0';
			if (debug == TRUE)	/* log error */
				logit(LOG_DEBUG, "%s", buffer);
			if (v3_receive_packet)
				send_buff = strdup(buffer);
			else {
				int size = sizeof(buffer);
				send_buff = calloc(1, size);
				strncpy(send_buff, buffer, size);
			}
			result = STATE_UNKNOWN;

		} else {

			/* process command line */
			if (command_prefix == NULL)
				strncpy(raw_command, temp_command->command_line, sizeof(raw_command) - 1);
			else
				snprintf(raw_command, sizeof(raw_command) - 1, "%s %s", command_prefix,
						 temp_command->command_line);
			raw_command[sizeof(raw_command) - 1] = '\x0';
			process_macros(raw_command, processed_command, sizeof(processed_command));

			if (debug == TRUE)	/* log info */
				logit(LOG_DEBUG, "Running command: %s", processed_command);

			/* run the command */
			buffer[0] = '\0';
			result = my_system(processed_command, command_timeout, &early_timeout, &send_buff);

			if (debug == TRUE)	/* log debug info */
				logit(LOG_DEBUG, "Command completed with return code %d and output: %s",
					   result, send_buff);

			/* see if the command timed out */
			if (early_timeout == TRUE) {
				free(send_buff);
				asprintf(&send_buff, "NRPE: Command timed out after %d seconds\n",
						command_timeout);
				result = STATE_UNKNOWN;
			} else if (!strcmp(send_buff, "")) {
				free(send_buff);
				asprintf(&send_buff, "NRPE: Unable to read output\n");
				result = STATE_UNKNOWN;
			}

			/* check return code bounds */
			if ((result < 0) || (result > 3)) {
				/* log error */
				logit(LOG_ERR, "Bad return code for [%s]: %d", send_buff, result);
				result = STATE_UNKNOWN;
			}
		}
	}

	/* free memory */
	free(command_name);
	command_name = NULL;
	for (x = 0; x < MAX_COMMAND_ARGUMENTS; x++) {
		free(macro_argv[x]);
		macro_argv[x] = NULL;
	}
	if (v3_receive_packet)
		free(v3_receive_packet);
	pkt_size = strlen(send_buff);
	/* strip newline character from end of output buffer */
	if (send_buff[strlen(send_buff) - 1] == '\n')
		send_buff[strlen(send_buff) - 1] = '\x0';

	if (packet_ver == NRPE_PACKET_VERSION_2) {
		pkt_size = sizeof(v2_packet);
		send_pkt = (char *)&send_packet;

		/* clear the response packet buffer */
		memset(&send_packet, 0, sizeof(send_packet));
		/* fill the packet with semi-random data */
		randomize_buffer((char *)&send_packet, sizeof(send_packet));

		/* initialize response packet data */
		send_packet.packet_version = htons(packet_ver);
		send_packet.packet_type = htons(RESPONSE_PACKET);
		send_packet.result_code = htons(result);
		strncpy(&send_packet.buffer[0], send_buff, MAX_PACKETBUFFER_LENGTH);
		send_packet.buffer[MAX_PACKETBUFFER_LENGTH - 1] = '\x0';

		/* calculate the crc 32 value of the packet */
		send_packet.crc32_value = 0;
		calculated_crc32 = calculate_crc32((char *)&send_packet, sizeof(send_packet));
		send_packet.crc32_value = htonl(calculated_crc32);

	} else {
		int send_buff_len = strlen(send_buff);
		pkt_size = (sizeof(v3_packet) - NRPE_V4_PACKET_SIZE_OFFSET) + send_buff_len + 1;
		if (packet_ver == NRPE_PACKET_VERSION_3) {
			pkt_size = (sizeof(v3_packet) - NRPE_V3_PACKET_SIZE_OFFSET) + send_buff_len + 1;
		}
		v3_send_packet = calloc(1, pkt_size);
		send_pkt = (char *)v3_send_packet;
		/* initialize response packet data */
		v3_send_packet->packet_version = htons(packet_ver);
		v3_send_packet->packet_type = htons(RESPONSE_PACKET);
		v3_send_packet->result_code = htons(result);
		v3_send_packet->alignment = 0;
		v3_send_packet->buffer_length = htonl(send_buff_len + 1);
		memcpy(&v3_send_packet->buffer[0], send_buff, send_buff_len + 1);

		/* calculate the crc 32 value of the packet */
		v3_send_packet->crc32_value = 0;
		calculated_crc32 = calculate_crc32((char *)v3_send_packet, pkt_size);
		v3_send_packet->crc32_value = htonl(calculated_crc32);
	}

	/* send the response back to the client */
	bytes_to_send = pkt_size;
	if (use_ssl == FALSE)
		sendall(sock, send_pkt, &bytes_to_send);
#ifdef HAVE_SSL
	else
		SSL_write(ssl, send_pkt, bytes_to_send);
#endif

#ifdef HAVE_SSL
	if (ssl) {
		complete_SSL_shutdown(ssl);
		SSL_free(ssl);
	}
#endif

	if (v3_send_packet)
		free(v3_send_packet);

	/* log info */
	if (debug == TRUE)
		logit(LOG_DEBUG, "Return Code: %d, Output: %s", result, send_buff);

	free(send_buff);

	return;
}

void init_handle_conn(void)
{
#ifdef HAVE_SIGACTION
	struct sigaction sig_action;
#endif

	/* log info */
	if (debug == TRUE)
		logit(LOG_DEBUG, "Handling the connection...");

	/* set connection handler */
#ifdef HAVE_SIGACTION
	sig_action.sa_sigaction = NULL;
	sig_action.sa_handler = my_connection_sighandler;
	sigfillset(&sig_action.sa_mask);
	sig_action.sa_flags = SA_NODEFER | SA_RESTART;
	sigaction(SIGALRM, &sig_action, NULL);
#else
	signal(SIGALRM, my_connection_sighandler);
#endif	 /* HAVE_SIGACTION */
	alarm(connection_timeout);
}

int handle_conn_ssl(int sock, void *ssl_ptr)
{
#ifdef HAVE_SSL
# if (defined(__sun) && defined(SOLARIS_10)) || defined(_AIX) || defined(__hpux)
	SSL_CIPHER *c;
#else
	const SSL_CIPHER *c;
#endif
	const char *errmsg = NULL;
	char      buffer[MAX_INPUT_BUFFER];
	SSL      *ssl = (SSL*)ssl_ptr;
	X509     *peer;
	int       rc, x, sockfd, retval;
	fd_set    rfds;
	struct timeval timeout;

	SSL_set_fd(ssl, sock);
	sockfd = SSL_get_fd(ssl);

	FD_ZERO(&rfds);
	FD_SET(sockfd, &rfds);

	timeout.tv_sec = connection_timeout;
	timeout.tv_usec = 0;


	/* keep attempting the request if needed */
	do {
		retval = select(sockfd + 1, &rfds, NULL, NULL, &timeout);

		if (retval > 0) {
			rc = SSL_accept(ssl);
		} else {
			logit(LOG_ERR, "Error: (!log_opts) Could not complete SSL handshake with %s: timeout %d seconds", remote_host, connection_timeout);
			return ERROR;
		}
	} while (SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ);

	if (rc != 1) {
		/* oops, got an unrecoverable error -- get out */
		if (sslprm.log_opts & (SSL_LogCertDetails | SSL_LogIfClientCert)) {
			int nerrs = 0;
			rc = 0;
			while ((x = ERR_get_error()) != 0) {
				errmsg = ERR_reason_error_string(x);
				logit(LOG_ERR, "Error: (ERR_get_error = 0x%08x), Could not complete SSL handshake with %s: %s", x, remote_host, errmsg);
				
				if (errmsg && !strcmp(errmsg, "no shared cipher") && (sslprm.cert_file == NULL || sslprm.cacert_file == NULL))
					logit(LOG_ERR, "Error: This could be because you have not specified certificate or ca-certificate files");

				++nerrs;
			}

			if (nerrs == 0) {
				logit(LOG_ERR, "Error: (nerrs = 0) Could not complete SSL handshake with %s: 0x%08x", remote_host, SSL_get_error(ssl, rc));
			}
		} else {
			logit(LOG_ERR, "Error: (!log_opts) Could not complete SSL handshake with %s: 0x%08x", remote_host, SSL_get_error(ssl, rc));
		}
# ifdef DEBUG
		errfp = fopen("/tmp/err.log", "a");
		ERR_print_errors_fp(errfp);
		fclose(errfp);
# endif
		return ERROR;
	}

	/* successful handshake */
	if (sslprm.log_opts & SSL_LogVersion)
		logit(LOG_NOTICE, "Remote %s - SSL Version: %s", remote_host, SSL_get_version(ssl));

	if (sslprm.log_opts & SSL_LogCipher) {
		c = SSL_get_current_cipher(ssl);
		logit(LOG_NOTICE, "Remote %s - %s, Cipher is %s", remote_host, SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c));
	}

	if ((sslprm.log_opts & SSL_LogIfClientCert)
		|| (sslprm.log_opts & SSL_LogCertDetails)) {


		peer = SSL_get_peer_certificate(ssl);

		if (peer) {
			if (sslprm.log_opts & SSL_LogIfClientCert)
				logit(LOG_NOTICE, "SSL Client %s has %s certificate",
					   remote_host, SSL_get_verify_result(ssl) == X509_V_OK ? "a valid" : "an invalid");

			if (sslprm.log_opts & SSL_LogCertDetails) {

				X509_NAME_oneline(X509_get_subject_name(peer), buffer, sizeof(buffer));
				logit(LOG_NOTICE, "SSL Client %s Cert Name: %s",
					   remote_host, buffer);

				X509_NAME_oneline(X509_get_issuer_name(peer), buffer, sizeof(buffer));
				logit(LOG_NOTICE, "SSL Client %s Cert Issuer: %s",
					   remote_host, buffer);
			}

		} else if (sslprm.client_certs == 0)
			logit(LOG_NOTICE, "SSL Not asking for client certification");

		else
			logit(LOG_NOTICE, "SSL Client %s did not present a certificate",
				   remote_host);
	}
#endif

	return OK;
}

int read_packet(int sock, void *ssl_ptr, v2_packet * v2_pkt, v3_packet ** v3_pkt)
{
	int32_t   common_size, tot_bytes, bytes_to_recv, buffer_size;
	int       rc;
	char     *buff_ptr;

	/* Read only the part that's common between versions 2 & 3 */
	common_size = tot_bytes = bytes_to_recv = (char *)&v2_pkt->buffer - (char *)v2_pkt;

	if (use_ssl == FALSE) {
		rc = recvall(sock, (char *)v2_pkt, &tot_bytes, socket_timeout);

		if (rc <= 0 || rc != bytes_to_recv)
			return -1;

		packet_ver = ntohs(v2_pkt->packet_version);
		if (packet_ver != NRPE_PACKET_VERSION_2 && packet_ver != NRPE_PACKET_VERSION_4) {
			logit(LOG_ERR, "Error: (use_ssl == false): Request packet version was invalid!");
			return -1;
		}

		if (packet_ver == NRPE_PACKET_VERSION_2) {
			buffer_size = sizeof(v2_packet) - common_size;
			buff_ptr = (char *)v2_pkt + common_size;

		} else {
			int32_t   pkt_size = sizeof(v3_packet) - 1;

			/* Read the alignment filler */
			bytes_to_recv = sizeof(int16_t);
			rc = recvall(sock, (char *)&buffer_size, &bytes_to_recv, socket_timeout);
			if (rc <= 0 || bytes_to_recv != sizeof(int16_t))
				return -1;
			tot_bytes += rc;

			/* Read the buffer size */
			bytes_to_recv = sizeof(buffer_size);
			rc = recvall(sock, (char *)&buffer_size, &bytes_to_recv, socket_timeout);
			if (rc <= 0 || bytes_to_recv != sizeof(buffer_size))
				return -1;
			tot_bytes += rc;

			buffer_size = ntohl(buffer_size);
			if (buffer_size < 0 || buffer_size > 65536) {
				logit(LOG_ERR, "Error: (use_ssl == false): Received packet with invalid buffer size");
				return -1;
			}
			pkt_size += buffer_size;
			if ((*v3_pkt = calloc(1, pkt_size)) == NULL) {
				logit(LOG_ERR, "Error: (use_ssl == false): Could not allocate memory for packet");
				return -1;
			}

			memcpy(*v3_pkt, v2_pkt, common_size);
			(*v3_pkt)->buffer_length = htonl(buffer_size);
			buff_ptr = (*v3_pkt)->buffer;
		}

		bytes_to_recv = buffer_size;
		rc = recvall(sock, buff_ptr, &bytes_to_recv, socket_timeout);

		if (rc <= 0 || rc != buffer_size) {
			if (packet_ver == NRPE_PACKET_VERSION_3) {
				free(*v3_pkt);
				*v3_pkt = NULL;
			}
			return -1;
		} else
			tot_bytes += rc;
	}
#ifdef HAVE_SSL
	else {
		SSL      *ssl = (SSL *) ssl_ptr;
		int       sockfd, retval;
		fd_set    rfds;
		struct timeval timeout;

		sockfd = SSL_get_fd(ssl);

		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);

		timeout.tv_sec = connection_timeout;
		timeout.tv_usec = 0;

		do {
			retval = select(sockfd + 1, &rfds, NULL, NULL, &timeout);

			if (retval > 0) {
				rc = SSL_read(ssl, v2_pkt, bytes_to_recv);
			} else {
				logit(LOG_ERR, "Error (!log_opts): Could not complete SSL_read with %s: timeout %d seconds", remote_host, connection_timeout);
				return -1;
			}
		} while (SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ);

		if (rc <= 0 || rc != bytes_to_recv)
			return -1;

		packet_ver = ntohs(v2_pkt->packet_version);
		if (packet_ver != NRPE_PACKET_VERSION_2 && packet_ver != NRPE_PACKET_VERSION_4) {
			logit(LOG_ERR, "Error: (use_ssl == true): Request packet version was invalid!");
			return -1;
		}

		if (packet_ver == NRPE_PACKET_VERSION_2) {
			buffer_size = sizeof(v2_packet) - common_size;
			buff_ptr = (char *)v2_pkt + common_size;
		} else {
			int32_t   pkt_size = sizeof(v3_packet);
			if (packet_ver == NRPE_PACKET_VERSION_3) {
				pkt_size -= NRPE_V3_PACKET_SIZE_OFFSET;
			}
			else if (packet_ver == NRPE_PACKET_VERSION_4) {
				pkt_size -= NRPE_V4_PACKET_SIZE_OFFSET;
			}

			/* Read the alignment filler */
			bytes_to_recv = sizeof(int16_t);
			while (((rc = SSL_read(ssl, &buffer_size, bytes_to_recv)) <= 0)
				   && (SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ)) {
			}

			if (rc <= 0 || bytes_to_recv != sizeof(int16_t))
				return -1;
			tot_bytes += rc;

			/* Read the buffer size */
			bytes_to_recv = sizeof(buffer_size);
			while (((rc = SSL_read(ssl, &buffer_size, bytes_to_recv)) <= 0)
				   && (SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ)) {
			}

			if (rc <= 0 || bytes_to_recv != sizeof(buffer_size))
				return -1;
			tot_bytes += rc;

			buffer_size = ntohl(buffer_size);
			if (buffer_size < 0 || buffer_size > 65536) {
				logit(LOG_ERR, "Error: (use_ssl == true): Received packet with invalid buffer size");
				return -1;
			}
			pkt_size += buffer_size;
			if ((*v3_pkt = calloc(1, pkt_size)) == NULL) {
				logit(LOG_ERR, "Error: (use_ssl == true): Could not allocate memory for packet");
				return -1;
			}

			memcpy(*v3_pkt, v2_pkt, common_size);
			(*v3_pkt)->buffer_length = htonl(buffer_size);
			buff_ptr = (*v3_pkt)->buffer;
		}

		bytes_to_recv = buffer_size;
		while (((rc = SSL_read(ssl, buff_ptr, bytes_to_recv)) <= 0)
			   && (SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ)) {
		}

		if (rc <= 0 || rc != buffer_size) {
			if (packet_ver == NRPE_PACKET_VERSION_3) {
				free(*v3_pkt);
				*v3_pkt = NULL;
			}
			return -1;
		} else
			tot_bytes += rc;
	}
#endif

	return tot_bytes;
}

/* free all allocated memory */
void free_memory(void)
{
	command  *this_command;
	command  *next_command;

	/* free memory for the command list */
	this_command = command_list;
	while (this_command != NULL) {
		next_command = this_command->next;
		if (this_command->command_name)
			free(this_command->command_name);
		if (this_command->command_line)
			free(this_command->command_line);
		free(this_command);
		this_command = next_command;
	}

	command_list = NULL;
	return;
}

static int my_system_parent(pid_t pid, int fd, int timeout, time_t start_time, int *early_timeout, char **output);
static int my_system_child(const char *command, int timeout, int fd);

/* executes a system command via popen(), but protects against timeouts */
int my_system(char *command, int timeout, int *early_timeout, char **output)
{
	pid_t     pid;
	time_t    start_time;
	int       result;
	int       fd[2];

	*early_timeout = FALSE;		/* initialize return variables */

	if (command == NULL)		/* if no command was passed, return with no error */
		return STATE_OK;

	/* make sure that we are within max_commands boundaries before attempting */
	if (max_commands != 0) {
		while (commands_running >= max_commands) {
			logit(LOG_WARNING, "Commands choked. Sleeping 1s - commands_running: %d, max_commands: %d", commands_running, max_commands);
			sleep(1);
		}
	}

	/* create a pipe */
	if (pipe(fd) == -1) {
		logit(LOG_ERR, "ERROR: pipe(): %s, bailing out...", strerror(errno));
		exit(STATE_CRITICAL);
	}

	/* make the pipe non-blocking */
	fcntl(fd[0], F_SETFL, O_NONBLOCK);
	fcntl(fd[1], F_SETFL, O_NONBLOCK);

	time(&start_time);			/* get the command start time */

	pid = fork();				/* fork */

	/* return an error if we couldn't fork */
	if (pid == -1) {
		asprintf(output, "NRPE: Call to fork() failed (errno=%i)\n", errno);

		/* close both ends of the pipe */
		close(fd[0]);
		close(fd[1]);

		return STATE_UNKNOWN;
	}

	/* execute the command in the child process */
	if (pid == 0) {

		/* get root back so the next call works correctly */
		if (SETEUID(0) == -1 && debug)
			logit(LOG_WARNING, "WARNING: my_system() seteuid(0): %s", strerror(errno));

		drop_privileges(nrpe_user, nrpe_group, 1);	/* drop privileges */
		close(fd[0]);			/* close pipe for reading */
		setpgid(0, 0);			/* become process group leader */

		result = my_system_child(command, timeout, fd[1]);
		exit(result);			/* return plugin exit code to parent process */
	} else {
		/* parent waits for child to finish executing command */

		close(fd[1]);			/* close pipe for writing */

		result = my_system_parent(pid, fd[0], timeout, start_time, early_timeout, output);
	}

#ifdef DEBUG
	printf("my_system() end\n");
#endif

	return result;
}

int my_system_parent(pid_t pid, int fd, int timeout, time_t start_time, int *early_timeout, char **output)
{
	time_t    end_time;
	int       status;
	int       result;
	int       output_size = 1024 * 64;	/* Maximum buffer is 64K */
	int       bytes_read = 0;
	int       do_wait = 1;

	commands_running++;

	if (packet_ver == NRPE_PACKET_VERSION_2) {
		output_size = MAX_PACKETBUFFER_LENGTH;
	}
	*output = calloc(1, output_size);

	while (1) {
		int rc;
		fd_set rfds;
		struct timeval tv;

		if (do_wait) {
			/* Check for child exit */
			rc = waitpid(pid, &status, WNOHANG);
			if (rc == pid || rc == -1) {
				time(&end_time);	/* get the end time for running the command */
				do_wait = 0;
			}
		}

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		rc = select(fd + 1, &rfds, 0, 0, &tv);
		if (rc == -1)
			break;

		if (rc == 0) {
			/* if child process has already exited and there is nothing to read, don't wait for grandkids */
			if (!do_wait)
				break;
			continue;
		}

		if (FD_ISSET(fd, &rfds)) {
			/* try and read the results from the command output (retry if we encountered a signal) */
			rc = read(fd, *output + bytes_read, output_size - bytes_read);
			if (rc == -1) {
				if (errno == EINTR)
					continue;
				break;
			} else if (rc == 0) {
				break;
			}

			bytes_read += rc;
			if (bytes_read == output_size)
				break;
		}
	}

	/* Ensure output buffer termination */
	(*output)[output_size - 1] = '\0';
	/* close the pipe for reading */
	close(fd);

	if (do_wait) {
		/* Child hasn't exited yet*/
		waitpid(pid, &status, 0);
		time(&end_time);	/* get the end time for running the command */
	}
	result = WEXITSTATUS(status);	/* get the exit code returned from the program */

	/* check bounds on the return value */
	if (result < 0 || result > 3)
		result = STATE_UNKNOWN;

	/* if there was a critical return code and no output AND the
	 * command time exceeded the timeout thresholds, assume a timeout */
	if (result == STATE_CRITICAL && bytes_read == 0 && (end_time - start_time) >= timeout) {
		*early_timeout = TRUE;

		/* send termination signal to child process group */
		kill((pid_t) (-pid), SIGTERM);
		kill((pid_t) (-pid), SIGKILL);
	}

	commands_running--;
	return result;
}

int my_system_child(const char *command, int timeout, int fd)
{
	FILE     *fp;
	int       status;
	int       result;
	char      buffer[MAX_INPUT_BUFFER];
#ifdef HAVE_SIGACTION
	struct sigaction sig_action;
#endif

	/* trap commands that timeout */
#ifdef HAVE_SIGACTION
	sig_action.sa_sigaction = NULL;
	sig_action.sa_handler = my_system_sighandler;
	sigfillset(&sig_action.sa_mask);
	sig_action.sa_flags = SA_NODEFER | SA_RESTART;
	sigaction(SIGALRM, &sig_action, NULL);
#else
	signal(SIGALRM, my_system_sighandler);
#endif	 /* HAVE_SIGACTION */
	alarm(timeout);

	fp = popen(command, "r");	/* run the command */

	/* report an error if we couldn't run the command */
	if (fp == NULL) {
		strncpy(buffer, "NRPE: Call to popen() failed\n", sizeof(buffer) - 1);
		buffer[sizeof(buffer) - 1] = '\x0';

		/* write the error back to the parent process */
		if (write(fd, buffer, strlen(buffer) + 1) == -1)
			logit(LOG_ERR, "ERROR: my_system() write(fd, buffer)-1 failed...");

		result = STATE_CRITICAL;

	} else {
		int do_read = 1;
		int bytes_read = 0;

		/* read all lines of output - supports Nagios 3.x multiline output */
		while (do_read || bytes_read) {
			int rc;
			int max_fd = 0;
			fd_set rfds;
			fd_set wfds;
			struct timeval tv;

			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			if (do_read && bytes_read < sizeof(buffer)) {
				FD_SET(fileno(fp), &rfds);
				max_fd = fileno(fp);
			}
			if (bytes_read) {
				FD_SET(fd, &wfds);
				max_fd = fd > max_fd ? fd : max_fd;
			}
			tv.tv_sec = 5;
			tv.tv_usec = 0;

			rc = select(max_fd + 1, &rfds, &wfds, 0, &tv);
			if (rc == -1) {
				logit(LOG_ERR, "ERROR: my_system_child() select failed (errno=%i)", errno);
				break;
			}

			if (rc == 0)
				continue;

			if (FD_ISSET(fileno(fp), &rfds)) {
				rc = fread(buffer + bytes_read, 1, sizeof(buffer) - bytes_read, fp);
				if (rc <= 0) {
					/* error or eof reached */
					do_read = 0;

					/* Add terminating NUL to send */
					buffer[bytes_read] = '\0';
					bytes_read++;
				} else {
					bytes_read += rc;
				}
			}

			if (bytes_read) {
				/* We always try to write if we have anything... we'll just get EAGAIN if still full */
				rc = write(fd, buffer, bytes_read);
				if (rc == -1) {
					if (errno != EAGAIN) {
						logit(LOG_ERR, "ERROR: my_system_child() write(fd, buffer) failed (errno=%i)", errno);
						break;
					}
				} else if (rc > 0) {
					memmove(buffer, buffer + rc, bytes_read - rc);
					bytes_read -= rc;
				}
			}
		}

		status = pclose(fp);	/* close the command and get termination status */

		/* report an error if we couldn't close the command */
		if (status == -1)
			result = STATE_CRITICAL;
		else if (!WIFEXITED(status))
			/* report an error if child died due to signal (Klas Lindfors) */
			result = STATE_CRITICAL;
		else
			result = WEXITSTATUS(status);
	}

	close(fd);				/* close pipe for writing */
	alarm(0);				/* reset the alarm */
	return result;
}

/* handle timeouts when executing commands via my_system() */
void my_system_sighandler(int sig)
{
	/* try to kill any child processes in our group */
	kill(0, SIGTERM);
	exit(STATE_CRITICAL);		/* force the child process to exit... */
}

/* handle errors where connection takes too long */
void my_connection_sighandler(int sig)
{
	logit(LOG_ERR, "Connection has taken too long to establish. Exiting...");
	exit(STATE_CRITICAL);
}

/* drops privileges */
int drop_privileges(char *user, char *group, int full_drop)
{
	uid_t     uid = (uid_t)-1;
	gid_t     gid = (gid_t)-1;
	struct group *grp;
	struct passwd *pw;

	if (use_inetd == TRUE)
		return OK;

	/* set effective group ID */
	if (group != NULL) {

		/* see if this is a group name */
		if (strspn(group, "0123456789") < strlen(group)) {
			grp = (struct group *)getgrnam(group);
			if (grp != NULL)
				gid = (gid_t) (grp->gr_gid);
			else
				logit(LOG_ERR, "Warning: Could not get group entry for '%s'", group);
			endgrent();

		} else
			/* else we were passed the GID */
			gid = (gid_t) atoi(group);

		/* set effective group ID if other than current EGID */
		if (gid != getegid()) {
			if (setgid(gid) == -1)
				logit(LOG_ERR, "Warning: Could not set effective GID=%d", (int)gid);
		}
	}


	/* set effective user ID */
	if (user != NULL) {

		/* see if this is a user name */
		if (strspn(user, "0123456789") < strlen(user)) {
			pw = (struct passwd *)getpwnam(user);
			if (pw != NULL)
				uid = (uid_t) (pw->pw_uid);
			else
				logit(LOG_ERR, "Warning: Could not get passwd entry for '%s'", user);
			endpwent();

		} else
			/* else we were passed the UID */
			uid = (uid_t) atoi(user);

		if (uid != geteuid()) {
		/* set effective user ID if other than current EUID */
#ifdef HAVE_INITGROUPS
			/* initialize supplementary groups */
			if (initgroups(user, gid) == -1) {
				if (errno == EPERM)
					logit(LOG_ERR, "Warning: Unable to change supplementary groups using initgroups()");
				else {
					logit(LOG_ERR, "Warning: Possibly root user failed dropping privileges with initgroups()");
					return ERROR;
				}
			}
#endif

			if (full_drop) {
				if (setuid(uid) == -1)
					logit(LOG_ERR, "Warning: Could not set UID=%d", (int)uid);
			} else if (SETEUID(uid) == -1)
				logit(LOG_ERR, "Warning: Could not set effective UID=%d", (int)uid);
		}
	}

	return OK;
}

/* write an optional pid file */
int write_pid_file(void)
{
	int       fd;
	int       result = 0;
	pid_t     pid = 0;
	char      pbuf[16];

	/* no pid file was specified */
	if (pid_file == NULL)
		return OK;

	/* read existing pid file */
	if ((fd = open(pid_file, O_RDONLY)) >= 0) {

		result = read(fd, pbuf, (sizeof pbuf) - 1);
		close(fd);

		if (result > 0) {
			pbuf[result] = '\x0';
			pid = (pid_t) atoi(pbuf);

			/* if previous process is no longer running running, remove the old pid file */
			if (pid && (pid == getpid() || kill(pid, 0) < 0))
				unlink(pid_file);

			else {
				/* previous process is still running */
				logit(LOG_ERR, "There's already an NRPE server running (PID %lu).  Bailing out...", (unsigned long)pid);
				return ERROR;
			}
		}
	}

	/* write new pid file */
	if ((fd = open(pid_file, O_WRONLY | O_CREAT, 0644)) >= 0) {
		snprintf(pbuf, sizeof(pbuf), "%d\n", (int)getpid());

		if (write(fd, pbuf, strlen(pbuf)) == -1)
			logit(LOG_ERR, "ERROR: write_pid_file() write(fd, pbuf) failed...");

		close(fd);
		wrote_pid_file = TRUE;
	} else {
		logit(LOG_ERR, "Cannot write to pidfile '%s' - check your privileges.", pid_file);
		return ERROR;
	}

	return OK;
}

/* remove pid file */
int remove_pid_file(void)
{
	if (pid_file == NULL)
		return OK;				/* no pid file was specified */
	if (wrote_pid_file == FALSE)
		return OK;				/* pid file was not written */

	/* get root back so we can delete the pid file */
	if (SETEUID(0) == -1 && debug)
		logit(LOG_WARNING, "WARNING: remove_pid_file() seteuid(0): %s", strerror(errno));

	if (unlink(pid_file) == -1) {
		logit(LOG_ERR, "Cannot remove pidfile '%s' - check your privileges.", pid_file);
		return ERROR;
	}

	return OK;
}

#ifdef HAVE_SSL

void my_disconnect_sighandler(int sig)
{
	logit(LOG_ERR, "SSL_shutdown() has taken too long to complete. Exiting now..");
	exit(STATE_CRITICAL);
}

void complete_SSL_shutdown(SSL * ssl)
{
	/* Thanks to Jari Takkala (jtakkala@gmail.com) for the following information.

	   We need to call SSL_shutdown() at least twice, otherwise we'll
	   be left with data in the socket receive buffer, and the
	   subsequent process termination will cause TCP RST's to be sent
	   to the client.

	   See http://bugs.ruby-lang.org/projects/ruby-trunk/repository/revisions/32219/diff
	   for more information.
	 */

	int       x;

	/* set disconnection handler */
	signal(SIGALRM, my_disconnect_sighandler);
	alarm(ssl_shutdown_timeout);

	for (x = 0; x < 4; x++) {
		if (SSL_shutdown(ssl))
			break;
	}

	alarm(0);
}
#endif	 /*HAVE_SSL */

/* bail if daemon is running as root */
int check_privileges(void)
{
	uid_t     uid = geteuid();
	gid_t     gid = getegid();

	if (uid == 0 || gid == 0) {
		logit(LOG_ERR, "Error: NRPE daemon cannot be run as user/group root!");
		exit(STATE_CRITICAL);
	}

	return OK;
}

/* handle signals (parent process) */
void sighandler(int sig)
{
	static char *sigs[] = {
		"EXIT", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE",
		"KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT",
		"CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU",
		"XFSZ", "VTALRM", "PROF", "WINCH", "IO", "PWR", "UNUSED", "ZERR",
		"DEBUG", (char *)NULL
	};
	int       i;

	if (sig < 0)
		sig = -sig;

	for (i = 0; sigs[i] != (char *)NULL; i++) ;
	sig %= i;

	/* we received a SIGHUP, so restart... */
	if (sig == SIGHUP) {
		sigrestart = TRUE;
		logit(LOG_NOTICE, "Caught SIGHUP - restarting...\n");
	}

	/* else begin shutting down... */
	if (sig == SIGTERM) {
		/* if shutdown is already true, we're in a signal trap loop! */
		if (sigshutdown == TRUE)
			exit(STATE_CRITICAL);
		sigshutdown = TRUE;
		logit(LOG_NOTICE, "Caught SIG%s - shutting down...\n", sigs[sig]);
	}

	return;
}

/* handle signals (child processes) */
void child_sighandler(int sig)
{
	exit(0);					/* terminate */
}

/* tests whether or not a client request is valid */
int validate_request(v2_packet * v2pkt, v3_packet * v3pkt)
{
	u_int32_t	packet_crc32;
	u_int32_t	calculated_crc32;
	int32_t		pkt_size, buffer_size;
	char		*buff, *ptr;
	int			rc;
#ifdef ENABLE_COMMAND_ARGUMENTS
	int			x;
#endif

	/* check the crc 32 value */
	if (packet_ver >= NRPE_PACKET_VERSION_3) {

		buffer_size = ntohl(v3pkt->buffer_length);

		pkt_size = sizeof(v3_packet);
		pkt_size -= (packet_ver == NRPE_PACKET_VERSION_3 ? NRPE_V3_PACKET_SIZE_OFFSET : NRPE_V4_PACKET_SIZE_OFFSET);
		pkt_size += buffer_size;

		packet_crc32 = ntohl(v3pkt->crc32_value);
		v3pkt->crc32_value = 0L;
		v3pkt->alignment = 0;
		calculated_crc32 = calculate_crc32((char *)v3pkt, pkt_size);
	} else {
		packet_crc32 = ntohl(v2pkt->crc32_value);
		v2pkt->crc32_value = 0L;
		calculated_crc32 = calculate_crc32((char *)v2pkt, sizeof(v2_packet));
	}

	if (packet_crc32 != calculated_crc32) {
		logit(LOG_ERR, "Error: Request packet had invalid CRC32.");
		return ERROR;
	}

	/* make sure this is the right type of packet */
	if (ntohs(v2pkt->packet_type) != QUERY_PACKET) {
		logit(LOG_ERR, "Error: Request packet type was invalid!");
		return ERROR;
	}

	/* make sure buffer is terminated */
	if (packet_ver >= NRPE_PACKET_VERSION_3) {
		int32_t   l = ntohs(v3pkt->buffer_length);
		v3pkt->buffer[l - 1] = '\x0';
		buff = v3pkt->buffer;
	} else {
		v2pkt->buffer[MAX_PACKETBUFFER_LENGTH - 1] = '\x0';
		buff = v2pkt->buffer;
	}

	/* client must send some kind of request */
	if (buff[0] == '\0') {
		logit(LOG_ERR, "Error: Request contained no query!");
		return ERROR;
	}

	/* make sure request doesn't contain nasties */
	if (packet_ver >= NRPE_PACKET_VERSION_3)
		rc = contains_nasty_metachars(v3pkt->buffer);
	else
		rc = contains_nasty_metachars(v2pkt->buffer);
	if (rc == TRUE) {
		logit(LOG_ERR, "Error: Request contained illegal metachars!");
		return ERROR;
	}

	/* make sure the request doesn't contain arguments */
	if (strchr(buff, '!')) {
#ifdef ENABLE_COMMAND_ARGUMENTS
		if (allow_arguments == FALSE) {
			logit(LOG_ERR, "Error: Request contained command arguments, but argument option is not enabled!");
			return ERROR;
		}
#else
		logit(LOG_ERR, "Error: Request contained command arguments!");
		return ERROR;
#endif
	}

	/* get command name */
#ifdef ENABLE_COMMAND_ARGUMENTS
	ptr = strtok(buff, "!");
#else
	ptr = buff;
#endif
	command_name = strdup(ptr);
	if (command_name == NULL) {
		logit(LOG_ERR, "Error: Memory allocation failed");
		return ERROR;
	}
#ifdef ENABLE_COMMAND_ARGUMENTS
	/* get command arguments */
	if (allow_arguments == TRUE) {

		for (x = 0; x < MAX_COMMAND_ARGUMENTS; x++) {
			ptr = strtok(NULL, "!");
			if (ptr == NULL)
				break;
			macro_argv[x] = strdup(ptr);
			if (macro_argv[x] == NULL) {
				logit(LOG_ERR, "Error: Memory allocation failed");
				return ERROR;
			}
			if (!strcmp(macro_argv[x], "")) {
				logit(LOG_ERR, "Error: Request contained an empty command argument");
				return ERROR;
			}
			if (strstr(macro_argv[x], "$(")) {
# ifndef ENABLE_BASH_COMMAND_SUBSTITUTION
				logit(LOG_ERR, "Error: Request contained a bash command substitution!");
				return ERROR;
# else
				if (FALSE == allow_bash_cmd_subst) {
					logit(LOG_ERR, "Error: Request contained a bash command substitution, but they are disallowed!");
					return ERROR;
				}
# endif
			}
		}
	}
#endif
	return OK;
}

/* tests whether a buffer contains illegal metachars */
int contains_nasty_metachars(char *str)
{
	int       result;

	if (str == NULL)
		return FALSE;

	result = strcspn(str, nasty_metachars);
	if (result != strlen(str))
		return TRUE;

	return FALSE;
}

/* replace macros in buffer */
int process_macros(char *input_buffer, char *output_buffer, int buffer_length)
{
	char     *temp_buffer;
	int       in_macro;
	int       arg_index = 0;
	char     *selected_macro = NULL;

	output_buffer[0] = '\0';

	in_macro = FALSE;

	for (temp_buffer = my_strsep(&input_buffer, "$"); temp_buffer != NULL;
		 temp_buffer = my_strsep(&input_buffer, "$")) {

		selected_macro = NULL;

		if (in_macro == FALSE) {
			if (strlen(output_buffer) + strlen(temp_buffer) < buffer_length - 1) {
				strncat(output_buffer, temp_buffer, buffer_length - strlen(output_buffer) - 1);
				output_buffer[buffer_length - 1] = '\x0';
			}
			in_macro = TRUE;

		} else {

			if (strlen(output_buffer) + strlen(temp_buffer) < buffer_length - 1) {

				/* argument macro */
				if (strstr(temp_buffer, "ARG") == temp_buffer) {
					arg_index = atoi(temp_buffer + 3);
					if (arg_index >= 1 && arg_index <= MAX_COMMAND_ARGUMENTS)
						selected_macro = macro_argv[arg_index - 1];

				} else if (!strcmp(temp_buffer, "")) {
					/* an escaped $ is done by specifying two $$ next to each other */
					strncat(output_buffer, "$", buffer_length - strlen(output_buffer) - 1);

				} else {
					/* a non-macro, just some user-defined string between two $s */
					strncat(output_buffer, "$", buffer_length - strlen(output_buffer) - 1);
					output_buffer[buffer_length - 1] = '\x0';
					strncat(output_buffer, temp_buffer,
							buffer_length - strlen(output_buffer) - 1);
					output_buffer[buffer_length - 1] = '\x0';
					strncat(output_buffer, "$", buffer_length - strlen(output_buffer) - 1);
				}


				/* insert macro */
				if (selected_macro != NULL)
					strncat(output_buffer, (selected_macro == NULL) ? "" : selected_macro,
							buffer_length - strlen(output_buffer) - 1);

				output_buffer[buffer_length - 1] = '\x0';
			}

			in_macro = FALSE;
		}
	}

	return OK;
}

/* process command line arguments */
int process_arguments(int argc, char **argv)
{
	char      optchars[MAX_INPUT_BUFFER];
	int       c = 1;
	int       have_mode = FALSE;
#ifdef HAVE_GETOPT_LONG
	int       option_index = 0;
	static struct option long_options[] = {
		{"config", required_argument, 0, 'c'},
		{"inetd", no_argument, 0, 'i'},
		/* To compatibility between short and long options but not used on AIX */
		{"src", no_argument, 0, 's'},
		{"no-forking", no_argument, 0, 'f'},
		{"4", no_argument, 0, '4'},
		{"ipv6", no_argument, 0, '6'},
		{"daemon", no_argument, 0, 'd'},
		{"no-ssl", no_argument, 0, 'n'},
		{"help", no_argument, 0, 'h'},
		{"license", no_argument, 0, 'l'},
		{"version", no_argument, 0, 'V'},
		{0, 0, 0, 0}
	};
#endif

	/* no options were supplied */
	if (argc < 2)
		return ERROR;

	snprintf(optchars, MAX_INPUT_BUFFER, "c:hVldi46nsf");

	while (1) {
#ifdef HAVE_GETOPT_LONG
		c = getopt_long(argc, argv, optchars, long_options, &option_index);
#else
		c = getopt(argc, argv, optchars);
#endif
		if (c == -1 || c == EOF)
			break;

		/* process all arguments */
		switch (c) {

		case '?':
		case 'h':
			show_help = TRUE;
			break;

		case 'V':
			show_version = TRUE;
			have_mode = TRUE;
			break;

		case 'l':
			show_license = TRUE;
			break;

		case 'c':
			strncpy(config_file, optarg, sizeof(config_file));
			config_file[sizeof(config_file) - 1] = '\x0';
			break;

		case 'd':
			use_inetd = FALSE;
			have_mode = TRUE;
			break;

		case 'i':
			use_inetd = TRUE;
			have_mode = TRUE;
			break;

		case '4':
			address_family = AF_INET;
			break;

		case '6':
			address_family = AF_INET6;
			break;

		case 'n':
			use_ssl = FALSE;
			break;

		case 's':				/* Argument s to indicate SRC option */
			use_src = TRUE;
			have_mode = TRUE;
			break;

		case 'f':
			use_inetd = FALSE;
			no_forking = TRUE;
			have_mode = TRUE;
			break;

		default:
			return ERROR;
		}
	}

	/* bail if we didn't get required args */
	if (have_mode == FALSE)
		return ERROR;

	return OK;
}
