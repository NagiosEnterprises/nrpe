/*******************************************************************************
 *
 * NRPE.C - Nagios Remote Plugin Executor
 *
 * Copyright (c) 2009 Nagios Core Development Team and Community Contributors
 * Copyright (c) 1999-2008 Ethan Galstad (nagios@nagios.org)
 * License: GPL
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
 ******************************************************************************/

/*
 * 08-10-2011 IPv4 subnetworks support added.
 * Main change in nrpe.c is that is_an_allowed_host() moved to acl.c.
 * now allowed_hosts is parsed by parse_allowed_hosts() from acl.c.
 */

#include "config.h"
#include "common.h"
#include "nrpe.h"
#include "utils.h"
#include "acl.h"

#ifdef HAVE_SSL
# ifdef USE_SSL_DH
#  include "../include/dh.h"
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

#ifdef HAVE_SSL
# if (defined(__sun) && defined(SOLARIS_10)) || defined(_AIX) || defined(__hpux)
SSL_METHOD *meth;
# else
const SSL_METHOD *meth;
# endif
SSL_CTX  *ctx;
int       use_ssl = TRUE;
#else
int       use_ssl = FALSE;
#endif

#define DEFAULT_COMMAND_TIMEOUT			60	/* default timeout for execution of plugins */
#define MAXFD							64
#define NASTY_METACHARS					"|`&><'\\[]{};\r\n"
#define MAX_LISTEN_SOCKS				16
#define DEFAULT_LISTEN_QUEUE_SIZE		5
#define DEFAULT_SSL_SHUTDOWN_TIMEOUT	15

#define how_many(x,y) (((x)+((y)-1))/(y))

extern int errno;
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
int       debug = FALSE;
int       use_src = FALSE;		/* Define parameter for SRC option */
int       no_forking = FALSE;
int       listen_queue_size = DEFAULT_LISTEN_QUEUE_SIZE;

/* SSL/TLS parameters */
typedef enum _SSL_VER {
	SSLv2 = 1, SSLv2_plus, SSLv3, SSLv3_plus, TLSv1,
	TLSv1_plus, TLSv1_1, TLSv1_1_plus, TLSv1_2, TLSv1_2_plus
} SslVer;

typedef enum _CLNT_CERTS {
	ClntCerts_Unknown = 0, Ask_For_Cert = 1, Require_Cert = 2
} ClntCerts;

typedef enum _SSL_LOGGING {
	SSL_NoLogging = 0, SSL_LogStartup = 1, SSL_LogIpAddr = 2,
	SSL_LogVersion = 4, SSL_LogCipher = 8, SSL_LogIfClientCert = 16,
	SSL_LogCertDetails = 32
} SslLogging;

struct _SSL_PARMS {
	char     *cert_file;
	char     *cacert_file;
	char     *privatekey_file;
	char      cipher_list[MAX_FILENAME_LENGTH];
	SslVer    ssl_min_ver;
	int       allowDH;
	ClntCerts client_certs;
	SslLogging log_opts;
} sslprm = {
NULL, NULL, NULL, "ALL:!MD5:@STRENGTH", TLSv1_plus, TRUE, 0, SSL_NoLogging};


#ifdef HAVE_SSL
static int verify_callback(int ok, X509_STORE_CTX * ctx);
static void my_disconnect_sighandler(int sig);
static void complete_SSL_shutdown(SSL *);
#endif

int main(int argc, char **argv)
{
	int       result = OK;
	int       x;
	uint32_t  y;
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
		strcpy(config_file, "");
		getcwd(config_file, sizeof(config_file));

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
		syslog(LOG_ERR, "Config file '%s' contained errors, aborting...", config_file);
		return STATE_CRITICAL;
	}

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
	DH       *dh;
	char      seedfile[FILENAME_MAX];
	int       i, c, x;
	int       ssl_opts = SSL_OP_ALL | SSL_OP_SINGLE_DH_USE, vrfy;

	if (use_ssl == FALSE) {
		if (debug == TRUE)
			syslog(LOG_INFO, "INFO: SSL/TLS NOT initialized. Network encryption DISABLED.");
		return;
	}

#ifndef USE_SSL_DH
	ssl_opts = SSL_OP_ALL;
	sslprm.allowDH = 0;
#endif

	if (sslprm.log_opts & SSL_LogStartup)
		log_ssl_startup();

	/* initialize SSL */
	SSL_load_error_strings();
	SSL_library_init();

	meth = SSLv23_server_method();

	/* use week random seed if necessary */
	if (allow_weak_random_seed && (RAND_status() == 0)) {
		if (RAND_file_name(seedfile, sizeof(seedfile) - 1))
			if (RAND_load_file(seedfile, -1))
				RAND_write_file(seedfile);

		if (RAND_status() == 0) {
			syslog(LOG_ERR,
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
# ifndef OPENSSL_NO_SSL2
	if (sslprm.ssl_min_ver == SSLv2)
		meth = SSLv2_server_method();
# endif
# ifndef OPENSSL_NO_SSL3
	if (sslprm.ssl_min_ver == SSLv3)
		meth = SSLv3_server_method();
# endif
	if (sslprm.ssl_min_ver == TLSv1)
		meth = TLSv1_server_method();
# ifdef SSL_TXT_TLSV1_1
	if (sslprm.ssl_min_ver == TLSv1_1)
		meth = TLSv1_1_server_method();
#  ifdef SSL_TXT_TLSV1_2
	if (sslprm.ssl_min_ver == TLSv1_2)
		meth = TLSv1_2_server_method();
#  endif
# endif

	ctx = SSL_CTX_new(meth);
	if (ctx == NULL) {
		syslog(LOG_ERR, "Error: could not create SSL context");
		SSL_CTX_free(ctx);
		exit(STATE_CRITICAL);
	}

	if (sslprm.ssl_min_ver >= SSLv3) {
		ssl_opts |= SSL_OP_NO_SSLv2;
		if (sslprm.ssl_min_ver >= TLSv1)
			ssl_opts |= SSL_OP_NO_SSLv3;
	}
	SSL_CTX_set_options(ctx, ssl_opts);

	if (sslprm.cert_file != NULL) {
		if (!SSL_CTX_use_certificate_file(ctx, sslprm.cert_file, SSL_FILETYPE_PEM)) {
			SSL_CTX_free(ctx);
			while ((x = ERR_get_error()) != 0)
				syslog(LOG_ERR, "Error: could not use certificate file %s : %s",
					   sslprm.cert_file, ERR_error_string(x, NULL));
			exit(STATE_CRITICAL);
		}
		if (!SSL_CTX_use_PrivateKey_file(ctx, sslprm.privatekey_file, SSL_FILETYPE_PEM)) {
			SSL_CTX_free(ctx);
			syslog(LOG_ERR, "Error: could not use private key file '%s'",
				   sslprm.privatekey_file);
			exit(STATE_CRITICAL);
		}
	}

	if (sslprm.client_certs != 0) {
		vrfy = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
		if ((sslprm.client_certs & Require_Cert) != 0)
			vrfy |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		SSL_CTX_set_verify(ctx, vrfy, verify_callback);
		if (!SSL_CTX_load_verify_locations(ctx, sslprm.cacert_file, NULL)) {
			SSL_CTX_free(ctx);
			syslog(LOG_ERR, "Error: could not use CA certificate '%s'", sslprm.cacert_file);
			exit(STATE_CRITICAL);
		}
	}

	if (!sslprm.allowDH) {
		if (strlen(sslprm.cipher_list) < sizeof(sslprm.cipher_list) - 6)
			strcat(sslprm.cipher_list, ":!ADH");
	} else {
		/* use anonymous DH ciphers */
		if (sslprm.allowDH == 2)
			strcpy(sslprm.cipher_list, "ADH");
#ifdef USE_SSL_DH
		dh = get_dh2048();
		SSL_CTX_set_tmp_dh(ctx, dh);
		DH_free(dh);
#endif
	}

	if (SSL_CTX_set_cipher_list(ctx, sslprm.cipher_list) == 0) {
		SSL_CTX_free(ctx);
		syslog(LOG_ERR, "Error: Could not set SSL/TLS cipher list");
		exit(STATE_CRITICAL);
	}

	if (debug == TRUE)
		syslog(LOG_INFO, "INFO: SSL/TLS initialized. All network traffic will be encrypted.");
#endif
}

void log_ssl_startup(void)
{
#ifdef HAVE_SSL
	char     *vers;

	syslog(LOG_INFO, "SSL Certificate File: %s", sslprm.cert_file ? sslprm.cert_file : "None");
	syslog(LOG_INFO, "SSL Private Key File: %s",
		   sslprm.privatekey_file ? sslprm.privatekey_file : "None");
	syslog(LOG_INFO, "SSL CA Certificate File: %s",
		   sslprm.cacert_file ? sslprm.cacert_file : "None");
	if (sslprm.allowDH < 2)
		syslog(LOG_INFO, "SSL Cipher List: %s", sslprm.cipher_list);
	else
		syslog(LOG_INFO, "SSL Cipher List: ADH");
	syslog(LOG_INFO, "SSL Allow ADH: %s",
		   sslprm.allowDH == 0 ? "No" : (sslprm.allowDH == 1 ? "Allow" : "Require"));
	syslog(LOG_INFO, "SSL Client Certs: %s",
		   sslprm.client_certs == 0 ? "Don't Ask" : (sslprm.client_certs ==
													 1 ? "Accept" : "Require"));
	syslog(LOG_INFO, "SSL Log Options: 0x%02x", sslprm.log_opts);
	switch (sslprm.ssl_min_ver) {
	case SSLv2:
		vers = "SSLv2";
		break;
	case SSLv2_plus:
		vers = "SSLv2 And Above";
		break;
	case SSLv3:
		vers = "SSLv3";
		break;
	case SSLv3_plus:
		vers = "SSLv3 And Above";
		break;
	case TLSv1:
		vers = "TLSv1";
		break;
	case TLSv1_plus:
		vers = "TLSv1 And Above";
		break;
	case TLSv1_1:
		vers = "TLSv1_1";
		break;
	case TLSv1_1_plus:
		vers = "TLSv1_1 And Above";
		break;
	case TLSv1_2:
		vers = "TLSv1_2";
		break;
	case TLSv1_2_plus:
		vers = "TLSv1_2 And Above";
		break;
	default:
		vers = "INVALID VALUE!";
		break;
	}
	syslog(LOG_INFO, "SSL Version: %s", vers);
#endif
}

void usage(int result)
{
	printf("\n");
	printf("NRPE - Nagios Remote Plugin Executor\n");
	printf("Copyright (c) 1999-2008 Ethan Galstad (nagios@nagios.org)\n");
	printf("Version: %s\n", PROGRAM_VERSION);
	printf("Last Modified: %s\n", MODIFICATION_DATE);
	printf("License: GPL v2 with exemptions (-l for more info)\n");
#ifdef HAVE_SSL
	printf("SSL/TLS Available, OpenSSL 0.9.6 or higher required\n");
#endif
#ifdef HAVE_LIBWRAP
	printf("TCP Wrappers Available\n");
#endif
	printf("\n");
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

	if (show_license == TRUE)
		display_license();

	if (result != OK || show_help == TRUE) {
		printf("Usage: nrpe [-n] -c <config_file> [-4|-6] <mode>\n");
		printf("\n");
		printf("Options:\n");
		printf(" -n               = Do not use SSL\n");
		printf(" -c <config_file> = Name of config file to use\n");
		printf(" -4               = use ipv4 only\n");
		printf(" -6               = use ipv6 only\n");
		printf(" <mode>           = One of the following operating modes:\n");
		printf("   -i             =    Run as a service under inetd or xinetd\n");
		printf("   -d             =    Run as a standalone daemon\n");
		printf("   -d -s          =    Run as a subsystem under AIX\n");
		printf("   -f             =    Don't fork() for systemd, launchd, etc.\n");
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
			syslog(LOG_ERR, "fork() failed with error %d, bailing out...", errno);
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

	close(0);					/* close standard file descriptors */
	close(1);
	close(2);
	open("/dev/null", O_RDONLY);	/* redirect standard descriptors to /dev/null */
	open("/dev/null", O_WRONLY);
	open("/dev/null", O_WRONLY);

	chdir("/");

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

	syslog(LOG_NOTICE, "Starting up daemon");	/* log info to syslog facility */
	if (write_pid_file() == ERROR)	/* write pid file */
		exit(STATE_CRITICAL);

	clean_environ(keep_env_vars, nrpe_user);
	drop_privileges(nrpe_user, nrpe_group, 0);	/* drop privileges */
	check_privileges();			/* make sure we're not root */
}

void cleanup(void)
{
	int       result;

	free_memory();				/* free all memory we allocated */

	if (sigrestart == TRUE && sigshutdown == FALSE) {
		result = read_config_file(config_file);	/* read the config file */

		if (result == ERROR) {	/* exit if there are errors... */
			syslog(LOG_ERR, "Config file '%s' contained errors, bailing out...", config_file);
			exit(STATE_CRITICAL);
		}
		return;
	}

	remove_pid_file();			/* remove pid file */
	syslog(LOG_NOTICE, "Daemon shutdown\n");
}

#ifdef HAVE_SSL
int verify_callback(int preverify_ok, X509_STORE_CTX * ctx)
{
	char      name[256], issuer[256];
	X509     *err_cert;
	int       err;
	SSL      *ssl;

	if (preverify_ok || ((sslprm.log_opts & SSL_LogCertDetails) == 0))
		return preverify_ok;

	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);

	/* Get the pointer to the SSL of the current connection */
	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

	X509_NAME_oneline(X509_get_subject_name(err_cert), name, 256);
	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), issuer, 256);

	if (!preverify_ok && (sslprm.log_opts & SSL_LogCertDetails)) {
		syslog(LOG_ERR, "SSL Client has an invalid certificate: %s (issuer=%s) err=%d:%s",
			   name, issuer, err, X509_verify_cert_error_string(err));
	}

	return preverify_ok;
}
#endif

/* read in the configuration file */
int read_config_file(char *filename)
{
	struct stat st;
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
		syslog(LOG_ERR, "Unable to open config file '%s' for reading\n", filename);
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
			syslog(LOG_ERR, "No variable name specified in config file '%s' - Line %d\n",
				   filename, line);
			return ERROR;
		}

		/* get the variable value */
		varvalue = strtok(NULL, "\n");
		if (varvalue == NULL) {
			syslog(LOG_ERR, "No variable value specified in config file '%s' - Line %d\n",
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
				syslog(LOG_ERR, "Continuing with errors...");

		} else if (!strcmp(varname, "include") || !strcmp(varname, "include_file")) {
			/* allow users to specify individual config files to include */

			/* process the config file... */
			if (read_config_file(varvalue) == ERROR)
				syslog(LOG_ERR, "Continuing with errors...");

		} else if (!strcmp(varname, "server_port")) {
			server_port = atoi(varvalue);
			if (server_port < 1024) {
				syslog(LOG_ERR,
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

		} else if (strstr(input_line, "command[")) {
			temp_buffer = strtok(varname, "[");
			temp_buffer = strtok(NULL, "]");
			if (temp_buffer == NULL) {
				syslog(LOG_ERR, "Invalid command specified in config file '%s' - Line %d\n",
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

		else if (!strcmp(varname, "allow_bash_command_substitution"))
			allow_bash_cmd_subst = (atoi(varvalue) == 1) ? TRUE : FALSE;

		else if (!strcmp(varname, "command_timeout")) {
			command_timeout = atoi(varvalue);
			if (command_timeout < 1) {
				syslog(LOG_ERR,
					   "Invalid command_timeout specified in config file '%s' - Line %d\n",
					   filename, line);
				return ERROR;
			}
		} else if (!strcmp(varname, "connection_timeout")) {
			connection_timeout = atoi(varvalue);
			if (connection_timeout < 1) {
				syslog(LOG_ERR,
					   "Invalid connection_timeout specified in config file '%s' - Line %d\n",
					   filename, line);
				return ERROR;
			}

		} else if (!strcmp(varname, "ssl_shutdown_timeout")) {
			ssl_shutdown_timeout = atoi(varvalue);
			if (ssl_shutdown_timeout < 1) {
				syslog(LOG_ERR,
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
				syslog(LOG_ERR,
					   "Invalid listen queue size specified in config file '%s' - Line %d\n",
					   filename, line);
				return ERROR;
			}

		} else if (!strcmp(varname, "ssl_version")) {
			if (!strcmp(varvalue, "SSLv2"))
				sslprm.ssl_min_ver = SSLv2;
			else if (!strcmp(varvalue, "SSLv2+"))
				sslprm.ssl_min_ver = SSLv2_plus;
			else if (!strcmp(varvalue, "SSLv3"))
				sslprm.ssl_min_ver = SSLv3;
			else if (!strcmp(varvalue, "SSLv3+"))
				sslprm.ssl_min_ver = SSLv3_plus;
			else if (!strcmp(varvalue, "TLSv1"))
				sslprm.ssl_min_ver = TLSv1;
			else if (!strcmp(varvalue, "TLSv1+"))
				sslprm.ssl_min_ver = TLSv1_plus;
			else if (!strcmp(varvalue, "TLSv1.1"))
				sslprm.ssl_min_ver = TLSv1_1;
			else if (!strcmp(varvalue, "TLSv1.1+"))
				sslprm.ssl_min_ver = TLSv1_1_plus;
			else if (!strcmp(varvalue, "TLSv1.2"))
				sslprm.ssl_min_ver = TLSv1_2;
			else if (!strcmp(varvalue, "TLSv1.2+"))
				sslprm.ssl_min_ver = TLSv1_2_plus;
			else {
				syslog(LOG_ERR, "Invalid ssl version specified in config file '%s' - Line %d",
					   filename, line);
				return ERROR;
			}

		} else if (!strcmp(varname, "ssl_use_adh")) {
			sslprm.allowDH = atoi(varvalue);
			if (sslprm.allowDH < 0 || sslprm.allowDH > 2) {
				syslog(LOG_ERR,
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
				syslog(LOG_ERR,
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
				syslog(LOG_WARNING,
					   "Invalid log_facility specified in config file '%s' - Line %d\n",
					   filename, line);

		} else if (!strcmp(varname, "keep_env_vars"))
			keep_env_vars = strdup(varvalue);

		else {
			syslog(LOG_WARNING, "Unknown option specified in config file '%s' - Line %d\n",
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
	struct stat buf;
	char      config_file[MAX_FILENAME_LENGTH];
	DIR      *dirp;
	int       result = OK;
	int       x;

	/* open the directory for reading */
	dirp = opendir(dirname);
	if (dirp == NULL) {
		syslog(LOG_ERR, "Could not open config directory '%s' for reading.\n", dirname);
		return ERROR;
	}

	/* process all files in the directory... */
	while ((dirfile = readdir(dirp)) != NULL) {

		/* create the full path to the config file or subdirectory */
		snprintf(config_file, sizeof(config_file) - 1, "%s/%s", dirname, dirfile->d_name);
		config_file[sizeof(config_file) - 1] = '\x0';
		stat(config_file, &buf);

		/* process this if it's a config file... */
		x = strlen(dirfile->d_name);
		if (x > 4 && !strcmp(dirfile->d_name + (x - 4), ".cfg")) {

			/* only process normal files */
			if (!S_ISREG(buf.st_mode))
				continue;

			/* process the config file */
			result = read_config_file(config_file);

			/* break out if we encountered an error */
			if (result == ERROR)
				break;
		}

		/* recurse into subdirectories... */
		if (S_ISDIR(buf.st_mode)) {

			/* ignore current, parent and hidden directory entries */
			if (dirfile->d_name[0] == '.')
				continue;

			/* process the config directory */
			result = read_config_dir(config_file);

			/* break out if we encountered an error */
			if (result == ERROR)
				break;
		}
	}

	closedir(dirp);
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
		syslog(LOG_DEBUG, "Added command[%s]=%s\n", command_name, command_line);

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
		syslog(LOG_ERR, "Too many listen sockets. Enlarge MAX_LISTEN_SOCKS");
		exit(1);
	}

	if ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, sizeof(ntop),
						   strport, sizeof(strport), NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
		syslog(LOG_ERR, "getnameinfo failed: %.100s", gai_strerror(ret));
		return;
	}

	/* Create socket for listening. */
	listen_sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (listen_sock < 0) {
		/* kernel may not support ipv6 */
		syslog(LOG_ERR, "socket: %.100s", strerror(errno));
		return;
	}

	/* socket should be non-blocking */
	fcntl(listen_sock, F_SETFL, O_NONBLOCK);

	/* set the reuse address flag so we don't get errors when restarting */
	if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
		syslog(LOG_ERR, "setsockopt SO_REUSEADDR: %s", strerror(errno));
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
		syslog(LOG_ERR, "Bind to port %s on %s failed: %.200s.",
			   strport, ntop, strerror(errno));
		close(listen_sock);
		return;
	}
	listen_socks[num_listen_socks] = listen_sock;
	num_listen_socks++;

	/* Start listening on the port. */
	if (listen(listen_sock, listen_queue_size) < 0) {
		syslog(LOG_ERR, "listen on [%s]:%s: %.100s", ntop, strport, strerror(errno));
		exit(1);
	}

	syslog(LOG_INFO, "Server listening on %s port %s.", ntop, strport);
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

			/* log info to syslog facility */
			if (debug == TRUE)
				syslog(LOG_DEBUG, "Connection from %s closed.", remote_host);

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

	add_listen_addr(&listen_addrs, address_family,
					(strcmp(server_address, "") == 0) ? NULL : server_address, server_port);

	for (ai = listen_addrs; ai; ai = ai->ai_next)
		create_listener(ai);

	if (!num_listen_socks) {
		syslog(LOG_ERR, "Cannot bind to any address.");
		exit(1);
	}

	/* log warning about command arguments */
#ifdef ENABLE_COMMAND_ARGUMENTS
	if (allow_arguments == TRUE)
		syslog(LOG_NOTICE,
			   "Warning: Daemon is configured to accept command arguments from clients!");
# ifdef ENABLE_BASH_COMMAND_SUBSTITUTION
	if (TRUE == allow_bash_cmd_subst) {
		if (TRUE == allow_arguments)
			syslog(LOG_NOTICE,
				   "Warning: Daemon is configured to accept command arguments with bash command substitutions!");
		else
			syslog(LOG_NOTICE,
				   "Warning: Daemon is configured to accept command arguments with bash command substitutions, but is not configured to accept command argements from clients. Enable command arguments if you wish to allow command arguments with bash command substitutions.");
	}
# endif
#endif

	syslog(LOG_INFO, "Listening for connections on port %d", server_port);

	if (allowed_hosts)
		syslog(LOG_INFO, "Allowing connections from: %s\n", allowed_hosts);
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
		syslog(LOG_ERR, "fork() failed with error %d, bailing out...", errno);
		exit(STATE_CRITICAL);
	}

	/* fork again so we don't create zombies */
	pid = fork();

	if (pid < 0) {
		syslog(LOG_ERR, "fork() failed with error %d, bailing out...", errno);
		exit(STATE_CRITICAL);
	}

	if (pid > 0) {
		/* first child returns immediately, grandchild is inherited by
		   INIT process -> no zombies... */
		exit(STATE_OK);
	}

	/* hey, there was an error... */
	if (sock < 0) {
		/* log error to syslog facility */
		syslog(LOG_ERR, "Network server accept failure (%d: %s)",
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
		/* log error to syslog facility */
		syslog(LOG_ERR, "Error: Network server getpeername() failure (%d: %s)",
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


	/* is this is a blessed machine? */
	if (allowed_hosts) {
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
		switch (addr.ss_family) {
#else
		switch (addr.sa_family) {
#endif

		case AF_INET:
			/* log info to syslog facility */
			if (debug == TRUE || (sslprm.log_opts & SSL_LogIpAddr))
				syslog(LOG_DEBUG, "Connection from %s port %d", remote_host, nptr->sin_port);

			if (!is_an_allowed_host(AF_INET, (void *)&(nptr->sin_addr))) {
				/* log error to syslog facility */
				syslog(LOG_ERR, "Host %s is not allowed to talk to us!", remote_host);

				/* log info to syslog facility */
				if (debug == TRUE)
					syslog(LOG_DEBUG, "Connection from %s closed.", remote_host);

				/* close socket prior to exiting */
				close(sock);
				exit(STATE_OK);

			} else {

				/* log info to syslog facility */
				if (debug == TRUE) {
					syslog(LOG_DEBUG, "Host address is in allowed_hosts");
				}

			}
			break;

		case AF_INET6:
			/* log info to syslog facility */
			strcpy(remote_host, ipstr);
			if (debug == TRUE || (sslprm.log_opts & SSL_LogIpAddr)) {
				syslog(LOG_DEBUG, "Connection from %s port %d", ipstr, nptr6->sin6_port);
			}

			if (!is_an_allowed_host(AF_INET6, (void *)&(nptr6->sin6_addr))) {
				/* log error to syslog facility */
				syslog(LOG_ERR, "Host %s is not allowed to talk to us!", ipstr);

				/* log info to syslog facility */
				if (debug == TRUE)
					syslog(LOG_DEBUG, "Connection from %s closed.", ipstr);

				/* close socket prior to exiting */
				close(sock);
				exit(STATE_OK);

			} else {
				/* log info to syslog facility */
				if (debug == TRUE)
					syslog(LOG_DEBUG, "Host address is in allowed_hosts");
			}
			break;
		}
	}

#ifdef HAVE_LIBWRAP
	/* Check whether or not connections are allowed from this host */
	request_init(&req, RQ_DAEMON, "nrpe", RQ_FILE, sock, 0);
	fromhost(&req);

	if (!hosts_access(&req)) {
		syslog(LOG_DEBUG, "Connection refused by TCP wrapper");
		refuse(&req);			/* refuse the connection */
		/* should not be reached */
		syslog(LOG_ERR, "libwrap refuse() returns!");
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
        	syslog(LOG_ERR, "Error: Could not create SSL connection structure.");
# ifdef DEBUG
            errfp = fopen("/tmp/err.log", "a");
    		ERR_print_errors_fp(errfp);
        	fclose(errfp);
# endif
    		return;
        }

		if (handle_conn_ssl(sock, ssl) != OK)
			return;
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
		/* log error to syslog facility */
		syslog(LOG_ERR, "Could not read request from client %s, bailing out...", remote_host);
		if (v3_receive_packet)
			free(v3_receive_packet);
#ifdef HAVE_SSL
		if (ssl) {
			complete_SSL_shutdown(ssl);
			SSL_free(ssl);
			syslog(LOG_INFO, "INFO: SSL Socket Shutdown.\n");
		}
#endif
		return;
	}

	/* make sure the request is valid */
	if (validate_request(&receive_packet, v3_receive_packet) == ERROR) {
		/* log an error */
		syslog(LOG_ERR, "Client request from %s was invalid, bailing out...", remote_host);

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

	/* log info to syslog facility */
	if (debug == TRUE)
		syslog(LOG_DEBUG, "Host %s is asking for command '%s' to be run...",
			   remote_host, command_name);

	/* if this is the version check command, just spew it out */
	if (!strcmp(command_name, NRPE_HELLO_COMMAND)) {
		snprintf(buffer, sizeof(buffer), "NRPE v%s", PROGRAM_VERSION);
		buffer[sizeof(buffer) - 1] = '\x0';
		if (debug == TRUE)		/* log info to syslog facility */
			syslog(LOG_DEBUG, "Response to %s: %s", remote_host, buffer);
		if (v3_receive_packet)
			send_buff = strdup(buffer);
		else {
			send_buff = calloc(1, sizeof(buffer));
			strcpy(send_buff, buffer);
		}
		result = STATE_OK;

	} else {

		/* find the command we're supposed to run */
		temp_command = find_command(command_name);
		if (temp_command == NULL) {
			snprintf(buffer, sizeof(buffer), "NRPE: Command '%s' not defined", command_name);
			buffer[sizeof(buffer) - 1] = '\x0';
			if (debug == TRUE)	/* log error to syslog facility */
				syslog(LOG_DEBUG, "%s", buffer);
			if (v3_receive_packet)
				send_buff = strdup(buffer);
			else {
				send_buff = calloc(1, sizeof(buffer));
				strcpy(send_buff, buffer);
			}
			result = STATE_CRITICAL;

		} else {

			/* process command line */
			if (command_prefix == NULL)
				strncpy(raw_command, temp_command->command_line, sizeof(raw_command) - 1);
			else
				snprintf(raw_command, sizeof(raw_command) - 1, "%s %s", command_prefix,
						 temp_command->command_line);
			raw_command[sizeof(raw_command) - 1] = '\x0';
			process_macros(raw_command, processed_command, sizeof(processed_command));

			if (debug == TRUE)	/* log info to syslog facility */
				syslog(LOG_DEBUG, "Running command: %s", processed_command);

			/* run the command */
			strcpy(buffer, "");
			result = my_system(processed_command, command_timeout, &early_timeout, &send_buff);

			if (debug == TRUE)	/* log debug info */
				syslog(LOG_DEBUG, "Command completed with return code %d and output: %s",
					   result, send_buff);

			/* see if the command timed out */
			if (early_timeout == TRUE) {
				sprintf(send_buff, "NRPE: Command timed out after %d seconds\n",
						command_timeout);
				result = STATE_UNKNOWN;
			} else if (!strcmp(send_buff, "")) {
				sprintf(send_buff, "NRPE: Unable to read output\n");
				result = STATE_UNKNOWN;
			}

			/* check return code bounds */
			if ((result < 0) || (result > 3)) {
				/* log error to syslog facility */
				syslog(LOG_ERR, "Bad return code for [%s]: %d", send_buff, result);
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

		pkt_size = (sizeof(v3_packet) - 1) + strlen(send_buff);
		v3_send_packet = calloc(1, pkt_size);
		send_pkt = (char *)v3_send_packet;
		/* initialize response packet data */
		v3_send_packet->packet_version = htons(packet_ver);
		v3_send_packet->packet_type = htons(RESPONSE_PACKET);
		v3_send_packet->result_code = htons(result);
		v3_send_packet->alignment = 0;
		v3_send_packet->buffer_length = htonl(strlen(send_buff));
		strcpy(&v3_send_packet->buffer[0], send_buff);

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

	/* log info to syslog facility */
	if (debug == TRUE)
		syslog(LOG_DEBUG, "Return Code: %d, Output: %s", result, send_buff);

	free(send_buff);

	return;
}

void init_handle_conn(void)
{
#ifdef HAVE_SIGACTION
	struct sigaction sig_action;
#endif

	/* log info to syslog facility */
	if (debug == TRUE)
		syslog(LOG_DEBUG, "Handling the connection...");

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
	char      buffer[MAX_INPUT_BUFFER];
	SSL      *ssl = (SSL*)ssl_ptr;
	X509     *peer;
	int       rc, x;

	SSL_set_fd(ssl, sock);

	/* keep attempting the request if needed */
	while (((rc = SSL_accept(ssl)) != 1)
		   && (SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ)) ;

	if (rc != 1) {
		/* oops, got an unrecoverable error -- get out */
		if (sslprm.log_opts & (SSL_LogCertDetails | SSL_LogIfClientCert)) {
			int       nerrs = 0;
			rc = 0;
			while ((x = ERR_get_error_line_data(NULL, NULL, NULL, NULL)) != 0) {
				syslog(LOG_ERR, "Error: Could not complete SSL handshake with %s: %s",
					   remote_host, ERR_reason_error_string(x));
				++nerrs;
			}
			if (nerrs == 0)
				syslog(LOG_ERR, "Error: Could not complete SSL handshake with %s: %d",
					   remote_host, SSL_get_error(ssl, rc));

		} else
			syslog(LOG_ERR, "Error: Could not complete SSL handshake with %s: %d",
				   remote_host, SSL_get_error(ssl, rc));
# ifdef DEBUG
		errfp = fopen("/tmp/err.log", "a");
		ERR_print_errors_fp(errfp);
		fclose(errfp);
# endif
		return ERROR;
	}

	/* successful handshake */
	if (sslprm.log_opts & SSL_LogVersion)
		syslog(LOG_NOTICE, "Remote %s - SSL Version: %s",
			   remote_host, SSL_get_version(ssl));
	if (sslprm.log_opts & SSL_LogCipher) {
		c = SSL_get_current_cipher(ssl);
		syslog(LOG_NOTICE, "Remote %s - %s, Cipher is %s", remote_host,
			   SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c));
	}

	if ((sslprm.log_opts & SSL_LogIfClientCert)
		|| (sslprm.log_opts & SSL_LogCertDetails))
	{
		peer = SSL_get_peer_certificate(ssl);

		if (peer) {
			if (sslprm.log_opts & SSL_LogIfClientCert)
				syslog(LOG_NOTICE, "SSL Client %s has %svalid certificate",
					   remote_host, peer->valid ? "a " : "an in");
			if (sslprm.log_opts & SSL_LogCertDetails) {
				syslog(LOG_NOTICE, "SSL Client %s Cert Name: %s",
					   remote_host, peer->name);
				X509_NAME_oneline(X509_get_issuer_name(peer), buffer, sizeof(buffer));
				syslog(LOG_NOTICE, "SSL Client %s Cert Issuer: %s",
					   remote_host, buffer);
			}

		} else if (sslprm.client_certs == 0)
			syslog(LOG_NOTICE, "SSL Not asking for client certification");

		else
			syslog(LOG_NOTICE, "SSL Client %s did not present a certificate",
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
		if (packet_ver != NRPE_PACKET_VERSION_2 && packet_ver != NRPE_PACKET_VERSION_3) {
			syslog(LOG_ERR, "Error: Request packet version was invalid!");
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
			pkt_size += buffer_size;
			if ((*v3_pkt = calloc(1, pkt_size)) == NULL) {
				syslog(LOG_ERR, "Error: Could not allocate memory for packet");
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

		while (((rc = SSL_read(ssl, v2_pkt, bytes_to_recv)) <= 0)
			   && (SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ)) {
		}

		if (rc <= 0 || rc != bytes_to_recv)
			return -1;

		packet_ver = ntohs(v2_pkt->packet_version);
		if (packet_ver != NRPE_PACKET_VERSION_2 && packet_ver != NRPE_PACKET_VERSION_3) {
			syslog(LOG_ERR, "Error: Request packet version was invalid!");
			return -1;
		}

		if (packet_ver == NRPE_PACKET_VERSION_2) {
			buffer_size = sizeof(v2_packet) - common_size;
			buff_ptr = (char *)v2_pkt + common_size;
		} else {
			int32_t   pkt_size = sizeof(v3_packet) - 1;

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
			pkt_size += buffer_size;
			if ((*v3_pkt = calloc(1, pkt_size)) == NULL) {
				syslog(LOG_ERR, "Error: Could not allocate memory for packet");
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

/* executes a system command via popen(), but protects against timeouts */
int my_system(char *command, int timeout, int *early_timeout, char **output)
{
	FILE     *fp;
	pid_t     pid;
	time_t    start_time, end_time;
	int       status;
	int       result;
	char      buffer[MAX_INPUT_BUFFER];
	int       fd[2];
	int       bytes_read = 0, tot_bytes = 0;
	int       output_size;
#ifdef HAVE_SIGACTION
	struct sigaction sig_action;
#endif

	*early_timeout = FALSE;		/* initialize return variables */

	if (command == NULL)		/* if no command was passed, return with no error */
		return STATE_OK;

	pipe(fd);					/* create a pipe */

	/* make the pipe non-blocking */
	fcntl(fd[0], F_SETFL, O_NONBLOCK);
	fcntl(fd[1], F_SETFL, O_NONBLOCK);

	time(&start_time);			/* get the command start time */

	pid = fork();				/* fork */

	/* return an error if we couldn't fork */
	if (pid == -1) {
		snprintf(buffer, sizeof(buffer) - 1, "NRPE: Call to fork() failed\n");
		buffer[sizeof(buffer) - 1] = '\x0';

		if (packet_ver == NRPE_PACKET_VERSION_2) {
			int       output_size = sizeof(v2_packet);
			*output = calloc(1, output_size);
			strncpy(*output, buffer, output_size - 1);
			*output[output_size - 1] = '\0';
		} else
			*output = strdup(buffer);

		/* close both ends of the pipe */
		close(fd[0]);
		close(fd[1]);

		return STATE_UNKNOWN;
	}

	/* execute the command in the child process */
	if (pid == 0) {
		SETEUID(0);				/* get root back so the next call works correctly */
		drop_privileges(nrpe_user, nrpe_group, 1);	/* drop privileges */
		close(fd[0]);			/* close pipe for reading */
		setpgid(0, 0);			/* become process group leader */

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
			write(fd[1], buffer, strlen(buffer) + 1);
			result = STATE_CRITICAL;

		} else {

			/* read all lines of output - supports Nagios 3.x multiline output */
			while ((bytes_read = fread(buffer, 1, sizeof(buffer) - 1, fp)) > 0) {
				/* write the output back to the parent process */
				write(fd[1], buffer, bytes_read);
			}

			write(fd[1], "\0", 1);
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

		close(fd[1]);			/* close pipe for writing */
		alarm(0);				/* reset the alarm */
		exit(result);			/* return plugin exit code to parent process */

	} else {
		/* parent waits for child to finish executing command */

		close(fd[1]);			/* close pipe for writing */
		waitpid(pid, &status, 0);	/* wait for child to exit */
		time(&end_time);		/* get the end time for running the command */
		result = WEXITSTATUS(status);	/* get the exit code returned from the program */

		/* because of my idiotic idea of having UNKNOWN states be equivalent to -1, I must hack things a bit... */
		if (result == 255)
			result = STATE_UNKNOWN;

		/* check bounds on the return value */
		if (result < 0 || result > 3)
			result = STATE_UNKNOWN;

		if (packet_ver == NRPE_PACKET_VERSION_2) {
			output_size = sizeof(v2_packet);
			*output = calloc(1, output_size);
		} else {
			output_size = 1024 * 64;	/* Maximum buffer is 64K */
			*output = calloc(1, output_size);
		}

		/* try and read the results from the command output (retry if we encountered a signal) */
		for (;;) {
			bytes_read = read(fd[0], buffer, sizeof(buffer) - 1);
			if (bytes_read == 0)
				break;
			if (bytes_read == -1) {
				if (errno == EINTR)
					continue;
				else
					break;
			}
			if (tot_bytes < output_size)	/* If buffer is full, discard the rest */
				strncat(*output, buffer, output_size - tot_bytes);
			tot_bytes += bytes_read;
		}

		(*output)[output_size - 1] = '\0';

		/* if there was a critical return code and no output AND the
		 * command time exceeded the timeout thresholds, assume a timeout */
		if (result == STATE_CRITICAL && bytes_read == -1 && (end_time - start_time) >= timeout) {
			*early_timeout = TRUE;

			/* send termination signal to child process group */
			kill((pid_t) (-pid), SIGTERM);
			kill((pid_t) (-pid), SIGKILL);
		}

		close(fd[0]);			/* close the pipe for reading */
	}

#ifdef DEBUG
	printf("my_system() end\n");
#endif

	return result;
}

/* handle timeouts when executing commands via my_system() */
void my_system_sighandler(int sig)
{
	exit(STATE_CRITICAL);		/* force the child process to exit... */
}

/* handle errors where connection takes too long */
void my_connection_sighandler(int sig)
{
	syslog(LOG_ERR, "Connection has taken too long to establish. Exiting...");
	exit(STATE_CRITICAL);
}

/* drops privileges */
int drop_privileges(char *user, char *group, int full_drop)
{
	uid_t     uid = -1;
	gid_t     gid = -1;
	struct group *grp;
	struct passwd *pw;

	/* set effective group ID */
	if (group != NULL) {

		/* see if this is a group name */
		if (strspn(group, "0123456789") < strlen(group)) {
			grp = (struct group *)getgrnam(group);
			if (grp != NULL)
				gid = (gid_t) (grp->gr_gid);
			else
				syslog(LOG_ERR, "Warning: Could not get group entry for '%s'", group);
			endgrent();

		} else
			/* else we were passed the GID */
			gid = (gid_t) atoi(group);

		/* set effective group ID if other than current EGID */
		if (gid != getegid()) {
			if (setgid(gid) == -1)
				syslog(LOG_ERR, "Warning: Could not set effective GID=%d", (int)gid);
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
				syslog(LOG_ERR, "Warning: Could not get passwd entry for '%s'", user);
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
					syslog(LOG_ERR,
						   "Warning: Unable to change supplementary groups using initgroups()");
				else {
					syslog(LOG_ERR,
						   "Warning: Possibly root user failed dropping privileges with initgroups()");
					return ERROR;
				}
			}
#endif

			if (full_drop) {
				if (setuid(uid) == -1)
					syslog(LOG_ERR, "Warning: Could not set UID=%d", (int)uid);
			} else if (SETEUID(uid) == -1)
				syslog(LOG_ERR, "Warning: Could not set effective UID=%d", (int)uid);
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
				syslog(LOG_ERR,
					   "There's already an NRPE server running (PID %lu).  Bailing out...",
					   (unsigned long)pid);
				return ERROR;
			}
		}
	}

	/* write new pid file */
	if ((fd = open(pid_file, O_WRONLY | O_CREAT, 0644)) >= 0) {
		sprintf(pbuf, "%d\n", (int)getpid());
		write(fd, pbuf, strlen(pbuf));
		close(fd);
		wrote_pid_file = TRUE;
	} else {
		syslog(LOG_ERR, "Cannot write to pidfile '%s' - check your privileges.", pid_file);
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

	SETEUID(0);					/* get root back so we can delete the pid file */
	if (unlink(pid_file) == -1) {
		syslog(LOG_ERR, "Cannot remove pidfile '%s' - check your privileges.", pid_file);
		return ERROR;
	}

	return OK;
}

#ifdef HAVE_SSL

void my_disconnect_sighandler(int sig)
{
	syslog(LOG_ERR, "SSL_shutdown() has taken too long to complete. Exiting now..");
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
		syslog(LOG_ERR, "Error: NRPE daemon cannot be run as user/group root!");
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
		syslog(LOG_NOTICE, "Caught SIGHUP - restarting...\n");
	}

	/* else begin shutting down... */
	if (sig == SIGTERM) {
		/* if shutdown is already true, we're in a signal trap loop! */
		if (sigshutdown == TRUE)
			exit(STATE_CRITICAL);
		sigshutdown = TRUE;
		syslog(LOG_NOTICE, "Caught SIG%s - shutting down...\n", sigs[sig]);
	}

	return;
}

/* handle signals (child processes) */
void child_sighandler(int sig)
{
	exit(0);					/* terminate */
	return;						/* so the compiler doesn't complain... */
}

/* tests whether or not a client request is valid */
int validate_request(v2_packet * v2pkt, v3_packet * v3pkt)
{
	u_int32_t	packet_crc32;
	u_int32_t	calculated_crc32;
	char		*buff, *ptr;
	int			rc;
#ifdef ENABLE_COMMAND_ARGUMENTS
	int			x;
#endif

	/* check the crc 32 value */
	if (packet_ver == NRPE_PACKET_VERSION_3) {
		int32_t   pkt_size = (sizeof(v3_packet) - 1) + ntohl(v3pkt->buffer_length);
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
		syslog(LOG_ERR, "Error: Request packet had invalid CRC32.");
		return ERROR;
	}

	/* make sure this is the right type of packet */
	if (ntohs(v2pkt->packet_type) != QUERY_PACKET) {
		syslog(LOG_ERR, "Error: Request packet type was invalid!");
		return ERROR;
	}

	/* make sure buffer is terminated */
	if (packet_ver == NRPE_PACKET_VERSION_3) {
		int32_t   l = ntohs(v3pkt->buffer_length);
		v3pkt->buffer[l - 1] = '\x0';
		buff = v3pkt->buffer;
	} else {
		v2pkt->buffer[MAX_PACKETBUFFER_LENGTH - 1] = '\x0';
		buff = v2pkt->buffer;
	}

	/* client must send some kind of request */
	if (buff[0] == '\0') {
		syslog(LOG_ERR, "Error: Request contained no query!");
		return ERROR;
	}

	/* make sure request doesn't contain nasties */
	if (packet_ver == NRPE_PACKET_VERSION_3)
		rc = contains_nasty_metachars(v3pkt->buffer);
	else
		rc = contains_nasty_metachars(v2pkt->buffer);
	if (rc == TRUE) {
		syslog(LOG_ERR, "Error: Request contained illegal metachars!");
		return ERROR;
	}

	/* make sure the request doesn't contain arguments */
	if (strchr(v2pkt->buffer, '!')) {
#ifdef ENABLE_COMMAND_ARGUMENTS
		if (allow_arguments == FALSE) {
			syslog(LOG_ERR,
				   "Error: Request contained command arguments, but argument option is not enabled!");
			return ERROR;
		}
#else
		syslog(LOG_ERR, "Error: Request contained command arguments!");
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
		syslog(LOG_ERR, "Error: Memory allocation failed");
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
				syslog(LOG_ERR, "Error: Memory allocation failed");
				return ERROR;
			}
			if (!strcmp(macro_argv[x], "")) {
				syslog(LOG_ERR, "Error: Request contained an empty command argument");
				return ERROR;
			}
			if (strstr(macro_argv[x], "$(")) {
# ifndef ENABLE_BASH_COMMAND_SUBSTITUTION
				syslog(LOG_ERR, "Error: Request contained a bash command substitution!");
				return ERROR;
# else
				if (FALSE == allow_bash_cmd_subst) {
					syslog(LOG_ERR,
						   "Error: Request contained a bash command substitution, but they are disallowed!");
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

	result = strcspn(str, NASTY_METACHARS);
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

	strcpy(output_buffer, "");

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
		{"6", no_argument, 0, '4'},
		{"daemon", no_argument, 0, 'd'},
		{"no-ssl", no_argument, 0, 'n'},
		{"help", no_argument, 0, 'h'},
		{"license", no_argument, 0, 'l'},
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
			break;
		}
	}

	/* bail if we didn't get required args */
	if (have_mode == FALSE)
		return ERROR;

	return OK;
}
