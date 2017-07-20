/****************************************************************************
 *
 * check_nrpe.c - NRPE Plugin For Nagios
 *
 * License: GPLv2
 * Copyright (c) 2009-2017 Nagios Enterprises
 *               1999-2008 Ethan Galstad (nagios@nagios.org)
 *
 * Command line: 
 *
 * check_nrpe -H <host_address> [-p port] [-c command] [-to to_sec]
 *
 * Description:
 *
 * This plugin will attempt to connect to the NRPE daemon on the specified 
 * server and port. The daemon will attempt to run the command 
 * defined as [command]. Program output and return code are sent back 
 * from the daemon and displayed as this plugin's own 
 * output and return code.
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

#include "config.h"
#include "common.h"
#include "utils.h"

#define DEFAULT_NRPE_COMMAND "_NRPE_CHECK"	/* check version of NRPE daemon */

u_short server_port = 0;
char *server_name = NULL;
char *bind_address = NULL;
char *config_file = NULL;
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
struct sockaddr_storage hostaddr;
#else
struct sockaddr hostaddr;
#endif
int address_family = AF_UNSPEC;
char *command_name = NULL;
int socket_timeout = DEFAULT_SOCKET_TIMEOUT;
char timeout_txt[10];
int timeout_return_code = -1;
int stderr_to_stdout = 0;
int sd;

char rem_host[MAX_HOST_ADDRESS_LENGTH];
char query[MAX_INPUT_BUFFER] = "";

int show_help = FALSE;
int show_license = FALSE;
int show_version = FALSE;
int packet_ver = NRPE_PACKET_VERSION_3;
int force_v2_packet = 0;
int payload_size = 0;
extern char *log_file;

#ifdef HAVE_SSL
# if (defined(__sun) && defined(SOLARIS_10)) || defined(_AIX) || defined(__hpux)
SSL_METHOD *meth;
# else
const SSL_METHOD *meth;
# endif
SSL_CTX *ctx;
SSL *ssl;
int use_ssl = TRUE;
unsigned long ssl_opts = SSL_OP_ALL;
#else
int use_ssl = FALSE;
#endif

/* SSL/TLS parameters */
typedef enum _SSL_VER {
	SSL_Ver_Invalid = 0, SSLv2 = 1, SSLv2_plus, SSLv3, SSLv3_plus,
	TLSv1, TLSv1_plus, TLSv1_1, TLSv1_1_plus, TLSv1_2, TLSv1_2_plus
} SslVer;

typedef enum _CLNT_CERTS { Ask_For_Cert = 1, Require_Cert = 2 } ClntCerts;

typedef enum _SSL_LOGGING {
	SSL_NoLogging = 0, SSL_LogStartup = 1, SSL_LogIpAddr = 2,
	SSL_LogVersion = 4, SSL_LogCipher = 8, SSL_LogIfClientCert = 16,
	SSL_LogCertDetails = 32,
} SslLogging;

struct _SSL_PARMS {
	char *cert_file;
	char *cacert_file;
	char *privatekey_file;
	char cipher_list[MAX_FILENAME_LENGTH];
	SslVer ssl_proto_ver;
	int allowDH;
	ClntCerts client_certs;
	SslLogging log_opts;
} sslprm = {
NULL, NULL, NULL, "", SSL_Ver_Invalid, -1, 0, SSL_NoLogging};
int have_log_opts = FALSE;

int process_arguments(int, char **, int);
int read_config_file(char *);
const char *state_text (int result);
int translate_state (char *state_text);
void set_timeout_state (char *state);
int parse_timeout_string (char *timeout_str);
void usage(int result);
void setup_ssl();
void set_sig_handlers();
int connect_to_remote();
int send_request();
int read_response();
int read_packet(int sock, void *ssl_ptr, v2_packet ** v2_pkt, v3_packet ** v3_pkt);
#ifdef HAVE_SSL
static int verify_callback(int ok, X509_STORE_CTX * ctx);
#endif
void alarm_handler(int);
int graceful_close(int, int);

int main(int argc, char **argv)
{
	int16_t result;

	result = process_arguments(argc, argv, 0);

	if (result != OK || show_help == TRUE || show_license == TRUE || show_version == TRUE)
		usage(result);			/* usage() will call exit() */

	snprintf(timeout_txt, sizeof(timeout_txt), "%d", socket_timeout);

	if (server_port == 0)
		server_port = DEFAULT_SERVER_PORT;
	if (socket_timeout == -1)
		socket_timeout = DEFAULT_SOCKET_TIMEOUT;
	if (timeout_return_code == -1)
		timeout_return_code = STATE_CRITICAL;
	if (sslprm.cipher_list[0] == '\0')
#if OPENSSL_VERSION_NUMBER >= 0x10100000
		strncpy(sslprm.cipher_list, "ALL:!MD5:@STRENGTH:@SECLEVEL=0", MAX_FILENAME_LENGTH - 1);
#else
		strncpy(sslprm.cipher_list, "ALL:!MD5:@STRENGTH", MAX_FILENAME_LENGTH - 1);
#endif
	if (sslprm.ssl_proto_ver == SSL_Ver_Invalid)
		sslprm.ssl_proto_ver = TLSv1_plus;
	if (sslprm.allowDH == -1)
		sslprm.allowDH = TRUE;

	generate_crc32_table();		/* generate the CRC 32 table */
	setup_ssl();				/* Do all the SSL/TLS set up */
	set_sig_handlers();			/* initialize alarm signal handling */
	result = connect_to_remote();	/* Make the connection */
	if (result != STATE_OK) {
		alarm(0);
		return result;
	}

	result = send_request();	/* Send the request */
	if (result != STATE_OK)
		return result;

	result = read_response();	/* Get the response */

	if (result == -1) {
		/* Failure reading from remote, so try version 2 packet */
		logit(LOG_INFO, "Remote %s does not support Version 3 Packets", rem_host);
		packet_ver = NRPE_PACKET_VERSION_2;

		/* Rerun the setup */
		setup_ssl();
		set_sig_handlers();
		result = connect_to_remote();	/* Connect */
		if (result != STATE_OK) {
			alarm(0);
			close_log_file();			/* close the log file */
			return result;
		}

		result = send_request();	/* Send the request */
		if (result != STATE_OK) {
			close_log_file();			/* close the log file */
			return result;
		}

		result = read_response();	/* Get the response */
	}

	if (result != -1 && force_v2_packet == 0 && packet_ver == NRPE_PACKET_VERSION_2)
		logit(LOG_DEBUG, "Remote %s accepted a Version %d Packet", rem_host, packet_ver);

	close_log_file();			/* close the log file */
	return result;
}

/* process command line arguments */
int process_arguments(int argc, char **argv, int from_config_file)
{
	char optchars[MAX_INPUT_BUFFER];
	int argindex = 0;
	int c = 1;
	int i = 1;
	int has_cert = 0, has_priv_key = 0, rc;

#ifdef HAVE_GETOPT_LONG
	int option_index = 0;
	static struct option long_options[] = {
		{"host", required_argument, 0, 'H'},
		{"config-file", required_argument, 0, 'f'},
		{"bind", required_argument, 0, 'b'},
		{"command", required_argument, 0, 'c'},
		{"args", required_argument, 0, 'a'},
		{"no-ssl", no_argument, 0, 'n'},
		{"unknown-timeout", no_argument, 0, 'u'},
		{"v2-packets-only", no_argument, 0, '2'},
		{"ipv4", no_argument, 0, '4'},
		{"ipv6", no_argument, 0, '6'},
		{"use-adh", required_argument, 0, 'd'},
		{"ssl-version", required_argument, 0, 'S'},
		{"cipher-list", required_argument, 0, 'L'},
		{"client-cert", required_argument, 0, 'C'},
		{"key-file", required_argument, 0, 'K'},
		{"ca-cert-file", required_argument, 0, 'A'},
		{"ssl-logging", required_argument, 0, 's'},
		{"timeout", required_argument, 0, 't'},
		{"port", required_argument, 0, 'p'},
		{"payload-size", required_argument, 0, 'P'},
		{"log-file", required_argument, 0, 'g'},
		{"help", no_argument, 0, 'h'},
		{"license", no_argument, 0, 'l'},
		{"version", no_argument, 0, 'V'},
		{"stderr-to-stdout", no_argument, 0, 'E'},
		{0, 0, 0, 0}
	};
#endif

	/* no options were supplied */
	if (argc < 2)
		return ERROR;

	optind = 0;
	snprintf(optchars, MAX_INPUT_BUFFER, "H:f:b:c:a:t:p:S:L:C:K:A:d:s:P:g:246hlnuVE");

	while (1) {
		if (argindex > 0)
			break;
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

		case 'b':
			bind_address = strdup(optarg);
			break;

		case 'f':
			if (from_config_file) {
				printf("Error: The config file should not have a config-file (-f) option.\n");
				break;
			}
			config_file = strdup(optarg);
			break;

		case 'V':
			show_version = TRUE;
			break;

		case 'l':
			show_license = TRUE;
			break;

		case 't':
			if (from_config_file && socket_timeout != -1) {
				logit(LOG_WARNING, "WARNING: Command-line socket timeout overrides the config file option.");
				break;
			}
			socket_timeout=parse_timeout_string(optarg);
			if (socket_timeout <= 0)
				return ERROR;
			break;

		case 'p':
			if (from_config_file && server_port != 0) {
				logit(LOG_WARNING, "WARNING: Command-line server port overrides the config file option.");
				break;
			}
			server_port = atoi(optarg);
			if (server_port <= 0)
				return ERROR;
			break;

		case 'P':
			if (from_config_file && payload_size > 0) {
				logit(LOG_WARNING, "WARNING: Command-line payload-size (-P) overrides the config file option.");
				break;
			}
			payload_size = atoi(optarg);
			if (payload_size < 0)
				return ERROR;
			break;

		case 'H':
			if (from_config_file && server_name != NULL) {
				logit(LOG_WARNING, "WARNING: Command-line server name overrides the config file option.");
				break;
			}
			server_name = strdup(optarg);
			break;

		case 'E':
			if (from_config_file && stderr_to_stdout != 0) {
				logit(LOG_WARNING, "WARNING: Command-line stderr redirection overrides the config file option.");
				break;
			}
			stderr_to_stdout = 1;
			break;

		case 'c':
			if (from_config_file) {
				printf("Error: The config file should not have a command (-c) option.\n");
				return ERROR;
			}
			command_name = strdup(optarg);
			break;

		case 'a':
			if (from_config_file) {
				printf("Error: The config file should not have args (-a) arguments.\n");
				return ERROR;
			}
			argindex = optind;
			break;

		case 'n':
			use_ssl = FALSE;
			break;

		case 'u':
			if (from_config_file && timeout_return_code != -1) {
				logit(LOG_WARNING, "WARNING: Command-line unknown-timeout (-u) overrides the config file option.");
				break;
			}
			timeout_return_code = STATE_UNKNOWN;
			break;

		case '2':
			if (from_config_file && packet_ver != NRPE_PACKET_VERSION_3) {
				logit(LOG_WARNING, "WARNING: Command-line v2-packets-only (-2) overrides the config file option.");
				break;
			}
			packet_ver = NRPE_PACKET_VERSION_2;
			force_v2_packet = 1;
			break;

		case '4':
			if (from_config_file && address_family != AF_UNSPEC) {
				logit(LOG_WARNING, "WARNING: Command-line ipv4 (-4) or ipv6 (-6) overrides the config file option.");
				break;
			}
			address_family = AF_INET;
			break;

		case '6':
			if (from_config_file && address_family != AF_UNSPEC) {
				logit(LOG_WARNING, "WARNING: Command-line ipv4 (-4) or ipv6 (-6) overrides the config file option.");
				break;
			}
			address_family = AF_INET6;
			break;

		case 'd':
			if (from_config_file && sslprm.allowDH != -1) {
				logit(LOG_WARNING, "WARNING: Command-line use-adh (-d) overrides the config file option.");
				break;
			}
			if (!optarg || optarg[0] < '0' || optarg[0] > '2')
				return ERROR;
			sslprm.allowDH = atoi(optarg);
			break;

		case 'A':
			if (from_config_file && sslprm.cacert_file != NULL) {
				logit(LOG_WARNING, "WARNING: Command-line ca-cert-file (-A) overrides the config file option.");
				break;
			}
			sslprm.cacert_file = strdup(optarg);
			break;

		case 'C':
			if (from_config_file && sslprm.cert_file != NULL) {
				logit(LOG_WARNING, "WARNING: Command-line client-cert (-C) overrides the config file option.");
				break;
			}
			sslprm.cert_file = strdup(optarg);
			has_cert = 1;
			break;

		case 'K':
			if (from_config_file && sslprm.privatekey_file != NULL) {
				logit(LOG_WARNING, "WARNING: Command-line key-file (-K) overrides the config file option.");
				break;
			}
			sslprm.privatekey_file = strdup(optarg);
			has_priv_key = 1;
			break;

		case 'S':
			if (from_config_file && sslprm.ssl_proto_ver != SSL_Ver_Invalid) {
				logit(LOG_WARNING, "WARNING: Command-line ssl-version (-S) overrides the config file option.");
				break;
			}

			if (!strcmp(optarg, "TLSv1.2"))
				sslprm.ssl_proto_ver = TLSv1_2;
			else if (!strcmp(optarg, "TLSv1.2+"))
				sslprm.ssl_proto_ver = TLSv1_2_plus;
			else if (!strcmp(optarg, "TLSv1.1"))
				sslprm.ssl_proto_ver = TLSv1_1;
			else if (!strcmp(optarg, "TLSv1.1+"))
				sslprm.ssl_proto_ver = TLSv1_1_plus;
			else if (!strcmp(optarg, "TLSv1"))
				sslprm.ssl_proto_ver = TLSv1;
			else if (!strcmp(optarg, "TLSv1+"))
				sslprm.ssl_proto_ver = TLSv1_plus;
			else if (!strcmp(optarg, "SSLv3"))
				sslprm.ssl_proto_ver = SSLv3;
			else if (!strcmp(optarg, "SSLv3+"))
				sslprm.ssl_proto_ver = SSLv3_plus;
#if OPENSSL_VERSION_NUMBER < 0x10100000
			else if (!strcmp(optarg, "SSLv2"))
				sslprm.ssl_proto_ver = SSLv2;
			else if (!strcmp(optarg, "SSLv2+"))
				sslprm.ssl_proto_ver = SSLv2_plus;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000 */
			else
				return ERROR;
			break;

		case 'L':
			if (from_config_file && sslprm.cipher_list[0] != '\0') {
				logit(LOG_WARNING, "WARNING: Command-line cipher-list (-L) overrides the config file option.");
				break;
			}
			strncpy(sslprm.cipher_list, optarg, sizeof(sslprm.cipher_list) - 1);
			sslprm.cipher_list[sizeof(sslprm.cipher_list) - 1] = '\0';
			break;

		case 's':
			if (from_config_file && have_log_opts == TRUE) {
				logit(LOG_WARNING, "WARNING: Command-line ssl-logging (-s) overrides the config file option.");
				break;
			}
			sslprm.log_opts = strtoul(optarg, NULL, 0);
			have_log_opts = TRUE;
			break;

		case 'g':
			if (from_config_file && log_file != NULL) {
				logit(LOG_WARNING, "WARNING: Command-line log-file (-g) overrides the config file option.");
				break;
			}
			log_file = strdup(optarg);
			open_log_file();
			break;

		default:
			return ERROR;
		}
	}

	/* determine (base) command query */
	if (!from_config_file) {
		snprintf(query, sizeof(query), "%s",
				 (command_name == NULL) ? DEFAULT_NRPE_COMMAND : command_name);
		query[sizeof(query) - 1] = '\x0';
	}

	/* get the command args */
	if (!from_config_file && argindex > 0) {

		for (c = argindex - 1; c < argc; c++) {

			i = sizeof(query) - strlen(query) - 2;
			if (i <= 0)
				break;

			strcat(query, "!");
			strncat(query, argv[c], i);
			query[sizeof(query) - 1] = '\x0';
		}
	}
	if (!from_config_file && config_file != NULL) {
		if ((rc = read_config_file(config_file)) != OK)
			return rc;
	}

	if ((has_cert && !has_priv_key) || (!has_cert && has_priv_key)) {
		printf("Error: the client certificate and the private key must both be given or neither\n");
		return ERROR;
	}

	if (payload_size > 0 && packet_ver != NRPE_PACKET_VERSION_2) {
		printf("Error: if a fixed payload size is specified, '-2' must also be specified\n");
		return ERROR;
	}

	/* make sure required args were supplied */
	if (server_name == NULL && show_help == FALSE && show_version == FALSE
		&& show_license == FALSE)
		return ERROR;

	return OK;
}

int read_config_file(char *fname)
{
	int			rc, argc = 0;
	FILE		*f;
	char		*buf, *bufp, **argv;
	char		*delims = " \t\r\n";
	struct stat	st;
	size_t		sz;

	if (stat(fname, &st)) {
		logit(LOG_ERR, "Error: Could not stat config file %s", fname);
		return ERROR;
	}
	if ((f = fopen(fname, "r")) == NULL) {
		logit(LOG_ERR, "Error: Could not open config file %s", fname);
		return ERROR;
	}
	if ((buf = (char*)calloc(1, st.st_size + 2)) == NULL) {
		fclose(f);
		logit(LOG_ERR, "Error: read_config_file fail to allocate memory");
		return ERROR;
	}
	if ((sz = fread(buf, 1, st.st_size, f)) != st.st_size) {
		fclose(f);
		free(buf);
		logit(LOG_ERR, "Error: Failed to completely read config file %s", fname);
		return ERROR;
	}
	if ((argv = calloc(50, sizeof(char*))) == NULL) {
		fclose(f);
		free(buf);
		logit(LOG_ERR, "Error: read_config_file fail to allocate memory");
		return ERROR;
	}

	argv[argc++] = "check_nrpe";

	bufp = buf;
	while (argc < 50) {
		while (*bufp && strchr(delims, *bufp))
			++bufp;
		if (*bufp == '\0')
			break;
		argv[argc] = my_strsep(&bufp, delims);
		if (!argv[argc++])
			break;
		if (!bufp)
			break;
	}

	fclose(f);

	if (argc == 50) {
		free(buf);
		free(argv);
		logit(LOG_ERR, "Error: too many parameters in config file %s", fname);
		return ERROR;
	}

	rc = process_arguments(argc, argv, 1);
	free(buf);
	free(argv);
	return rc;
}

const char *state_text (int result)
{
	switch (result) {
		case STATE_OK:
			return "OK";
		case STATE_WARNING:
			return "WARNING";
		case STATE_CRITICAL:
			return "CRITICAL";
		default:
			return "UNKNOWN";
	}
}

int translate_state (char *state_text) {
       if (!strcasecmp(state_text,"OK") || !strcmp(state_text,"0"))
               return STATE_OK;
       if (!strcasecmp(state_text,"WARNING") || !strcmp(state_text,"1"))
               return STATE_WARNING;
       if (!strcasecmp(state_text,"CRITICAL") || !strcmp(state_text,"2"))
               return STATE_CRITICAL;
       if (!strcasecmp(state_text,"UNKNOWN") || !strcmp(state_text,"3"))
               return STATE_UNKNOWN;
       return ERROR;
}

void set_timeout_state (char *state) {
    if ((timeout_return_code = translate_state(state)) == ERROR)
        printf("Timeout state must be a valid state name (OK, WARNING, CRITICAL, UNKNOWN) or integer (0-3).\n");
}

int parse_timeout_string (char *timeout_str)
{
	char *separated_str;
	char *timeout_val = NULL;
	char *timeout_sta = NULL;

	if (strstr(timeout_str, ":") == NULL)
		timeout_val = timeout_str;
	else if (strncmp(timeout_str, ":", 1) == 0) {
		separated_str = strtok(timeout_str, ":");
		if (separated_str != NULL)
			timeout_sta = separated_str;
	} else {
		separated_str = strtok(timeout_str, ":");
		timeout_val = separated_str;
		separated_str = strtok(NULL, ":");
		if (separated_str != NULL) {
			timeout_sta = separated_str;
		}
	}

	if ( timeout_sta != NULL )
		set_timeout_state(timeout_sta);

	if ((timeout_val == NULL) || (timeout_val[0] == '\0'))
		return socket_timeout;
	else if (atoi(timeout_val) > 0)
		return atoi(timeout_val);
	else {
		printf("Timeout value must be a positive integer\n");
		exit (STATE_UNKNOWN);
	}
}

void usage(int result)
{
	if (result != OK) {
		printf("\n");
		printf("Incorrect command line arguments supplied\n");
		printf("\n");
	}
	printf("NRPE Plugin for Nagios\n");
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
		printf("SSL/TLS Available: OpenSSL 0.9.6 or higher required\n");
		printf("\n");
#endif
		printf("Usage: check_nrpe -H <host> [-2] [-4] [-6] [-n] [-u] [-V] [-l] [-d <dhopt>]\n");
		printf("       [-P <size>] [-S <ssl version>]  [-L <cipherlist>] [-C <clientcert>]\n");
		printf("       [-K <key>] [-A <ca-certificate>] [-s <logopts>] [-b <bindaddr>]\n");
		printf("       [-f <cfg-file>] [-p <port>] [-t <interval>:<state>] [-g <log-file>]\n");
		printf("       [-c <command>] [-E] [-a <arglist...>]\n");
		printf("\n");
		printf("Options:\n");
		printf(" -H, --host=HOST              The address of the host running the NRPE daemon\n");
		printf(" -2, --v2-packets-only        Only use version 2 packets, not version 3\n");
		printf(" -4, --ipv4                   Bind to ipv4 only\n");
		printf(" -6, --ipv6                   Bind to ipv6 only\n");
		printf(" -n, --no-ssl                 Do no use SSL\n");
		printf(" -u, --unknown-timeout        Make connection problems return UNKNOWN instead of CRITICAL\n");
		printf(" -V, --version                Print version info and quit\n");
		printf(" -l, --license                Show license\n");
		printf(" -E, --stderr-to-stdout       Redirect stderr to stdout\n");
		printf(" -d, --use-dh=DHOPT           Anonymous Diffie Hellman use:\n");
		printf("                              0         Don't use Anonymous Diffie Hellman\n");
		printf("                                        (This will be the default in a future release.)\n");
		printf("                              1         Allow Anonymous Diffie Hellman (default)\n");
		printf("                              2         Force Anonymous Diffie Hellman\n");
		printf(" -P, --payload-size=SIZE      Specify non-default payload size for NSClient++\n");
		printf(" -S, --ssl-version=VERSION    The SSL/TLS version to use. Can be any one of:\n");
#if OPENSSL_VERSION_NUMBER < 0x10100000
		printf("                              SSLv2     SSL v2 only\n");
		printf("                              SSLv2+    SSL v2 or above\n");
#endif
		printf("                              SSLv3     SSL v3 only\n");
		printf("                              SSLv3+    SSL v3 or above \n");
		printf("                              TLSv1     TLS v1 only\n");
		printf("                              TLSv1+    TLS v1 or above (DEFAULT)\n");
		printf("                              TLSv1.1   TLS v1.1 only\n");
		printf("                              TLSv1.1+  TLS v1.1 or above\n");
		printf("                              TLSv1.2   TLS v1.2 only\n");
		printf("                              TLSv1.2+  TLS v1.2 or above\n");
		printf(" -L, --cipher-list=LIST       The list of SSL ciphers to use (currently defaults\n");
#if OPENSSL_VERSION_NUMBER >= 0x10100000
		printf("                              to \"ALL:!MD5:@STRENGTH:@SECLEVEL=0\". THIS WILL change in a future release.)\n");
#else
		printf("                              to \"ALL:!MD5:@STRENGTH\". THIS WILL change in a future release.)\n");
#endif
		printf(" -C, --client-cert=FILE       The client certificate to use for PKI\n");
		printf(" -K, --key-file=FILE          The private key to use with the client certificate\n");
		printf(" -A, --ca-cert-file=FILE      The CA certificate to use for PKI\n");
		printf(" -s, --ssl-logging=OPTIONS    SSL Logging Options\n");
		printf(" -b, --bind=IPADDR            Local address to bind to\n");
		printf(" -f, --config-file=FILE       Configuration file to use\n");
		printf(" -g, --log-file=FILE          Log file to write to\n");
		printf(" -p, --port=PORT              The port on which the daemon is running (default=%d)\n", DEFAULT_SERVER_PORT);
		printf(" -c, --command=COMMAND        The name of the command that the remote daemon should run\n");
		printf(" -a, --args=LIST              Optional arguments that should be passed to the command,\n");
		printf("                              separated by a space. If provided, this must be the last\n");
		printf("                              option supplied on the command line.\n");
		printf("\n");
		printf(" NEW TIMEOUT SYNTAX\n");
		printf(" -t, --timeout=INTERVAL:STATE\n");
		printf("                              INTERVAL  Number of seconds before connection times out (default=%d)\n", DEFAULT_SOCKET_TIMEOUT);
		printf("                              STATE     Check state to exit with in the event of a timeout (default=CRITICAL)\n");
		printf("                              Timeout STATE must be a valid state name (case-insensitive) or integer:\n");
		printf("                              (OK, WARNING, CRITICAL, UNKNOWN) or integer (0-3)\n");
		printf("\n");
		printf("Note:\n");
		printf("This plugin requires that you have the NRPE daemon running on the remote host.\n");
		printf("You must also have configured the daemon to associate a specific plugin command\n");
		printf("with the [command] option you are specifying here. Upon receipt of the\n");
		printf("[command] argument, the NRPE daemon will run the appropriate plugin command and\n");
		printf("send the plugin output and return code back to *this* plugin. This allows you\n");
		printf("to execute plugins on remote hosts and 'fake' the results to make Nagios think\n");
		printf("the plugin is being run locally.\n");
		printf("\n");
	}

	if (show_license == TRUE)
		display_license();

	exit(STATE_UNKNOWN);
}

void setup_ssl()
{
#ifdef HAVE_SSL
	int vrfy, x;

	if (sslprm.log_opts & SSL_LogStartup) {
		char *val;

		logit(LOG_INFO, "SSL Certificate File: %s", sslprm.cert_file ? sslprm.cert_file : "None");
		logit(LOG_INFO, "SSL Private Key File: %s", sslprm.privatekey_file ? sslprm.privatekey_file : "None");
		logit(LOG_INFO, "SSL CA Certificate File: %s", sslprm.cacert_file ? sslprm.cacert_file : "None");
		logit(LOG_INFO, "SSL Cipher List: %s", sslprm.cipher_list);
		logit(LOG_INFO, "SSL Allow ADH: %d", sslprm.allowDH);
		logit(LOG_INFO, "SSL Log Options: 0x%02x", sslprm.log_opts);

		switch (sslprm.ssl_proto_ver) {
		case SSLv2:
			val = "SSLv2";
			break;
		case SSLv2_plus:
			val = "SSLv2 And Above";
			break;
		case SSLv3:
			val = "SSLv3";
			break;
		case SSLv3_plus:
			val = "SSLv3_plus And Above";
			break;
		case TLSv1:
			val = "TLSv1";
			break;
		case TLSv1_plus:
			val = "TLSv1_plus And Above";
			break;
		case TLSv1_1:
			val = "TLSv1_1";
			break;
		case TLSv1_1_plus:
			val = "TLSv1_1_plus And Above";
			break;
		case TLSv1_2:
			val = "TLSv1_2";
			break;
		case TLSv1_2_plus:
			val = "TLSv1_2_plus And Above";
			break;
		default:
			val = "INVALID VALUE!";
			break;
		}
		logit(LOG_INFO, "SSL Version: %s", val);
	}

	/* initialize SSL */
	if (use_ssl == TRUE) {
		SSL_load_error_strings();
		SSL_library_init();
		ENGINE_load_builtin_engines();
		RAND_set_rand_engine(NULL);
 		ENGINE_register_all_complete();

#if OPENSSL_VERSION_NUMBER >= 0x10100000

		meth = TLS_method();

#else		/* OPENSSL_VERSION_NUMBER >= 0x10100000 */

		meth = SSLv23_client_method();

# ifndef OPENSSL_NO_SSL2
		if (sslprm.ssl_proto_ver == SSLv2)
			meth = SSLv2_client_method();
# endif
# ifndef OPENSSL_NO_SSL3
		if (sslprm.ssl_proto_ver == SSLv3)
			meth = SSLv3_client_method();
# endif
		if (sslprm.ssl_proto_ver == TLSv1)
			meth = TLSv1_client_method();
# ifdef SSL_TXT_TLSV1_1
		if (sslprm.ssl_proto_ver == TLSv1_1)
			meth = TLSv1_1_client_method();
#  ifdef SSL_TXT_TLSV1_2
		if (sslprm.ssl_proto_ver == TLSv1_2)
			meth = TLSv1_2_client_method();
#  endif	/* ifdef SSL_TXT_TLSV1_2 */
# endif	/* ifdef SSL_TXT_TLSV1_1 */

#endif		/* OPENSSL_VERSION_NUMBER >= 0x10100000 */

		if ((ctx = SSL_CTX_new(meth)) == NULL) {
			printf("CHECK_NRPE: Error - could not create SSL context.\n");
			exit(STATE_CRITICAL);
		}

#if OPENSSL_VERSION_NUMBER >= 0x10100000

	SSL_CTX_set_max_proto_version(ctx, 0);

	switch(sslprm.ssl_proto_ver) {

		case TLSv1_2:
			SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
		case TLSv1_2_plus:
			SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
			break;

		case TLSv1_1:
			SSL_CTX_set_max_proto_version(ctx, TLS1_1_VERSION);
		case TLSv1_1_plus:
			SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
			break;

		case TLSv1:
			SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION);
		case TLSv1_plus:
			SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
			break;

		case SSLv3:
			SSL_CTX_set_max_proto_version(ctx, SSL3_VERSION);
		case SSLv3_plus:
			SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION);
			break;
	}

#else		/* OPENSSL_VERSION_NUMBER >= 0x10100000 */

		switch(sslprm.ssl_proto_ver) {
			case SSLv2:
			case SSLv2_plus:
				break;
			case TLSv1_2:
			case TLSv1_2_plus:
#ifdef SSL_OP_NO_TLSv1_1
				ssl_opts |= SSL_OP_NO_TLSv1_1;
#endif
			case TLSv1_1:
			case TLSv1_1_plus:
				ssl_opts |= SSL_OP_NO_TLSv1;
			case TLSv1:
			case TLSv1_plus:
				ssl_opts |= SSL_OP_NO_SSLv3;
			case SSLv3:
			case SSLv3_plus:
				ssl_opts |= SSL_OP_NO_SSLv2;
				break;
		}

#endif		/* OPENSSL_VERSION_NUMBER >= 0x10100000 */

		SSL_CTX_set_options(ctx, ssl_opts);

		if (sslprm.cert_file != NULL && sslprm.privatekey_file != NULL) {
			if (!SSL_CTX_use_certificate_file(ctx, sslprm.cert_file, SSL_FILETYPE_PEM)) {
				printf("Error: could not use certificate file '%s'.\n", sslprm.cert_file);
				while ((x = ERR_get_error_line_data(NULL, NULL, NULL, NULL)) != 0) {
					printf("Error: could not use certificate file '%s': %s\n", sslprm.cert_file, ERR_reason_error_string(x));
				}
				SSL_CTX_free(ctx);
				exit(STATE_CRITICAL);
			}
			if (!SSL_CTX_use_PrivateKey_file(ctx, sslprm.privatekey_file, SSL_FILETYPE_PEM)) {
				SSL_CTX_free(ctx);
				printf("Error: could not use private key file '%s'.\n", sslprm.privatekey_file);
				while ((x = ERR_get_error_line_data(NULL, NULL, NULL, NULL)) != 0) {
					printf("Error: could not use private key file '%s': %s\n", sslprm.privatekey_file, ERR_reason_error_string(x));
				}
				SSL_CTX_free(ctx);
				exit(STATE_CRITICAL);
			}
		}

		if (sslprm.cacert_file != NULL) {
			vrfy = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
			SSL_CTX_set_verify(ctx, vrfy, verify_callback);
			if (!SSL_CTX_load_verify_locations(ctx, sslprm.cacert_file, NULL)) {
				printf("Error: could not use CA certificate '%s'.\n", sslprm.cacert_file);
				while ((x = ERR_get_error_line_data(NULL, NULL, NULL, NULL)) != 0) {
					printf("Error: could not use CA certificate '%s': %s\n", sslprm.privatekey_file, ERR_reason_error_string(x));
				}
				SSL_CTX_free(ctx);
				exit(STATE_CRITICAL);
			}
		}

		if (!sslprm.allowDH) {
			if (strlen(sslprm.cipher_list) < sizeof(sslprm.cipher_list) - 6) {
				strcat(sslprm.cipher_list, ":!ADH");
				if (sslprm.log_opts & SSL_LogStartup)
					logit(LOG_INFO, "New SSL Cipher List: %s", sslprm.cipher_list);
			}
		} else {
			/* use anonymous DH ciphers */
			if (sslprm.allowDH == 2) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000
				strncpy(sslprm.cipher_list, "ADH@SECLEVEL=0", MAX_FILENAME_LENGTH - 1);
#else
				strncpy(sslprm.cipher_list, "ADH", MAX_FILENAME_LENGTH - 1);
#endif
			}
		}

		if (SSL_CTX_set_cipher_list(ctx, sslprm.cipher_list) == 0) {
			printf("Error: Could not set SSL/TLS cipher list: %s\n", sslprm.cipher_list);
			while ((x = ERR_get_error_line_data(NULL, NULL, NULL, NULL)) != 0) {
				printf("Could not set SSL/TLS cipher list '%s': %s\n", sslprm.cipher_list, ERR_reason_error_string(x));
			}
			SSL_CTX_free(ctx);
			exit(STATE_CRITICAL);
		}
	}
#endif
}

void set_sig_handlers()
{
#ifdef HAVE_SIGACTION
	struct sigaction sig_action;
#endif

#ifdef HAVE_SIGACTION
	sig_action.sa_sigaction = NULL;
	sig_action.sa_handler = alarm_handler;
	sigfillset(&sig_action.sa_mask);
	sig_action.sa_flags = SA_NODEFER | SA_RESTART;
	sigaction(SIGALRM, &sig_action, NULL);
#else
	signal(SIGALRM, alarm_handler);
#endif	 /* HAVE_SIGACTION */

	/* set socket timeout */
	alarm(socket_timeout);
}

int connect_to_remote()
{
	struct sockaddr addr;
	struct in_addr *inaddr;
	socklen_t addrlen;
	int result, rc, ssl_err, ern, x, nerrs = 0;

	/* try to connect to the host at the given port number */
	if ((sd = my_connect(server_name, &hostaddr, server_port, address_family, bind_address, stderr_to_stdout)) < 0)
		exit(timeout_return_code);

	result = STATE_OK;
	addrlen = sizeof(addr);
	rc = getpeername(sd, (struct sockaddr *)&addr, &addrlen);
	if (addr.sa_family == AF_INET) {
		struct sockaddr_in *addrin = (struct sockaddr_in *)&addr;
		inaddr = &addrin->sin_addr;
	} else {
		struct sockaddr_in6 *addrin = (struct sockaddr_in6 *)&addr;
		inaddr = (struct in_addr *)&addrin->sin6_addr;
	}
	if (inet_ntop(addr.sa_family, inaddr, rem_host, sizeof(rem_host)) == NULL)
		strncpy(rem_host, "Unknown", sizeof(rem_host));
	rem_host[MAX_HOST_ADDRESS_LENGTH - 1] = '\0';
	if ((sslprm.log_opts & SSL_LogIpAddr) != 0)
		logit(LOG_DEBUG, "Connected to %s", rem_host);

#ifdef HAVE_SSL
	if (use_ssl == FALSE)
		return result;

	/* do SSL handshake */
	if ((ssl = SSL_new(ctx)) == NULL) {
		printf("CHECK_NRPE: Error - Could not create SSL connection structure.\n");
		return STATE_CRITICAL;
	}

	SSL_set_fd(ssl, sd);
	if ((rc = SSL_connect(ssl)) != 1) {
		ern = errno;
		ssl_err = SSL_get_error(ssl, rc);

		if (sslprm.log_opts & (SSL_LogCertDetails | SSL_LogIfClientCert)) {
			rc = 0;
			while ((x = ERR_get_error_line_data(NULL, NULL, NULL, NULL)) != 0) {
				logit(LOG_ERR, "Error: (ERR_get_error_line_data = %d), Could not complete SSL handshake with %s: %s", x, rem_host, ERR_reason_error_string(x));
				++nerrs;
			}
			if (nerrs == 0) {
				logit(LOG_ERR, "Error: (nerrs = 0) Could not complete SSL handshake with %s: rc=%d SSL-error=%d", rem_host, rc, ssl_err);
			}
		} else {
			while ((x = ERR_get_error_line_data(NULL, NULL, NULL, NULL)) != 0) {
				logit(LOG_ERR, "Error: (!log_opts) Could not complete SSL handshake with %s: %s", rem_host, ERR_reason_error_string(x));
				++nerrs;
			}
			if (nerrs == 0) {
				logit(LOG_ERR, "Error: (nerrs = 0)(!log_opts) Could not complete SSL handshake with %s: rc=%d SSL-error=%d", rem_host, rc, ssl_err);
			}
		}

		if (ssl_err == 5) {
			/* Often, errno will be zero, so print a generic message here */
			if (ern == 0)
				printf("CHECK_NRPE: Error - Could not connect to %s. Check system logs on %s\n", rem_host, rem_host);
			else
				printf("CHECK_NRPE: Error - Could not connect to %s: %s\n", rem_host, strerror(ern));
		} else {
			printf("CHECK_NRPE: (ssl_err != 5) Error - Could not complete SSL handshake with %s: %d\n", rem_host, ssl_err);
		}

# ifdef DEBUG
		printf("SSL_connect=%d\n", rc);
		/*
		   rc = SSL_get_error(ssl, rc);
		   printf("SSL_get_error=%d\n", rc);
		   printf("ERR_get_error=%lu\n", ERR_get_error());
		   printf("%s\n",ERR_error_string(rc, NULL));
		 */
		ERR_print_errors_fp(stdout);
# endif
		result = STATE_CRITICAL;

	} else {

		if (sslprm.log_opts & SSL_LogVersion)
			logit(LOG_NOTICE, "Remote %s - SSL Version: %s", rem_host, SSL_get_version(ssl));

		if (sslprm.log_opts & SSL_LogCipher) {
# if (defined(__sun) && defined(SOLARIS_10)) || defined(_AIX) || defined(__hpux)
			SSL_CIPHER *c = SSL_get_current_cipher(ssl);
# else
			const SSL_CIPHER *c = SSL_get_current_cipher(ssl);
# endif
			logit(LOG_NOTICE, "Remote %s - %s, Cipher is %s", rem_host,
				   SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c));
		}

		if ((sslprm.log_opts & SSL_LogIfClientCert) || (sslprm.log_opts & SSL_LogCertDetails)) {
			char peer_cn[256], buffer[2048];
			X509 *peer = SSL_get_peer_certificate(ssl);

			if (peer) {
				if (sslprm.log_opts & SSL_LogIfClientCert)
					logit(LOG_NOTICE, "SSL %s has %s certificate", rem_host, SSL_get_verify_result(ssl) == X509_V_OK ? "a valid" : "an invalid");

				if (sslprm.log_opts & SSL_LogCertDetails) {
					X509_NAME_oneline(X509_get_subject_name(peer), buffer, sizeof(buffer));
					logit(LOG_NOTICE, "SSL %s Cert Name: %s", rem_host, buffer);
					X509_NAME_oneline(X509_get_issuer_name(peer), buffer, sizeof(buffer));
					logit(LOG_NOTICE, "SSL %s Cert Issuer: %s", rem_host, buffer);
				}

			} else
				logit(LOG_NOTICE, "SSL Did not get certificate from %s", rem_host);
		}
	}

	/* bail if we had errors */
	if (result != STATE_OK) {
		SSL_CTX_free(ctx);
		close(sd);
		exit(result);
	}
#endif

	return result;
}

int send_request()
{
	v2_packet *v2_send_packet = NULL;
	v3_packet *v3_send_packet = NULL;
	u_int32_t calculated_crc32;
	int rc, bytes_to_send, pkt_size;
	char *send_pkt;

	if (packet_ver == NRPE_PACKET_VERSION_2) {
		pkt_size = sizeof(v2_packet);
		if (payload_size > 0)
			pkt_size = sizeof(v2_packet) - MAX_PACKETBUFFER_LENGTH + payload_size;
		v2_send_packet = (v2_packet*)calloc(1, pkt_size);
		send_pkt = (char *)v2_send_packet;

		/* fill the packet with semi-random data */
		randomize_buffer((char *)v2_send_packet, pkt_size);

		/* initialize response packet data */
		v2_send_packet->packet_version = htons(packet_ver);
		v2_send_packet->packet_type = htons(QUERY_PACKET);
		if (payload_size > 0) {
			strncpy(&v2_send_packet->buffer[0], query, payload_size);
			v2_send_packet->buffer[payload_size - 1] = '\x0';
		} else {
			strncpy(&v2_send_packet->buffer[0], query, MAX_PACKETBUFFER_LENGTH);
			v2_send_packet->buffer[MAX_PACKETBUFFER_LENGTH - 1] = '\x0';
		}

		/* calculate the crc 32 value of the packet */
		v2_send_packet->crc32_value = 0;
		calculated_crc32 = calculate_crc32(send_pkt, pkt_size);
		v2_send_packet->crc32_value = htonl(calculated_crc32);

	} else {

		pkt_size = (sizeof(v3_packet) - 1) + strlen(query) + 1;
		if (pkt_size < sizeof(v2_packet))
			pkt_size = sizeof(v2_packet);

		v3_send_packet = calloc(1, pkt_size);
		send_pkt = (char *)v3_send_packet;
		/* initialize response packet data */
		v3_send_packet->packet_version = htons(packet_ver);
		v3_send_packet->packet_type = htons(QUERY_PACKET);
		v3_send_packet->alignment = 0;
		v3_send_packet->buffer_length = htonl(pkt_size - sizeof(v3_packet) + 1);
		strcpy(&v3_send_packet->buffer[0], query);

		/* calculate the crc 32 value of the packet */
		v3_send_packet->crc32_value = 0;
		calculated_crc32 = calculate_crc32((char *)v3_send_packet, pkt_size);
		v3_send_packet->crc32_value = htonl(calculated_crc32);
	}

	/* send the request to the remote */
	bytes_to_send = pkt_size;

	if (use_ssl == FALSE)
		rc = sendall(sd, (char *)send_pkt, &bytes_to_send);
#ifdef HAVE_SSL
	else {
		rc = SSL_write(ssl, send_pkt, bytes_to_send);
		if (rc < 0)
			rc = -1;
	}
#endif

	if (v3_send_packet)
		free(v3_send_packet);
	if (v2_send_packet)
		free(v2_send_packet);

	if (rc == -1) {
		printf("CHECK_NRPE: Error sending query to host.\n");
		close(sd);
		return STATE_UNKNOWN;
	}

	return STATE_OK;
}

int read_response()
{
	v2_packet *v2_receive_packet = NULL;
	v3_packet *v3_receive_packet = NULL;
	u_int32_t packet_crc32;
	u_int32_t calculated_crc32;
	int32_t pkt_size;
	int rc, result;

	alarm(0);
	set_sig_handlers();

#ifdef HAVE_SSL
	rc = read_packet(sd, ssl, &v2_receive_packet, &v3_receive_packet);
#else
	rc = read_packet(sd, NULL, &v2_receive_packet, &v3_receive_packet);
#endif

	alarm(0);

	/* close the connection */
#ifdef HAVE_SSL
	if (use_ssl == TRUE) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
		SSL_CTX_free(ctx);
	}
#endif
	graceful_close(sd, 1000);

	/* recv() error */
	if (rc < 0) {
		if (packet_ver == NRPE_PACKET_VERSION_3) {
			if (v3_receive_packet)
				free(v3_receive_packet);
			return -1;
		}
		if (v2_receive_packet)
			free(v2_receive_packet);
		return STATE_UNKNOWN;

	} else if (rc == 0) {

		/* server disconnected */
		printf("CHECK_NRPE: Received 0 bytes from daemon.  Check the remote server logs for error messages.\n");
		if (packet_ver == NRPE_PACKET_VERSION_3) {
			if (v3_receive_packet) {
				free(v3_receive_packet);
			}
		} else if (v2_receive_packet) {
			free(v2_receive_packet);
		}
		return STATE_UNKNOWN;
	}

	/* check the crc 32 value */
	if (packet_ver == NRPE_PACKET_VERSION_3) {
		pkt_size = (sizeof(v3_packet) - 1) + ntohl(v3_receive_packet->buffer_length);
		packet_crc32 = ntohl(v3_receive_packet->crc32_value);
		v3_receive_packet->crc32_value = 0L;
		v3_receive_packet->alignment = 0;
		calculated_crc32 = calculate_crc32((char *)v3_receive_packet, pkt_size);
	} else {
		pkt_size = sizeof(v2_packet);
		if (payload_size > 0) {
			pkt_size = sizeof(v2_packet) - MAX_PACKETBUFFER_LENGTH + payload_size;
		}
		packet_crc32 = ntohl(v2_receive_packet->crc32_value);
		v2_receive_packet->crc32_value = 0L;
		calculated_crc32 = calculate_crc32((char *)v2_receive_packet, pkt_size);
	}

	if (packet_crc32 != calculated_crc32) {
		printf("CHECK_NRPE: Response packet had invalid CRC32.\n");
		close(sd);
		if (packet_ver == NRPE_PACKET_VERSION_3) {
			if (v3_receive_packet) {
				free(v3_receive_packet);
			}
		} else if (v2_receive_packet) {
			free(v2_receive_packet);
		}
		return STATE_UNKNOWN;
	}

	/* get the return code from the remote plugin */
	/* and print the output returned by the daemon */
	if (packet_ver == NRPE_PACKET_VERSION_3) {
		result = ntohs(v3_receive_packet->result_code);
		if (v3_receive_packet->buffer_length == 0) {
			printf("CHECK_NRPE: No output returned from daemon.\n");
		} else {
			printf("%s\n", v3_receive_packet->buffer);
		}
	} else {
		result = ntohs(v2_receive_packet->result_code);
		if (payload_size > 0) {
			v2_receive_packet->buffer[payload_size - 1] = '\x0';
		} else {
			v2_receive_packet->buffer[MAX_PACKETBUFFER_LENGTH - 1] = '\x0';
		}
		if (!strcmp(v2_receive_packet->buffer, "")) {
			printf("CHECK_NRPE: No output returned from daemon.\n");
		} else if (strstr(v2_receive_packet->buffer, "Invalid packet version.3") != NULL) {
			/* NSClient++ doesn't recognize it */
			return -1;
		} else {
			printf("%s\n", v2_receive_packet->buffer);
		}
	}

	if (packet_ver == NRPE_PACKET_VERSION_3) {
		if (v3_receive_packet) {
			free(v3_receive_packet);
		}
	} else if (v2_receive_packet) {
		free(v2_receive_packet);
	}

	return result;
}

int read_packet(int sock, void *ssl_ptr, v2_packet ** v2_pkt, v3_packet ** v3_pkt)
{
	v2_packet	packet;
	int32_t pkt_size, common_size, tot_bytes, bytes_to_recv, buffer_size, bytes_read = 0;
	int rc;
	char *buff_ptr;

	/* Read only the part that's common between versions 2 & 3 */
	common_size = tot_bytes = bytes_to_recv = (char *)packet.buffer - (char *)&packet;

	if (use_ssl == FALSE) {
		rc = recvall(sock, (char *)&packet, &tot_bytes, socket_timeout);

		if (rc <= 0 || rc != bytes_to_recv) {
			if (rc < bytes_to_recv) {
				if (packet_ver != NRPE_PACKET_VERSION_3)
					printf("CHECK_NRPE: Receive header underflow - only %d bytes received (%ld expected).\n", rc, sizeof(bytes_to_recv));
			}
			return -1;
		}

		packet_ver = ntohs(packet.packet_version);
		if (packet_ver != NRPE_PACKET_VERSION_2 && packet_ver != NRPE_PACKET_VERSION_3) {
			printf("CHECK_NRPE: Invalid packet version received from server.\n");
			return -1;
		}

		if (ntohs(packet.packet_type) != RESPONSE_PACKET) {
			printf("CHECK_NRPE: Invalid packet type received from server.\n");
			return -1;
		}

		if (packet_ver == NRPE_PACKET_VERSION_2) {
			pkt_size = sizeof(v2_packet);
			if (payload_size > 0) {
				pkt_size = common_size + payload_size;
				buffer_size = payload_size;
			} else {
				buffer_size = pkt_size - common_size;
			}
			if ((*v2_pkt = calloc(1, pkt_size)) == NULL) {
				logit(LOG_ERR, "Error: Could not allocate memory for packet");
				return -1;
			}
			memcpy(*v2_pkt, &packet, common_size);
			buff_ptr = (*v2_pkt)->buffer;
			memset(buff_ptr, 0, buffer_size);
		} else {
			pkt_size = sizeof(v3_packet) - 1;

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
				logit(LOG_ERR, "Error: Could not allocate memory for packet");
				return -1;
			}

			memcpy(*v3_pkt, &packet, common_size);
			(*v3_pkt)->buffer_length = htonl(buffer_size);
			buff_ptr = (*v3_pkt)->buffer;
		}

		bytes_to_recv = buffer_size;
		rc = recvall(sock, buff_ptr, &bytes_to_recv, socket_timeout);

		if (rc <= 0 || rc != buffer_size) {
			if (packet_ver == NRPE_PACKET_VERSION_3) {
				free(*v3_pkt);
				*v3_pkt = NULL;
			} else {
				free(*v2_pkt);
				*v2_pkt = NULL;
			}
			if (rc < buffer_size)
				printf("CHECK_NRPE: Receive underflow - only %d bytes received (%ld expected).\n", rc, sizeof(buffer_size));
			return -1;
		} else
			tot_bytes += rc;
	}
#ifdef HAVE_SSL
	else {
		SSL *ssl = (SSL *) ssl_ptr;

		while (((rc = SSL_read(ssl, &packet, bytes_to_recv)) <= 0)
			   && (SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ)) {
		}

		if (rc <= 0 || rc != bytes_to_recv) {
			if (rc < bytes_to_recv) {
				if (packet_ver != NRPE_PACKET_VERSION_3)
					printf("CHECK_NRPE: Receive header underflow - only %d bytes received (%ld expected).\n", rc, sizeof(bytes_to_recv));
			}
			return -1;
		}

		packet_ver = ntohs(packet.packet_version);
		if (packet_ver != NRPE_PACKET_VERSION_2 && packet_ver != NRPE_PACKET_VERSION_3) {
			printf("CHECK_NRPE: Invalid packet version received from server.\n");
			return -1;
		}

		if (ntohs(packet.packet_type) != RESPONSE_PACKET) {
			printf("CHECK_NRPE: Invalid packet type received from server.\n");
			return -1;
		}

		if (packet_ver == NRPE_PACKET_VERSION_2) {
			pkt_size = sizeof(v2_packet);
			if (payload_size > 0) {
				pkt_size = common_size + payload_size;
				buffer_size = payload_size;
			} else
				buffer_size = pkt_size - common_size;
			if ((*v2_pkt = calloc(1, pkt_size)) == NULL) {
				logit(LOG_ERR, "Error: Could not allocate memory for packet");
				return -1;
			}
			memcpy(*v2_pkt, &packet, common_size);
			buff_ptr = (*v2_pkt)->buffer;
			memset(buff_ptr, 0, buffer_size);
		} else {
			pkt_size = sizeof(v3_packet) - 1;

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
				logit(LOG_ERR, "Error: Could not allocate memory for packet");
				return -1;
			}

			memcpy(*v3_pkt, &packet, common_size);
			(*v3_pkt)->buffer_length = htonl(buffer_size);
			buff_ptr = (*v3_pkt)->buffer;
		}

		bytes_to_recv = buffer_size;
		for (;;) {
			while (((rc = SSL_read(ssl, &buff_ptr[bytes_read], bytes_to_recv)) <= 0)
				   && (SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ)) {
			}

			if (rc <= 0)
				break;
			bytes_read += rc;
			bytes_to_recv -= rc;
		}

		buff_ptr[bytes_read] = 0;

		if (rc < 0 || bytes_read != buffer_size) {
			if (packet_ver == NRPE_PACKET_VERSION_3) {
				free(*v3_pkt);
				*v3_pkt = NULL;
			} else {
				free(*v2_pkt);
				*v2_pkt = NULL;
			}
			if (bytes_read != buffer_size) {
				if (packet_ver == NRPE_PACKET_VERSION_3) {
					printf("CHECK_NRPE: Receive buffer size - %ld bytes received (%ld expected).\n", (long)bytes_read, sizeof(buffer_size));
				} else {
					printf("CHECK_NRPE: Receive underflow - only %ld bytes received (%ld expected).\n", (long)bytes_read, sizeof(buffer_size));
				}
			}
			return -1;
		} else
			tot_bytes += rc;
	}
#endif

	return tot_bytes;
}

#ifdef HAVE_SSL
int verify_callback(int preverify_ok, X509_STORE_CTX * ctx)
{
	char name[256], issuer[256];
	X509 *err_cert;
	int err;
	SSL *ssl;

	if (preverify_ok || ((sslprm.log_opts & SSL_LogCertDetails) == 0))
		return preverify_ok;

	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);

	/* Get the pointer to the SSL of the current connection */
	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

	X509_NAME_oneline(X509_get_subject_name(err_cert), name, 256);
	X509_NAME_oneline(X509_get_issuer_name(err_cert), issuer, 256);

	if (!preverify_ok && sslprm.client_certs >= Ask_For_Cert
		&& (sslprm.log_opts & SSL_LogCertDetails)) {
		
		logit(LOG_ERR, "SSL Client has an invalid certificate: %s (issuer=%s) err=%d:%s", name, issuer, err, X509_verify_cert_error_string(err));
	}

	return preverify_ok;
}
#endif

void alarm_handler(int sig)
{
	const char	msg1[] = "CHECK_NRPE STATE ";
	const char	msg2[] = ": Socket timeout after ";
	const char	msg3[] = " seconds.\n";
	const char	*text = state_text(timeout_return_code);
	size_t		lth1 = 0, lth2 = 0;

	for (lth1 = 0; lth1 < 10; ++lth1)
		if (text[lth1] == 0)
			break;
	for (lth2 = 0; lth2 < 10; ++lth2)
		if (timeout_txt[lth2] == 0)
			break;

	
	if ((write(STDOUT_FILENO, msg1, sizeof(msg1) - 1) == -1)
		|| (write(STDOUT_FILENO, text, lth1) == -1)
		|| (write(STDOUT_FILENO, msg2, sizeof(msg2) - 1) == -1)
		|| (write(STDOUT_FILENO, timeout_txt, lth2) == -1)
		|| (write(STDOUT_FILENO, msg3, sizeof(msg3) - 1) == -1)) {

		logit(LOG_ERR, "ERROR: alarm_handler() write(): %s", strerror(errno));
	}

	exit(timeout_return_code);
}

/* submitted by Mark Plaksin 08/31/2006 */
int graceful_close(int sd, int timeout)
{
	fd_set in;
	struct timeval tv;
	char buf[1000];

	/* send FIN packet */
	shutdown(sd, SHUT_WR);

	for (;;) {
		FD_ZERO(&in);
		FD_SET(sd, &in);
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;

		/* timeout or error */
		if (1 != select(sd + 1, &in, NULL, NULL, &tv))
			break;

		/* no more data (FIN or RST) */
		if (0 >= recv(sd, buf, sizeof(buf), 0))
			break;
	}

#ifdef HAVE_CLOSESOCKET
	closesocket(sd);
#else
	close(sd);
#endif

	return OK;
}
