/********************************************************************************************
 *
 * CHECK_NRPE.C - NRPE Plugin For Nagios
 * Copyright (c) 1999-2008 Ethan Galstad (nagios@nagios.org)
 * License: GPL
 *
 * Last Modified: 11-09-2015
 *
 * Command line: CHECK_NRPE -H <host_address> [-p port] [-c command] [-to to_sec]
 *
 * Description:
 *
 * This plugin will attempt to connect to the NRPE daemon on the specified server and port.
 * The daemon will attempt to run the command defined as [command].  Program output and
 * return code are sent back from the daemon and displayed as this plugin's own output and
 * return code.
 *
 ********************************************************************************************/

#include "config.h"
#include "common.h"
#include "utils.h"

#define DEFAULT_NRPE_COMMAND "_NRPE_CHECK"	/* check version of NRPE daemon */

u_short server_port = DEFAULT_SERVER_PORT;
char *server_name = NULL;
char *bind_address = NULL;
struct sockaddr_storage hostaddr;
int address_family = AF_UNSPEC;
char *command_name = NULL;
int socket_timeout = DEFAULT_SOCKET_TIMEOUT;
int timeout_return_code = STATE_CRITICAL;
int sd;

char rem_host[MAX_HOST_ADDRESS_LENGTH];
char query[MAX_INPUT_BUFFER] = "";

int show_help = FALSE;
int show_license = FALSE;
int show_version = FALSE;
int packet_ver = NRPE_PACKET_VERSION_3;

#ifdef HAVE_SSL
# ifdef __sun
SSL_METHOD *meth;
# else
const SSL_METHOD *meth;
# endif
SSL_CTX *ctx;
SSL *ssl;
int use_ssl = TRUE;
int ssl_opts = SSL_OP_ALL;
#else
int use_ssl = FALSE;
#endif

/* SSL/TLS parameters */
typedef enum _SSL_VER {
	SSLv2 = 1, SSLv2_plus, SSLv3, SSLv3_plus, TLSv1,
	TLSv1_plus, TLSv1_1, TLSv1_1_plus, TLSv1_2, TLSv1_2_plus
} SslVer;

typedef enum _CLNT_CERTS { Ask_For_Cert = 1, Require_Cert = 2 } ClntCerts;

typedef enum _SSL_LOGGING {
	SSL_NoLogging = 0, SSL_LogStartup = 1, SSL_LogIpAddr = 2,
	SSL_LogVersion = 4, SSL_LogCipher = 8, SSL_LogIfClientCert = 16,
	SSL_LogCertDetails = 32
} SslLogging;

struct _SSL_PARMS {
	char *cert_file;
	char *cacert_file;
	char *privatekey_file;
	char cipher_list[MAX_FILENAME_LENGTH];
	SslVer ssl_min_ver;
	int allowDH;
	ClntCerts client_certs;
	SslLogging log_opts;
} sslprm = {
NULL, NULL, NULL, "ALL:!MD5:@STRENGTH", TLSv1_plus, TRUE, 0, SSL_NoLogging};

int process_arguments(int, char **);
void usage(int result);
void setup_ssl();
void set_sig_hadlers();
int connect_to_remote();
int send_request();
int read_response();
int read_packet(int sock, void *ssl_ptr, v2_packet * v2_pkt, v3_packet ** v3_pkt);
#ifdef HAVE_SSL
static int verify_callback(int ok, X509_STORE_CTX * ctx);
#endif
void alarm_handler(int);
int graceful_close(int, int);

int main(int argc, char **argv)
{
	int16_t result;

	result = process_arguments(argc, argv);

	if (result != OK || show_help == TRUE || show_license == TRUE || show_version == TRUE)
		usage(result);			/* usage() will call exit() */

	generate_crc32_table();		/* generate the CRC 32 table */
	setup_ssl();				/* Do all the SSL/TLS set up */
	set_sig_hadlers();			/* initialize alarm signal handling */
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
		syslog(LOG_NOTICE, "Remote %s does not support Version 3 Packets", rem_host);
		packet_ver = NRPE_PACKET_VERSION_2;

		/* Rerun the setup */
		setup_ssl();
		set_sig_hadlers();
		result = connect_to_remote();	/* Connect */
		if (result != STATE_OK) {
			alarm(0);
			return result;
		}

		result = send_request();	/* Send the request */
		if (result != STATE_OK)
			return result;

		result = read_response();	/* Get the response */
	}

	if (result != -1)
		syslog(LOG_NOTICE, "Remote %s accepted a Version %d Packet", rem_host, packet_ver);

	return result;
}

/* process command line arguments */
int process_arguments(int argc, char **argv)
{
	char optchars[MAX_INPUT_BUFFER];
	int argindex = 0;
	int c = 1;
	int i = 1;

#ifdef HAVE_GETOPT_LONG
	int option_index = 0;
	static struct option long_options[] = {
		{"host", required_argument, 0, 'H'},
		{"bind", required_argument, 0, 'b'},
		{"command", required_argument, 0, 'c'},
		{"args", required_argument, 0, 'a'},
		{"no-ssl", no_argument, 0, 'n'},
		{"unknown-timeout", no_argument, 0, 'u'},
		{"v2-packets-only", no_argument, 0, '2'},
		{"ipv4", no_argument, 0, '4'},
		{"ipv6", no_argument, 0, '6'},
		{"no-adh", no_argument, 0, 'd'},
		{"use-adh", optional_argument, 0, 'd'},
		{"ssl-version", required_argument, 0, 'S'},
		{"cipher-list", required_argument, 0, 'L'},
		{"client-cert", required_argument, 0, 'C'},
		{"key-file", required_argument, 0, 'K'},
		{"ca-cert-file", required_argument, 0, 'A'},
		{"ssl-logging", required_argument, 0, 's'},
		{"timeout", required_argument, 0, 't'},
		{"port", required_argument, 0, 'p'},
		{"help", no_argument, 0, 'h'},
		{"license", no_argument, 0, 'l'},
		{0, 0, 0, 0}
	};
#endif

	/* no options were supplied */
	if (argc < 2)
		return ERROR;

	snprintf(optchars, MAX_INPUT_BUFFER, "H:b:c:a:t:p:S:L:C:K:A:d::s:46hlnuV");

	while (1) {
#ifdef HAVE_GETOPT_LONG
		c = getopt_long(argc, argv, optchars, long_options, &option_index);
#else
		c = getopt(argc, argv, optchars);
#endif
		if (c == -1 || c == EOF || argindex > 0)
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

		case 'V':
			show_version = TRUE;
			break;

		case 'l':
			show_license = TRUE;
			break;

		case 't':
			socket_timeout = atoi(optarg);
			if (socket_timeout <= 0)
				return ERROR;
			break;

		case 'p':
			server_port = atoi(optarg);
			if (server_port <= 0)
				return ERROR;
			break;

		case 'H':
			server_name = strdup(optarg);
			break;

		case 'c':
			command_name = strdup(optarg);
			break;

		case 'a':
			argindex = optind;
			break;

		case 'n':
			use_ssl = FALSE;
			break;

		case 'u':
			timeout_return_code = STATE_UNKNOWN;
			break;

		case '2':
			packet_ver = NRPE_PACKET_VERSION_2;
			break;

		case '4':
			address_family = AF_INET;
			break;

		case '6':
			address_family = AF_INET6;
			break;

		case 'd':
			if (optarg)
				sslprm.allowDH = atoi(optarg);
			else
				sslprm.allowDH = 0;
			if (sslprm.allowDH < 0 || sslprm.allowDH > 2)
				return ERROR;
			break;

		case 'A':
			sslprm.cacert_file = strdup(optarg);
			break;

		case 'C':
			sslprm.cert_file = strdup(optarg);
			break;

		case 'K':
			sslprm.privatekey_file = strdup(optarg);
			break;

		case 'S':
			if (!strcmp(optarg, "SSLv2"))
				sslprm.ssl_min_ver = SSLv2;
			else if (!strcmp(optarg, "SSLv2+"))
				sslprm.ssl_min_ver = SSLv2_plus;
			else if (!strcmp(optarg, "SSLv3"))
				sslprm.ssl_min_ver = SSLv3;
			else if (!strcmp(optarg, "SSLv3+"))
				sslprm.ssl_min_ver = SSLv3_plus;
			else if (!strcmp(optarg, "TLSv1"))
				sslprm.ssl_min_ver = TLSv1;
			else if (!strcmp(optarg, "TLSv1+"))
				sslprm.ssl_min_ver = TLSv1_plus;
			else if (!strcmp(optarg, "TLSv1.1"))
				sslprm.ssl_min_ver = TLSv1_1;
			else if (!strcmp(optarg, "TLSv1.1+"))
				sslprm.ssl_min_ver = TLSv1_1_plus;
			else if (!strcmp(optarg, "TLSv1.2"))
				sslprm.ssl_min_ver = TLSv1_2;
			else if (!strcmp(optarg, "TLSv1.2+"))
				sslprm.ssl_min_ver = TLSv1_2_plus;
			else
				return ERROR;
			break;

		case 'L':
			strncpy(sslprm.cipher_list, optarg, sizeof(sslprm.cipher_list) - 1);
			sslprm.cipher_list[sizeof(sslprm.cipher_list) - 1] = '\0';
			break;

		case 's':
			sslprm.log_opts = strtoul(optarg, NULL, 0);
			break;

		default:
			return ERROR;
			break;
		}
	}

	/* determine (base) command query */
	snprintf(query, sizeof(query), "%s",
			 (command_name == NULL) ? DEFAULT_NRPE_COMMAND : command_name);
	query[sizeof(query) - 1] = '\x0';

	/* get the command args */
	if (argindex > 0) {

		for (c = argindex - 1; c < argc; c++) {

			i = sizeof(query) - strlen(query) - 2;
			if (i <= 0)
				break;

			strcat(query, "!");
			strncat(query, argv[c], i);
			query[sizeof(query) - 1] = '\x0';
		}
	}

	/* make sure required args were supplied */
	if (server_name == NULL && show_help == FALSE && show_version == FALSE
		&& show_license == FALSE)
		return ERROR;

	return OK;
}

void usage(int result)
{
	if (result != OK)
		printf("Incorrect command line arguments supplied\n");
	printf("\n");
	printf("NRPE Plugin for Nagios\n");
	printf("Copyright (c) 1999-2008 Ethan Galstad (nagios@nagios.org)\n");
	printf("Version: %s\n", PROGRAM_VERSION);
	printf("Last Modified: %s\n", MODIFICATION_DATE);
	printf("License: GPL v2 with exemptions (-l for more info)\n");
#ifdef HAVE_SSL
	printf("SSL/TLS Available: OpenSSL 0.9.6 or higher required\n");
#endif
	printf("\n");

	if (result != OK || show_help == TRUE) {
		printf("Usage: check_nrpe -H <host> [-2] [-4] [-6] [-n] [-u] [-V] [-l] [-d <num>]\n"
			   "       [-S <ssl version>  [-L <cipherlist>] [-C <clientcert>]\n"
			   "       [-K <key>] [-A <ca-certificate>] [-s <logopts>] [-b <bindaddr>]\n"
			   "       [-p <port>] [-t <timeout>] [-c <command>] [-a <arglist...>]\n");
		printf("\n");
		printf("Options:\n");
		printf(" <host>       = The address of the host running the NRPE daemon\n");
		printf(" -2           = Only use Version 2 packets, not Version 3\n");
		printf(" -4           = bind to ipv4 only\n");
		printf(" -6           = bind to ipv6 only\n");
		printf(" -n           = Do no use SSL\n");
		printf
			(" -u           = Make socket timeouts return UNKNOWN state instead of CRITICAL\n");
		printf(" -V           = Show version\n");
		printf(" -l           = Show license\n");
		printf(" -d           = Don't use Anonymous Diffie Hellman\n");
		printf(" -<num>       = Anonymous Diffie Hellman use:\n");
		printf("                0 = Don't use Anonymous Diffie Hellman\n");
		printf("                    (This will be the default in a future release.)\n");
		printf("                1 = Allow Anonymous Diffie Hellman\n");
		printf("                2 = Force Anonymous Diffie Hellman\n");
		printf(" <bindaddr>   = bind to local address\n");
		printf
			(" <ssl ver>    = The SSL/TLS version to use. Can be any one of: SSLv2 (only),\n");
		printf("                SSLv2+ (or above), SSLv3 (only), SSLv3+ (or above),\n");
		printf("                TLSv1 (only), TLSv1+ (or above DEFAULT), TLSv1.1 (only),\n");
		printf("                TLSv1.1+ (or above), TLSv1.2 (only), TLSv1.2+ (or above)\n");
		printf(" <cipherlist> = The list of SSL ciphers to use (currently defaults\n");
		printf
			("                to \"ALL:!MD5:@STRENGTH\". WILL change in a future release.)\n");
		printf(" <clientcert> = The client certificate to use for PKI\n");
		printf(" <key>        = The private key to use with the client certificate\n");
		printf(" <ca-cert>    = The CA certificate to use for PKI\n");
		printf(" <logopts>    = SSL Logging Options\n");
		printf(" [port]       = The port on which the daemon is running (default=%d)\n",
			   DEFAULT_SERVER_PORT);
		printf(" [timeout]    = Number of seconds before connection times out (default=%d)\n",
			   DEFAULT_SOCKET_TIMEOUT);
		printf(" [command]    = The name of the command that the remote daemon should run\n");
		printf(" [arglist]    = Optional arguments that should be passed to the command,\n");
		printf("                separated by a space.  If provided, this must be the last\n");
		printf("                option supplied on the command line.\n");
		printf("\n");
		printf("Note:\n");
		printf
			("This plugin requires that you have the NRPE daemon running on the remote host.\n");
		printf
			("You must also have configured the daemon to associate a specific plugin command\n");
		printf("with the [command] option you are specifying here.  Upon receipt of the\n");
		printf
			("[command] argument, the NRPE daemon will run the appropriate plugin command and\n");
		printf
			("send the plugin output and return code back to *this* plugin.  This allows you\n");
		printf
			("to execute plugins on remote hosts and 'fake' the results to make Nagios think\n");
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
	int vrfy;

	if (sslprm.log_opts & SSL_LogStartup) {
		char *val;

		syslog(LOG_INFO, "SSL Certificate File: %s",
			   sslprm.cert_file ? sslprm.cert_file : "None");
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
		syslog(LOG_INFO, "SSL Log Options: 0x%02x", sslprm.log_opts);
		switch (sslprm.ssl_min_ver) {
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
		syslog(LOG_INFO, "SSL Version: %s", val);
	}

	/* initialize SSL */
	if (use_ssl == TRUE) {
		SSL_load_error_strings();
		SSL_library_init();
		meth = SSLv23_client_method();

# ifndef OPENSSL_NO_SSL2
		if (sslprm.ssl_min_ver == SSLv2)
			meth = SSLv2_client_method();
# endif
# ifndef OPENSSL_NO_SSL3
		if (sslprm.ssl_min_ver == SSLv3)
			meth = SSLv3_client_method();
# endif
		if (sslprm.ssl_min_ver == TLSv1)
			meth = TLSv1_client_method();
		if (sslprm.ssl_min_ver == TLSv1_1)
			meth = TLSv1_1_client_method();
		if (sslprm.ssl_min_ver == TLSv1_2)
			meth = TLSv1_2_client_method();

		if ((ctx = SSL_CTX_new(meth)) == NULL) {
			printf("CHECK_NRPE: Error - could not create SSL context.\n");
			exit(STATE_CRITICAL);
		}

		if (sslprm.ssl_min_ver >= SSLv3) {
			ssl_opts |= SSL_OP_NO_SSLv2;
			if (sslprm.ssl_min_ver >= TLSv1)
				ssl_opts |= SSL_OP_NO_SSLv3;
		}
		SSL_CTX_set_options(ctx, ssl_opts);

		if (sslprm.cert_file != NULL && sslprm.privatekey_file != NULL) {
			if (!SSL_CTX_use_certificate_file(ctx, sslprm.cert_file, SSL_FILETYPE_PEM)) {
				SSL_CTX_free(ctx);
				printf("Error: could not use certificate file '%s'.\n", sslprm.cert_file);
				exit(STATE_CRITICAL);
			}
			if (!SSL_CTX_use_PrivateKey_file(ctx, sslprm.privatekey_file, SSL_FILETYPE_PEM)) {
				SSL_CTX_free(ctx);
				printf("Error: could not use private key file '%s'.\n",
					   sslprm.privatekey_file);
				exit(STATE_CRITICAL);
			}
		}

		if (sslprm.cacert_file != NULL) {
			vrfy = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
			SSL_CTX_set_verify(ctx, vrfy, verify_callback);
			if (!SSL_CTX_load_verify_locations(ctx, sslprm.cacert_file, NULL)) {
				SSL_CTX_free(ctx);
				printf("Error: could not use CA certificate '%s'.\n", sslprm.cacert_file);
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
		}

		if (SSL_CTX_set_cipher_list(ctx, sslprm.cipher_list) == 0) {
			SSL_CTX_free(ctx);
			printf("Error: Could not set SSL/TLS cipher list: %s", sslprm.cipher_list);
			exit(STATE_CRITICAL);
		}
	}
#endif
}

void set_sig_hadlers()
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
	int result, rc;

	/* try to connect to the host at the given port number */
	if ((sd =
		 my_connect(server_name, &hostaddr, server_port, address_family, bind_address)) < 0)
		exit(STATE_CRITICAL);

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
		syslog(LOG_DEBUG, "Connected to %s", rem_host);

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
		if (sslprm.log_opts & (SSL_LogCertDetails | SSL_LogIfClientCert)) {
			int x, nerrs = 0;
			rc = 0;
			while ((x = ERR_get_error_line_data(NULL, NULL, NULL, NULL)) != 0) {
				syslog(LOG_ERR, "Error: Could not complete SSL handshake with %s: %s",
					   rem_host, ERR_reason_error_string(x));
				++nerrs;
			}
			if (nerrs == 0)
				syslog(LOG_ERR, "Error: Could not complete SSL handshake with %s: %d",
					   rem_host, SSL_get_error(ssl, rc));

		} else
			syslog(LOG_ERR, "Error: Could not complete SSL handshake with %s: %d",
				   rem_host, SSL_get_error(ssl, rc));

		printf("CHECK_NRPE: Error - Could not complete SSL handshake with %s: %d\n",
			   rem_host, SSL_get_error(ssl, rc));

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
			syslog(LOG_NOTICE, "Remote %s - SSL Version: %s", rem_host, SSL_get_version(ssl));

		if (sslprm.log_opts & SSL_LogCipher) {
			const SSL_CIPHER *c = SSL_get_current_cipher(ssl);
			syslog(LOG_NOTICE, "Remote %s - %s, Cipher is %s", rem_host,
				   SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c));
		}

		if ((sslprm.log_opts & SSL_LogIfClientCert) || (sslprm.log_opts & SSL_LogCertDetails)) {
			char peer_cn[256], buffer[2048];
			X509 *peer = SSL_get_peer_certificate(ssl);

			if (peer) {
				if (sslprm.log_opts & SSL_LogIfClientCert)
					syslog(LOG_NOTICE, "SSL %s has %s certificate",
						   rem_host, peer->valid ? "a valid" : "an invalid");
				if (sslprm.log_opts & SSL_LogCertDetails) {
					syslog(LOG_NOTICE, "SSL %s Cert Name: %s", rem_host, peer->name);
					X509_NAME_oneline(X509_get_issuer_name(peer), buffer, sizeof(buffer));
					syslog(LOG_NOTICE, "SSL %s Cert Issuer: %s", rem_host, buffer);
				}

			} else
				syslog(LOG_NOTICE, "SSL Did not get certificate from %s", rem_host);
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
	v2_packet send_packet;
	v3_packet *v3_send_packet = NULL;
	u_int32_t calculated_crc32;
	int rc, bytes_to_send, pkt_size;
	char *send_pkt;

	if (packet_ver == NRPE_PACKET_VERSION_2) {
		pkt_size = sizeof(v2_packet);
		send_pkt = (char *)&send_packet;

		/* clear the response packet buffer */
		memset(&send_packet, 0, sizeof(send_packet));
		/* fill the packet with semi-random data */
		randomize_buffer((char *)&send_packet, sizeof(send_packet));

		/* initialize response packet data */
		send_packet.packet_version = htons(packet_ver);
		send_packet.packet_type = htons(QUERY_PACKET);
		strncpy(&send_packet.buffer[0], query, MAX_PACKETBUFFER_LENGTH);
		send_packet.buffer[MAX_PACKETBUFFER_LENGTH - 1] = '\x0';

		/* calculate the crc 32 value of the packet */
		send_packet.crc32_value = 0;
		calculated_crc32 = calculate_crc32((char *)&send_packet, sizeof(send_packet));
		send_packet.crc32_value = htonl(calculated_crc32);

	} else {

		pkt_size = (sizeof(v3_packet) - 1) + strlen(query) + 1;
		v3_send_packet = calloc(1, pkt_size);
		send_pkt = (char *)v3_send_packet;
		/* initialize response packet data */
		v3_send_packet->packet_version = htons(packet_ver);
		v3_send_packet->packet_type = htons(QUERY_PACKET);
		v3_send_packet->alignment = 0;
		v3_send_packet->buffer_length = htonl(strlen(query) + 1);
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

	if (rc == -1) {
		printf("CHECK_NRPE: Error sending query to host.\n");
		close(sd);
		return STATE_UNKNOWN;
	}

	return STATE_OK;
}

int read_response()
{
	v2_packet receive_packet;
	v3_packet *v3_receive_packet = NULL;
	u_int32_t packet_crc32;
	u_int32_t calculated_crc32;
	int32_t pkt_size;
	int rc, result;

	alarm(0);
	set_sig_hadlers();

#ifdef HAVE_SSL
	rc = read_packet(sd, ssl, &receive_packet, &v3_receive_packet);
#else
	rc = read_packet(sd, NULL, &receive_packet, &v3_receive_packet);
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
			free(v3_receive_packet);
			return -1;
		}
		return STATE_UNKNOWN;

	} else if (rc == 0) {

		/* server disconnected */
		printf
			("CHECK_NRPE: Received 0 bytes from daemon.  Check the remote server logs for error messages.\n");
		if (packet_ver == NRPE_PACKET_VERSION_3)
			free(v3_receive_packet);
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
		packet_crc32 = ntohl(receive_packet.crc32_value);
		receive_packet.crc32_value = 0L;
		calculated_crc32 = calculate_crc32((char *)&receive_packet, sizeof(receive_packet));
	}

	if (packet_crc32 != calculated_crc32) {
		printf("CHECK_NRPE: Response packet had invalid CRC32.\n");
		close(sd);
		if (packet_ver == NRPE_PACKET_VERSION_3)
			free(v3_receive_packet);
		return STATE_UNKNOWN;
	}

	/* get the return code from the remote plugin */
	/* and print the output returned by the daemon */
	if (packet_ver == NRPE_PACKET_VERSION_3) {
		result = ntohs(v3_receive_packet->result_code);
		if (v3_receive_packet->buffer_length == 0)
			printf("CHECK_NRPE: No output returned from daemon.\n");
		else
			printf("%s\n", v3_receive_packet->buffer);
	} else {
		result = ntohs(receive_packet.result_code);
		receive_packet.buffer[MAX_PACKETBUFFER_LENGTH - 1] = '\x0';
		if (!strcmp(receive_packet.buffer, ""))
			printf("CHECK_NRPE: No output returned from daemon.\n");
		else
			printf("%s\n", receive_packet.buffer);
	}

	if (packet_ver == NRPE_PACKET_VERSION_3)
		free(v3_receive_packet);

	return result;
}

int read_packet(int sock, void *ssl_ptr, v2_packet * v2_pkt, v3_packet ** v3_pkt)
{
	int32_t common_size, tot_bytes, bytes_to_recv, buffer_size, bytes_read = 0;
	int rc;
	char *buff_ptr;

	/* Read only the part that's common between versions 2 & 3 */
	common_size = tot_bytes = bytes_to_recv = (char *)&v2_pkt->buffer - (char *)v2_pkt;

	if (use_ssl == FALSE) {
		rc = recvall(sock, (char *)v2_pkt, &tot_bytes, socket_timeout);

		if (rc <= 0 || rc != bytes_to_recv) {
			if (rc < bytes_to_recv) {
				if (packet_ver != NRPE_PACKET_VERSION_3)
					printf
						("CHECK_NRPE: Receive header underflow - only %d bytes received (%ld expected).\n",
						 rc, sizeof(bytes_to_recv));
			}
			return -1;
		}

		packet_ver = ntohs(v2_pkt->packet_version);
		if (packet_ver != NRPE_PACKET_VERSION_2 && packet_ver != NRPE_PACKET_VERSION_3) {
			printf("CHECK_NRPE: Invalid packet version received from server.\n");
			return -1;
		}

		if (ntohs(v2_pkt->packet_type) != RESPONSE_PACKET) {
			printf("CHECK_NRPE: Invalid packet type received from server.\n");
			return -1;
		}

		if (packet_ver == NRPE_PACKET_VERSION_2) {
			buffer_size = sizeof(v2_packet) - common_size;
			buff_ptr = (char *)v2_pkt + common_size;
		} else {
			int32_t pkt_size = sizeof(v3_packet) - 1;

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
			if (rc < buffer_size)
				printf
					("CHECK_NRPE: Receive underflow - only %d bytes received (%ld expected).\n",
					 rc, sizeof(buffer_size));
			return -1;
		} else
			tot_bytes += rc;
	}
#ifdef HAVE_SSL
	else {
		SSL *ssl = (SSL *) ssl_ptr;
		int32_t pkt_size;

		while (((rc = SSL_read(ssl, v2_pkt, bytes_to_recv)) <= 0)
			   && (SSL_get_error(ssl, rc) == SSL_ERROR_WANT_READ)) {
		}

		if (rc <= 0 || rc != bytes_to_recv) {
			if (rc < bytes_to_recv) {
				if (packet_ver != NRPE_PACKET_VERSION_3)
					printf
						("CHECK_NRPE: Receive header underflow - only %d bytes received (%ld expected).\n",
						 rc, sizeof(bytes_to_recv));
			}
			return -1;
		}

		packet_ver = ntohs(v2_pkt->packet_version);
		if (packet_ver != NRPE_PACKET_VERSION_2 && packet_ver != NRPE_PACKET_VERSION_3) {
			printf("CHECK_NRPE: Invalid packet version received from server.\n");
			return -1;
		}

		if (ntohs(v2_pkt->packet_type) != RESPONSE_PACKET) {
			printf("CHECK_NRPE: Invalid packet type received from server.\n");
			return -1;
		}

		if (packet_ver == NRPE_PACKET_VERSION_2) {
			buffer_size = sizeof(v2_packet) - common_size;
			buff_ptr = (char *)v2_pkt + common_size;
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
				syslog(LOG_ERR, "Error: Could not allocate memory for packet");
				return -1;
			}

			memcpy(*v3_pkt, v2_pkt, common_size);
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

		if (rc < 0 || bytes_read != buffer_size) {
			if (packet_ver == NRPE_PACKET_VERSION_3) {
				free(*v3_pkt);
				*v3_pkt = NULL;
			}
			if (bytes_read != buffer_size) {
				if (packet_ver == NRPE_PACKET_VERSION_3)
					printf("CHECK_NRPE: Receive buffer size - %ld bytes received "
						   "(%ld expected).\n", bytes_read, sizeof(buffer_size));
				else
					printf("CHECK_NRPE: Receive underflow - only %ld bytes received "
						   "(%ld expected).\n", bytes_read, sizeof(buffer_size));
			}
			return -1;
		} else
			tot_bytes += rc;
	}
#endif

	return tot_bytes;
}

int verify_callback(int preverify_ok, X509_STORE_CTX * ctx)
{
	char name[256], issuer[256];
	X509 *err_cert;
	int err;
	SSL *ssl;

	if (preverify_ok || (sslprm.log_opts & SSL_LogCertDetails == 0))
		return preverify_ok;

	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);

	/* Get the pointer to the SSL of the current connection */
	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

	X509_NAME_oneline(X509_get_subject_name(err_cert), name, 256);
	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), issuer, 256);

	if (!preverify_ok && sslprm.client_certs >= Ask_For_Cert
		&& (sslprm.log_opts & SSL_LogCertDetails)) {
		syslog(LOG_ERR, "SSL Client has an invalid certificate: %s (issuer=%s) err=%d:%s",
			   name, issuer, err, X509_verify_cert_error_string(err));
	}

	return preverify_ok;
}

void alarm_handler(int sig)
{
	const char msg[] = "CHECK_NRPE: Socket timeout";
	write(STDOUT_FILENO, msg, sizeof(msg) - 1);
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
