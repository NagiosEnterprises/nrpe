#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include "common.h"
#include "ssl.h"
#include "utils.h"

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



void ssl_initialize(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
	/* initialize SSL */
	SSL_load_error_strings();
	SSL_library_init();
	ENGINE_load_builtin_engines();
	RAND_set_rand_engine(NULL);
 	ENGINE_register_all_complete();
#endif
}

void ssl_set_protocol_version(SslVer ssl_proto_ver, unsigned long *ssl_opts)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000

	SSL_CTX_set_max_proto_version(ctx, 0);

	switch(ssl_proto_ver) {
		case TLSv1_3:
#if OPENSSL_VERSION_NUMBER >= 0x10101000
			SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
#endif
		case TLSv1_3_plus:
#if OPENSSL_VERSION_NUMBER >= 0x10101000
			SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
			break;
#endif

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

		case SSLv2:
		case SSLv2_plus:
			/* SSLv2 support dropped */
			break;
		case SSL_Ver_Invalid:
			/* Should never be seen, silence warning */
			break;
	}

#else		/* OPENSSL_VERSION_NUMBER >= 0x10100000 */

	switch(sslprm.ssl_proto_ver) {
		case SSLv2:
		case SSLv2_plus:
			break;
		case TLSv1_3:
		case TLSv1_3_plus:
#ifdef SSL_OP_NO_TLSv1_2
			*ssl_opts |= SSL_OP_NO_TLSv1_2;
#endif
		case TLSv1_2:
		case TLSv1_2_plus:
#ifdef SSL_OP_NO_TLSv1_1
			*ssl_opts |= SSL_OP_NO_TLSv1_1;
#endif
		case TLSv1_1:
		case TLSv1_1_plus:
			*ssl_opts |= SSL_OP_NO_TLSv1;
		case TLSv1:
		case TLSv1_plus:
			*ssl_opts |= SSL_OP_NO_SSLv3;
		case SSLv3:
		case SSLv3_plus:
			*ssl_opts |= SSL_OP_NO_SSLv2;
			break;
        case SSL_Ver_Invalid:
            /* Should never be seen, silence warning */
            break;
	}
#endif		/* OPENSSL_VERSION_NUMBER >= 0x10100000 */
}

void ssl_log_startup(int server)
{
	char     *vers;

	logit(LOG_INFO, "SSL Certificate File: %s", sslprm.cert_file ? sslprm.cert_file : "None");
	logit(LOG_INFO, "SSL Private Key File: %s", sslprm.privatekey_file ? sslprm.privatekey_file : "None");
	logit(LOG_INFO, "SSL CA Certificate File: %s", sslprm.cacert_file ? sslprm.cacert_file : "None");
	logit(LOG_INFO, "SSL Cipher List: %s", sslprm.cipher_list);
	logit(LOG_INFO, "SSL Allow ADH: %d", sslprm.allowDH);
    if (server)
    {
        logit(LOG_INFO, "SSL Client Certs: %s",
            sslprm.client_certs == 0 ? "Don't Ask" : 
                (sslprm.client_certs == 1 ? "Accept" : "Require"));
    }
	logit(LOG_INFO, "SSL Log Options: 0x%02x", sslprm.log_opts);

	switch (sslprm.ssl_proto_ver) {
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
	case TLSv1_3:
		vers = "TLSv1_3";
		break;
	case TLSv1_3_plus:
		vers = "TLSv1_3 And Above";
		break;
	default:
		vers = "INVALID VALUE!";
		break;
	}
	logit(LOG_INFO, "SSL Version: %s", vers);
}

int ssl_load_certificates(void)
{
    int x;
	char errstr[256] = { "" };

	if (sslprm.cacert_file != NULL) {
		if (!SSL_CTX_load_verify_locations(ctx, sslprm.cacert_file, NULL)) {
			logit(LOG_ERR, "Error: Could not use CA certificate '%s'", sslprm.cacert_file);
			while ((x = ERR_get_error()) != 0) {
				ERR_error_string(x, errstr);
				logit(LOG_ERR, "     : %s\n", errstr);
			}
            return FALSE;
		}
	}

	if (sslprm.cert_file != NULL && sslprm.privatekey_file != NULL) {
		if (!SSL_CTX_use_certificate_chain_file(ctx, sslprm.cert_file)) {
			logit(LOG_ERR, "Error: Could not use certificate '%s'", sslprm.cert_file);
			while ((x = ERR_get_error()) != 0) {
				ERR_error_string(x, errstr);
				logit(LOG_ERR, "     : %s\n", errstr);
			}
            return FALSE;
		}
		if (!SSL_CTX_use_PrivateKey_file(ctx, sslprm.privatekey_file, SSL_FILETYPE_PEM)) {
            logit(LOG_ERR, "Error: Could not use private key file '%s'", sslprm.privatekey_file);
			while ((x = ERR_get_error()) != 0) {
				ERR_error_string(x, errstr);
				logit(LOG_ERR, "     : %s\n", errstr);
			}
            return FALSE;
		}
		if (!SSL_CTX_check_private_key(ctx)) {
            logit(LOG_ERR, "Error: Could not use certificate/private key pair");
			while ((x = ERR_get_error()) != 0) {
				ERR_error_string(x, errstr);
				logit(LOG_ERR, "     : %s\n", errstr);
			}
            return FALSE;
		}
	}

    return TRUE;
}

int ssl_set_ciphers(void)
{
    int x;
    int changed = FALSE;
	char errstr[256] = { "" };

    if (!sslprm.allowDH) {
        x = strlen(sslprm.cipher_list);
        if (x < sizeof(sslprm.cipher_list) - 6) {
            changed = TRUE;
            strncpy(sslprm.cipher_list + x, ":!ADH", sizeof(sslprm.cipher_list) - x);
        }
    } else {
        /* use anonymous DH ciphers */
        if (sslprm.allowDH == 2) {
            changed = TRUE;
#if OPENSSL_VERSION_NUMBER >= 0x10100000
            strncpy(sslprm.cipher_list, "ADH:@SECLEVEL=0", MAX_FILENAME_LENGTH - 1);
#else
            strncpy(sslprm.cipher_list, "ADH", MAX_FILENAME_LENGTH - 1);
#endif
        }
    }

    if (changed && sslprm.log_opts & SSL_LogStartup)
        logit(LOG_INFO, "New SSL Cipher List: %s", sslprm.cipher_list);

    if (SSL_CTX_set_cipher_list(ctx, sslprm.cipher_list) == 0) {
        logit(LOG_ERR, "Error: Could not set SSL/TLS cipher list: %s\n", sslprm.cipher_list);
        while ((x = ERR_get_error()) != 0) {
            ERR_error_string(x, errstr);
            logit(LOG_ERR, "     : %s\n", errstr);
        }
        return FALSE;
    }

    return TRUE;
}

int ssl_verify_callback_common(int preverify_ok, X509_STORE_CTX * ctx, int is_invalid)
{
	char name[256], issuer[256];
	X509 *err_cert;
	int err;

	if (preverify_ok || ((sslprm.log_opts & SSL_LogCertDetails) == 0))
		return preverify_ok;

	if (is_invalid || sslprm.log_opts & SSL_LogCertDetails) {
		err_cert = X509_STORE_CTX_get_current_cert(ctx);
		err = X509_STORE_CTX_get_error(ctx);

		X509_NAME_oneline(X509_get_subject_name(err_cert), name, 256);
		X509_NAME_oneline(X509_get_issuer_name(err_cert), issuer, 256);

		if (is_invalid) {
			logit(LOG_ERR, "SSL Client has an invalid certificate: %s (issuer=%s) err=%d:%s", name, issuer, err, X509_verify_cert_error_string(err));
		} else {
			logit(LOG_INFO, "SSL Client certificate: %s (issuer=%s)", name, issuer);
		}
	}

	return preverify_ok;
}
