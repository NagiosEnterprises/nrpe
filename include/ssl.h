/* SSL/TLS parameters */
typedef enum _SSL_VER {
	SSL_Ver_Invalid = 0, SSLv2 = 1, SSLv2_plus, SSLv3, SSLv3_plus,
	TLSv1, TLSv1_plus, TLSv1_1, TLSv1_1_plus, TLSv1_2, TLSv1_2_plus, TLSv1_3, TLSv1_3_plus
} SslVer;

typedef enum _CLNT_CERTS {
	ClntCerts_Unknown = 0, Ask_For_Cert = 1, Require_Cert = 2
} ClntCerts;

typedef enum _SSL_LOGGING {
	SSL_NoLogging = 0, SSL_LogStartup = 1, SSL_LogIpAddr = 2,
	SSL_LogVersion = 4, SSL_LogCipher = 8, SSL_LogIfClientCert = 16,
	SSL_LogCertDetails = 32
} SslLogging;

typedef struct _SSL_PARMS {
	char     *cert_file;
	char     *cacert_file;
	char     *privatekey_file;
	char      cipher_list[MAX_FILENAME_LENGTH];
	SslVer    ssl_proto_ver;
	int       allowDH;
	ClntCerts client_certs;
	SslLogging log_opts;
} SslParms;


#ifdef HAVE_SSL
# if (defined(__sun) && defined(SOLARIS_10)) || defined(_AIX) || defined(__hpux)
extern SSL_METHOD *meth;
# else
extern const SSL_METHOD *meth;
# endif
extern SSL_CTX  *ctx;
extern SslParms sslprm;
#endif

extern int       use_ssl;


void ssl_initialize(void);
void ssl_set_protocol_version(SslVer ssl_proto_ver, unsigned long *ssl_opts);
void ssl_log_startup(int server);
int ssl_load_certificates(void);
int ssl_set_ciphers(void);
int ssl_verify_callback_common(int preverify_ok, X509_STORE_CTX * ctx, int is_invalid);
