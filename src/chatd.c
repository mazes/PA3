/* A TCP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
        const struct sockaddr_in *_addr1 = addr1;
        const struct sockaddr_in *_addr2 = addr2;

        /* If either of the pointers is NULL or the addresses
           belong to different families, we abort. */
        g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
                 (_addr1->sin_family != _addr2->sin_family));

        if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
                return -1;
        } else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
                return 1;
        } else if (_addr1->sin_port < _addr2->sin_port) {
                return -1;
        } else if (_addr1->sin_port > _addr2->sin_port) {
                return 1;
        }
        return 0;
}

void LoadServerCertificates(SSL_CTX* ssl_ctx, char* cert, char* key){
  if(!SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM)){
     perror("SSL_CTX_use_certificate_file()");
     exit(-1);
  }
  if(!SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM)){
     perror("SSL_CTX_use_PrivateKey_file()");
     exit(-1);
  }
  if(!SSL_CTX_check_private_key(ssl_ctx)){
    perror("private key no match");
    exit(-1);
  }
}

int getSocket(int port){
  /* Create and bind a TCP socket */
  fd = socket(AF_INET, SOCK_STREAM, 0);
  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  /* Network functions need arguments in network byte order instead of
     host byte order. The macros htonl, htons convert the values, */
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_port = htons(port);
  bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));
  /* Before we can accept messages, we have to listen to the port. We allow one
   * 1 connection to queue for simplicity.
   */
  printf("listening... ");
  if(listen(fd, 5) != 0){
    perror("listen()");
  }

	return fd;
}

void serveData(SSL* ssl){
  char message[512];
  char reply[512];
  int read, fd, err;
  const char* greeting "Welcome!";

  err = SSL_accept(ssl);
  CHK_SSL(err);

  ShowCerts(ssl);

  read = SSL_read(ssl, message, sizeof(message));
  if(read > 0){
      message[read] = 0;
      printf("Client msg: %s\n", message);
      err = sprintf(reply, greeting);
      if(err < 0){
        printf("sprintf ret negative");
      }
      SSL_write(ssl, reply, strlen(reply));
  }
  else{
      SSL_CHK(read);
  }
  fd = SSL_get_fd(ssl);
  SSL_free(ssl);
  close(fd);
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

int main(int argc, char **argv)
{
        int sockfd;
        int accSocket;
        struct sockaddr_in server, client;
        char message[512];

        /* Initialize OpenSSL */
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_server_method());
        LoadServerCertificates(ssl_ctx, "../data/server.crt", "../data/server.key");

    sockfd = getSocket(atoi(argv[1]));

        for (;;) {
          SSL *server_ssl;
          fd_set rfds;
          struct timeval tv;
        //  int retval;

          /* Check whether there is data on the socket fd. */
          FD_ZERO(&rfds);
          FD_SET(sockfd, &rfds);

          /* Wait for five seconds. */
          tv.tv_sec = 5;
          tv.tv_usec = 0;
        /*  printf("Before select()\n");
          retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);
          */
                  /* Data is available, receive it. */
                  assert(FD_ISSET(sockfd, &rfds));
                  /* Copy to len, since recvfrom may change it. */
                  socklen_t len = (socklen_t) sizeof(client);
                  /* For TCP connectios, we first have to accept. */
                  if(accSocket = accept(sockfd, (struct sockaddr*)&client, &len) < 0){
                    perror("accept()");
                    exit(-1);
                  }
                    printf ("Connection from %lx, port %x\n",
                      inet_ntoa(client.sin_addr), ntohs(client.sin_port));

                  server_ssl = SSL_new(ssl_ctx);
                  SSL_set_fd(server_ssl, accSocket);
                  printf("Before Servlet()");
                  serveData(server_ssl);
        }
        printf("Before close()\n");
        close(sockfd);
        SSL_CTX_free(ssl_ctx);
}
