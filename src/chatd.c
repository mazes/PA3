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

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
	printf("show certificates()\n");
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
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

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{   char message[512];
    char reply[512];
    int sd,readBytes;
    const char* Welc="Welcome!";
	printf("inside Servlet()\n");
    if ( SSL_accept(ssl) == -1 ){     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    }
    else{
        ShowCerts(ssl);        /* get any certificates */
        readBytes = SSL_read(ssl, message, sizeof(message)); /* get request */
        if ( readBytes > 0 ){
            message[readBytes] = 0;
            printf("Client msg: \"%s\"\n", message);
            sprintf(reply, Welc, message);   /* construct reply */
            SSL_write(ssl, reply, strlen(reply)); /* send reply */
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
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

        if(!SSL_CTX_use_certificate_file(ssl_ctx,"../data/server.crt", SSL_FILETYPE_PEM)){
           perror("SSL_CTX_use_certificate_file()");
           exit(-1);
        }
        if(!SSL_CTX_use_PrivateKey_file(ssl_ctx,"../data/server.key", SSL_FILETYPE_PEM)){
           perror("SSL_CTX_use_PrivateKey_file()");
           exit(-1);
        }
        if(!SSL_CTX_check_private_key(ssl_ctx)){
          perror("private key no match");
          exit(-1);
        }
        if (!SSL_CTX_load_verify_locations(ssl_ctx, NULL, "../data/fd.crt")){
          perror("SSL_CTX_load_verify_locations()");
          exit(-1);
        }
          SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
          SSL_CTX_set_verify_depth(ssl_ctx, 1);

        /* Create and bind a TCP socket */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        /* Network functions need arguments in network byte order instead of
           host byte order. The macros htonl, htons convert the values, */
        server.sin_addr.s_addr = htonl(INADDR_ANY);
        server.sin_port = htons(atoi(argv[1]));
        bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));

	/* Before we can accept messages, we have to listen to the port. We allow one
	 * 1 connection to queue for simplicity.
	 */
   printf("listening... ");
	if(listen(sockfd, 5) != 0){
    perror("listen()");
  }
        for (;;) {
          SSL *server_ssl;
          fd_set rfds;
          struct timeval tv;
          int retval;

          /* Check whether there is data on the socket fd. */
          FD_ZERO(&rfds);
          FD_SET(sockfd, &rfds);

          /* Wait for five seconds. */
          tv.tv_sec = 5;
          tv.tv_usec = 0;
          printf("Before select()\n");
          retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);

          if (retval == -1) {
                  perror("select()\n");
          } else if (retval > 0) {
                  /* Data is available, receive it. */
                  assert(FD_ISSET(sockfd, &rfds));
                  /* Copy to len, since recvfrom may change it. */
                  socklen_t len = (socklen_t) sizeof(client);
                  /* For TCP connectios, we first have to accept. */
                  if(accSocket = accept(sockfd, (struct sockaddr*)&client, &len) < 0){
                    perror("accept()");
                    exit(-1);
                  }
                  else{
                    printf ("Connection from %lx, port %x\n", client.sin_addr.s_addr, client.sin_port);
                  }
                  server_ssl = SSL_new(ssl_ctx);
                  SSL_set_fd(server_ssl, accSocket);
                  printf("Before Servlet");
                  Servlet(server_ssl);

          } else {
                  fprintf(stdout, "No message in five seconds.\n");
                  fflush(stdout);
          }
        }
        printf("Before close()\n");
        close(sockfd);
        SSL_CTX_free(ssl_ctx);
}
