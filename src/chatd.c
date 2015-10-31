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
  /* the address of a connection. */
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

static SSL *server_ssl;

int main(int argc, char **argv)
{
        int sockfd, accSocket, err;
        struct sockaddr_in server, client;
        char message[512];

        /* Initialize OpenSSL */
        SSL_library_init();
        SSL_load_error_strings();
        SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_client_method());

        if(SSL_CTX_use_certificate_file(ssl_ctx,"../data/server.crt", SSL_FILETYPE_PEM) <= 0){
           perror("SSL_CTX_use_certificate_file()");
           exit(-1);
        }
        if(SSL_CTX_use_PrivateKey_file(ssl_ctx,"../data/server.key", SSL_FILETYPE_PEM) <= 0){
           perror("SSL_CTX_use_PrivateKey_file()");
           exit(-1);
        }
        if(!SSL_CTX_check_private_key(ssl_ctx)){
          perror("private key no match");
          exit(-1);
        }
        if (SSL_CTX_load_verify_locations(ssl_ctx, NULL, "../data/server.crt") <= 0){
          perror("SSL_CTX_load_verify_locations()");
          exit(-1);
        }
        else{
          SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
          SSL_CTX_set_verify_depth(ssl_ctx, 1);
        }

        /* Create and bind a TCP socket */
        sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		CHK_ERR(sockfd, "socket");
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        /* Network functions need arguments in network byte order instead of
           host byte order. The macros htonl, htons convert the values, */
        server.sin_addr.s_addr = htonl(INADDR_ANY);
        server.sin_port = htons(atoi(argv[1]));
        err = bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));
		CHK_ERR(err, "bind");
	/* Before we can accept messages, we have to listen to the port. We allow one
	 * 1 connection to queue for simplicity.
	 */
	err = listen(sockfd, 1);
	CHK_ERR(err, "listen");

	socklen_t clientLength = (socklen_t) sizeof(client);
	//int clientLength = sizeof(client);
  	accSocket = accept(sockfd, (struct sockaddr*)&client, &clientLength);
	CHK_ERR(accSocket, "accept");
  
    printf ("Connection from %lx, port %x\n", client.sin_addr.s_addr, client.sin_port);
  
	printf("after accept():\n");

  server_ssl = SSL_new(ssl_ctx);
  SSL_set_fd(server_ssl, accSocket);
  SSL_accept(server_ssl);
      /* Informational output (optional) */
       printf("SSL connection using %s\n", SSL_get_cipher (server_ssl));
        for (;;) {
                fd_set rfds;
                struct timeval tv;
                int retval;

                /* Check whether there is data on the socket fd. */
                FD_ZERO(&rfds);
                FD_SET(sockfd, &rfds);

                /* Wait for five seconds. */
                tv.tv_sec = 5;
                tv.tv_usec = 0;
                retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);

                if (retval == -1) {
                        perror("select()");
                } else if (retval > 0) {
                        /* Data is available, receive it. */
                        assert(FD_ISSET(sockfd, &rfds));

                        /* Copy to len, since recvfrom may change it. */
                        socklen_t len = (socklen_t) sizeof(client);

                        /* For TCP connectios, we first have to accept. */
                        int connfd;
                        connfd = accept(sockfd, (struct sockaddr *) &client,
                                        &len);

                        /* Receive one byte less than declared,
                           because it will be zero-termianted
                           below. */
                        ssize_t n = read(connfd, message, sizeof(message) - 1);

                        /* Send the message back. */
                        write(connfd, message, (size_t) n);

                        /* We should close the connection. */
                        shutdown(connfd, SHUT_RDWR);
                        close(connfd);

                        /* Zero terminate the message, otherwise
                           printf may access memory outside of the
                           string. */
                        message[n] = '\0';
                        /* Print the message to stdout and flush. */
                        fprintf(stdout, "Received:\n%s\n", message);
                        fflush(stdout);
                } else {
                        fprintf(stdout, "No message in five seconds.\n");
                        fflush(stdout);
                }
        }
}
