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
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/*Error checks for the SSL*/
#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

typedef struct Users{
  char clientIP[17];
  char portNr[6];
  char *username;
  int socket;
}Users;


/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2){
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

/*Load the certificates for all the users*/
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

/*Create a socket to listen for client connections*/
int getSocket(int port){
  int sockfd;
  struct sockaddr_in server;
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_port = htons(port);
  if(bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server)) == -1){
    perror("bind():");
  }
  printf("listening...\n");
  if(listen(sockfd, 5) != 0){
    perror("listen()");
  }

	return sockfd;
}

/*Write to the logged in and out users*/
void writeToFile(struct sockaddr_in client , char *connection){
  FILE* fd;
  fd = fopen("chat.log", "a");

  if(fd == NULL){
      fd = fopen("chat.log", "w+");
      if(fd == NULL){
          printf("error opening file");
      }
  }

  char date[21];
  time_t t;
  struct tm *tmpt;

  t = time(NULL);
  tmpt = localtime(&t);

  if (tmpt == NULL) {
      perror("getting localtime failed");
  }

  strftime(date,21, "%Y-%m-%d %H:%M:%S", tmpt);

	char clientIP[17] ;
	memset(&clientIP, 0, sizeof(clientIP));
	struct sockaddr_in* ip4Add = (struct sockaddr_in*)&client;
	int ipAddr = ip4Add->sin_addr.s_addr;
	inet_ntop( AF_INET, &ipAddr, clientIP, INET_ADDRSTRLEN);
	int portnum = (int) ntohs(client.sin_port);
	char portNr[8];
	sprintf(portNr, "%d", portnum);

  if(fputs(date, fd) < 0)printf("error writing to file");
  fputs(" : ", fd);
  fputs(clientIP, fd);
  fputs(":", fd);
  fputs(portNr, fd);
  fputs(" ", fd);
  fputs(connection, fd);
  fputs("\r\n", fd);
  fclose(fd);
}

/*Print out logged in users*/
void addUsers(int fd, struct sockaddr_in client, Users users){
  memset(&users.clientIP, 0, sizeof(users.clientIP));
  struct sockaddr_in* ip4Add = (struct sockaddr_in*)&client;
  int ipAddr = ip4Add->sin_addr.s_addr;
  inet_ntop( AF_INET, &ipAddr, users.clientIP, INET_ADDRSTRLEN);
  int portnum = (int) ntohs(client.sin_port);
  sprintf(users.portNr, "%d", portnum);
  users.username = NULL;
}

void printUsers(Users users[]){
  for(int i = 0; i < 1000; i++){
    if(strcmp("X", users[i].clientIP, 1 != 0)){
      printf("clientIP: %s\n", users[i].clientIP);
    }
  }
}

void checkMessage(SSL *ssl, char *message, Users users[]){
    if(strncmp("/who", message, 4) == 0){
      printUsers(users);
    }
}

void setUsersNull(Users users[]){
  for(int i = 0; i < 1000; i++){
    users[i].clientIP[0] = 'X';
  }
}
int main(int argc, char **argv){
    int sockfd, err;
    int maxFD;
    int connfd;
    fd_set rfds, master;
    struct timeval tv;
    int retval;
    char message[512];
    char reply[124];
    SSL *server_ssl;
    Users users[1000];
    setUsersNull(users);
    struct sockaddr_in clientArr[1000];
    if(argc < 2){
      perror("only use port as argument");
      exit(-1);
    }
    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_server_method());
    LoadServerCertificates(ssl_ctx, "../data/server.crt", "../data/server.key");
    /*get socket*/
    sockfd = getSocket(atoi(argv[1]));
    /*create new ssl context*/
    server_ssl = SSL_new(ssl_ctx);
    SSL_set_fd(server_ssl, sockfd);


    maxFD = sockfd;
    FD_ZERO(&master);
    FD_ZERO(&rfds);
    FD_SET(sockfd, &master);
    while(1) {
      FD_ZERO(&rfds);
      memcpy(&rfds, &master, sizeof(rfds));
      tv.tv_sec = 5;
      tv.tv_usec = 0;

      retval = select(maxFD + 1, &rfds, NULL, NULL, &tv);
      if(retval < 0){
        perror("select()");
      }
      for(int i = 0; i <= maxFD; i++){
        if(FD_ISSET(i, &rfds)){
          if(i == sockfd){
            struct sockaddr_in client;
            /* Now we have new Connection*/
            /* accept connection from new user */
            socklen_t len = (socklen_t) sizeof(client);
            connfd = accept(sockfd, (struct sockaddr *) &client,
                            &len);
            /*set the socket in fd and ssl*/
            FD_SET(connfd, &master);
            SSL_set_fd(server_ssl, connfd);
            clientArr[connfd] = client;
            /*increase sockets if needed*/
            if(maxFD < connfd){
                printf("maxFD = connfd\n");
                maxFD = connfd;
            }
            printf ("Connection from %s, port %d\n",
              inet_ntoa(client.sin_addr), ntohs(client.sin_port));
            /*write connection to .log*/
				    writeToFile(clientArr[connfd], "connected");

            addUsers(connfd, client, users[connfd]);
            /*accept the ssl connection*/
            if(SSL_accept(server_ssl) < 0){
                perror("SSL_accept()");
            }
            /*send user the welcoming message*/
            err = sprintf(reply, "%s" ,"welcome!");
            err = SSL_write(server_ssl, reply, strlen(reply));
            CHK_SSL(err);
          }
          else{
                if(retval == 0){
                  printf("retval == 0\n");
                }
                //connection exists data to read
                memset(&message, 0, sizeof(message));
                err = SSL_read(server_ssl, message, sizeof(message));
                CHK_SSL(err);
                checkMessage(server_ssl, message, users);
                if(err == 0){
                  /*client has disconnected*/
                  int sock = SSL_get_fd(server_ssl);
                  /*get sockaddr from socket!!*/
                  close(sock);
				          FD_CLR(i, &master);
                  writeToFile(clientArr[i], "disconnected");
                }else{
                    message[err] = '\0';
                    printf("%s\n", message);
                    SSL_write(server_ssl, message, strlen(message));
				        }
          }
        } //FD_ISSET
      }//forloopfd
    }//for()
    printf("Before close()\n");
    close(sockfd);
    SSL_CTX_free(ssl_ctx);
  }
