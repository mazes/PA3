/* A UDP echo server with timeouts.
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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <errno.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

/* This variable is 1 while the client is active and becomes 0 after
   a quit command to terminate the client and to clean up the
   connection. */
static int active = 1;


/* To read a password without echoing it to the console.
 *
 * We assume that stdin is not redirected to a pipe and we won't
 * access tty directly. It does not make much sense for this program
 * to redirect input and output.
 *
 * This function is not safe to termination. If the program
 * crashes during getpasswd or gets terminated, then echoing
 * may remain disabled for the shell (that depends on shell,
 * operating system and C library). To restore echoing,
 * type 'reset' into the sell and press enter.
 */
void getpasswd(const char *prompt, char *passwd, size_t size)
{
	struct termios old_flags, new_flags;

        /* Clear out the buffer content. */
        memset(passwd, 0, size);

        /* Disable echo. */
	tcgetattr(fileno(stdin), &old_flags);
	memcpy(&new_flags, &old_flags, sizeof(old_flags));
	new_flags.c_lflag &= ~ECHO;
	new_flags.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSANOW, &new_flags) != 0) {
		perror("tcsetattr");
		exit(EXIT_FAILURE);
	}

	printf("%s", prompt);
	fgets(passwd, size, stdin);

	/* The result in passwd is '\0' terminated and may contain a final
	 * '\n'. If it exists, we remove it.
	 */
	if (passwd[strlen(passwd) - 1] == '\n') {
		passwd[strlen(passwd) - 1] = '\0';
	}

	/* Restore the terminal */
	if (tcsetattr(fileno(stdin), TCSANOW, &old_flags) != 0) {
		perror("tcsetattr");
		exit(EXIT_FAILURE);
	}
}



/* If someone kills the client, it should still clean up the readline
   library, otherwise the terminal is in a inconsistent state. We set
   active to 0 to get out of the loop below. Also note that the select
   call below may return with -1 and errno set to EINTR. Do not exit
   select with this error. */
void sigint_handler(int signum)
{
        active = 0;

        /* We should not use printf inside of signal handlers, this is not
         * considered safe. We may, however, use write() and fsync(). */
        write(STDOUT_FILENO, "Terminated.\n", 12);
        fsync(STDOUT_FILENO);
}


/* The next two variables are used to access the encrypted stream to
 * the server. The socket file descriptor server_fd is provided for
 * select (if needed), while the encrypted communication should use
 * server_ssl and the SSL API of OpenSSL.
 */
static int server_fd;
static SSL *server_ssl;

/* This variable shall point to the name of the user. The initial value
   is NULL. Set this variable to the username once the user managed to be
   authenticated. */
static char *user;

/* This variable shall point to the name of the chatroom. The initial
   value is NULL (not member of a chat room). Set this variable whenever
   the user changed the chat room successfully. */
static char *chatroom;

/* This prompt is used by the readline library to ask the user for
 * input. It is good style to indicate the name of the user and the
 * chat room he is in as part of the prompt. */
static char *prompt;



/* When a line is entered using the readline library, this function
   gets called to handle the entered line. Implement the code to
   handle the user requests in this function. The client handles the
   server messages in the loop in main(). */
void readline_callback(char *line)
{		printf("readline_callback()\n");
        char buffer[256];

        if (NULL == line) {
                rl_callback_handler_remove();
                active = 0;
                return;
        }
        if (strlen(line) > 0) {
                add_history(line);
        }
        if ((strncmp("/bye", line, 4) == 0) ||
            (strncmp("/quit", line, 5) == 0)) {
                rl_callback_handler_remove();
                active = 0;
								/*send the server 0 bytes to let know
								we have left*/
								SSL_write(server_ssl, "", 0);
                return;
        }
        if (strncmp("/game", line, 5) == 0) {
                /* Skip whitespace */
                int i = 4;
                while (line[i] != '\0' && isspace(line[i])) { i++; }
                if (line[i] == '\0') {
                        write(STDOUT_FILENO, "Usage: /game username\n",
                              29);
                        fsync(STDOUT_FILENO);
                        rl_redisplay();
                        return;
                }
                /* Start game */
                return;
        }
        if (strncmp("/join", line, 5) == 0) {
                int i = 5;
                /* Skip whitespace */
                while (line[i] != '\0' && isspace(line[i])) { i++; }
                if (line[i] == '\0') {
                        write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
                        fsync(STDOUT_FILENO);
                        rl_redisplay();
                        return;
                }
                char *chatroom = strdup(&(line[i]));

                /* Process and send this information to the server. */

                /* Maybe update the prompt. */
                free(prompt);
                prompt = strdup(chatroom); /* What should the new prompt look like? */
				free(chatroom);
		rl_set_prompt(prompt);
                return;
        }
        if (strncmp("/list", line, 5) == 0) {
                /* Query all available chat rooms */
                return;
        }
        if (strncmp("/roll", line, 5) == 0) {
                /* roll dice and declare winner. */
                return;
        }
        if (strncmp("/say", line, 4) == 0) {
                /* Skip whitespace */
                int i = 4;
                while (line[i] != '\0' && isspace(line[i])) { i++; }
                if (line[i] == '\0') {
                        write(STDOUT_FILENO, "Usage: /say username message\n",
                              29);
                        fsync(STDOUT_FILENO);
                        rl_redisplay();
                        return;
                }
                /* Skip whitespace */
                int j = i+1;
                while (line[j] != '\0' && isgraph(line[j])) { j++; }
                if (line[j] == '\0') {
                        write(STDOUT_FILENO, "Usage: /say username message\n",
                              29);
                        fsync(STDOUT_FILENO);
                        rl_redisplay();
                        return;
                }
                char *receiver = strndup(&(line[i]), j - i - 1);
                char *message = strndup(&(line[j]), j - i - 1);

                /* Send private message to receiver. */

                return;
        }
        if (strncmp("/user", line, 5) == 0) {
                int i = 5;
                /* Skip whitespace */
                while (line[i] != '\0' && isspace(line[i])) { i++; }
                if (line[i] == '\0') {
                        write(STDOUT_FILENO, "Usage: /user username\n", 22);
                        fsync(STDOUT_FILENO);
                        rl_redisplay();
                        return;
                }
                char *new_user = strdup(&(line[i]));
                char passwd[48];
                getpasswd("Password: ", passwd, 48);

                /* Process and send this information to the server. */

                /* Maybe update the prompt. */
                free(prompt);
                prompt = NULL; /* What should the new prompt look like? */
		rl_set_prompt(prompt);
                return;
        }
        if (strncmp("/who", line, 4) == 0) {
                /* Query all available users */
								snprintf(buffer, 255, "%s\n", line);
								SSL_write(server_ssl, buffer, strlen(buffer));
                return;
        }
        /* Sent the buffer to the server. */
        snprintf(buffer, 255, "Message: %s\n", line);
				SSL_write(server_ssl, buffer, strlen(buffer));
        write(STDOUT_FILENO, buffer, strlen(buffer));
        fsync(STDOUT_FILENO);
}

/*Returns the socket to connect with server*/
int getSocket(int port){
	int fd;
	struct sockaddr_in server;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if(fd <= 0){
	 	perror("socket()");
	 	exit(-1);
	}
  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(port);

	int err = connect(fd, (struct sockaddr*)&server, sizeof(server));
	CHK_ERR(err, "connect");

	return fd;
}

int main(int argc, char **argv){
	char message[512];
	int err;
	fd_set master;
	fd_set rfds;
	struct timeval timeout;
	/* Initialize OpenSSL */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_client_method());

	/*setup socket to listen to clients*/
	server_fd = getSocket(atoi(argv[2]));

	/* Use the socket for the SSL connection. */
	server_ssl = SSL_new(ssl_ctx);
	SSL_set_fd(server_ssl, server_fd);

	printf("Before SSL_connect()\n");
  /* Set up secure connection to the chatd server. */
	if(SSL_connect(server_ssl) == -1){
		perror("SSL_connect()");
		exit(-1);
	}
	printf("Before SSL_read()\n");

	/*recieve Welcoming message */
	memset(&message, 0, sizeof(message));
	err = SSL_read(server_ssl, message, sizeof(message));
	CHK_SSL(err);
	message[err] = '\0';
	printf("%s\n", message);

	/*Zero and set FD's*/
	FD_ZERO(&master);
	FD_SET(STDIN_FILENO, &master);
	FD_SET(server_fd, &master);

	/* Read characters from the keyboard while waiting for input.
	 */
  prompt = strdup("> ");
  rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
	while (active) {
          FD_ZERO(&rfds);
					memcpy(&rfds, &master, sizeof(rfds));
					timeout.tv_sec = 5;
					timeout.tv_usec = 0;

          int r = select(FD_SETSIZE, &rfds, NULL, NULL, &timeout);
          if (r < 0) {
                  if (errno == EINTR) {
                          /* This should either retry the call or
                             exit the loop, depending on whether we
                             received a SIGTERM. */
                          continue;
                  }
                  /* Not interrupted, maybe nothing we can do? */
                  break;
          }
          if (r == 0) {
                  write(STDOUT_FILENO, "No message?\n", 12);
                  fsync(STDOUT_FILENO);
                  /* Whenever you print out a message, call this
                     to reprint the current input line. */
									rl_callback_read_char();
                  continue;
          }

          if (FD_ISSET(STDIN_FILENO, &rfds)) {
                  rl_callback_read_char();
          }
					if(FD_ISSET(server_fd, &rfds)){
							/* Handle messages from the server here! */
							if (r < 0){
								perror("serverselect < 0");
							}

							else if(r == 0){
								printf("nothing to read from serverselect\n");
							}
							else{
								memset(&message, 0, sizeof(message));
								err = SSL_read(server_ssl, message, sizeof(message));
								if(err == 0){
									FD_CLR(server_fd, &master);
									SSL_free(server_ssl);
									close(server_fd);
									printf("Server crashed!\n");
								}
								CHK_SSL(err);
								message[err] = '\0';
								printf("%s\n", message);
							}
					}
  }
	SSL_free(server_ssl);
	close(server_fd);
	SSL_CTX_free(ssl_ctx);
}
