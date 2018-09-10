/* NAME: Caleb Chau
 * EMAIL: caleb.h.chau@gmail.com
 * ID: 204805602
 */ 

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <signal.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <mcrypt.h>

#define TCGETATTR "tcgetattr"
#define TCSETATTR "tcsetattr"
#define FORK "fork"
#define CREAT "creat"
#define OPEN "open"
#define CLOSE "close"
#define READ "read"
#define WRITE "write"
#define POLL "poll"
#define SOCKET "socket"
#define GET_HOST "host"
#define CONNECT "connect"
#define MCRYPT_OPEN "mcrypt open"
#define MCRYPT_INIT "mcrypt init"
#define MCRYPT_DEINIT "mcrypt deinit"
#define PORT 'p'
#define HOST 'h'
#define LOG 'l'
#define ENCRYPT 'e'
#define CR '\r'
#define LF '\n'
#define CTRL_C '\003'
#define CTRL_D '\004'

/* Arbitrary buffer size */
const size_t BUFFER_SIZE = 1024;
/* Buffer to store read input */
char* buffer;
ssize_t count;
/* Store ret values of syscalls */
int ret;
/* Character mappings */
const char* cr_lf = "\r\n";
const char* lf = "\n";
const char* ctrl_c = "^C";
const char* ctrl_d = "^D";
/* File descriptors for socket connection, log file, and key file */
int sock_fd, log_fd, key_fd;
/* File name for --log and --encrypt option */
char* log_filename = NULL;
char* key_filename = NULL;
/* Detect if --encrypt option is given */
int encrypt;
/* Variables for encryption */
MCRYPT td;
char* key, * IV;
int key_size, IV_size;
/* Use this variable to remember original terminal attributes */
struct termios saved_attributes;

void handle_error(char* operation) {
    int err_no = errno;
    char* err_message = strerror(err_no);
    
    fprintf(stderr, "%s failed: %s\r\n", operation, err_message);
}

int creat_or_open_fd(const char* pathname, int flags, mode_t mode) {
    if ((ret = creat(pathname, mode)) == -1) {
        if ((ret = open(pathname, flags)) == -1) {
            handle_error(OPEN);
            exit(1);
        } else {
            return ret;
        }
    } else {
        return ret;
    }
}

int open_fd(const char* pathname, int flags) {
    if ((ret = open(pathname, flags)) == -1) {
        handle_error(OPEN);
        exit(1);
    } else {
        return ret;
    }
}

void close_fd(int fd) {
    if (close(fd) == -1) {
        handle_error(CLOSE);
        exit(1);
    }
}

ssize_t read_fd(int fd, void* buf, size_t count) {
    if ((ret = read(fd, buf, count)) == -1) {
        handle_error(READ);
        exit(1);
    } else {
        return ret;
    }
}

ssize_t write_fd(int fd, const void* buf, size_t count) {
    if ((ret = write(fd, buf, count)) == -1) {
        handle_error(WRITE);
        exit(1);
    } else {
        return ret;
    }
}

ssize_t write_log_fd(int log_fd, const void* buf, size_t count) {
    if (log_fd > 0) {
        ret = write_fd(log_fd, buf, count);
        return ret;
    } else {
        return 0;
    }
}

void reset_input_mode(void) {
    if (tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes) == -1) {
        handle_error(TCSETATTR);
        exit(1);
    }
}

void set_input_mode(void) {
    struct termios tattr;
    
    /* Make sure stdin is a terminal. */
    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr, "Not a terminal.\r\n");
        exit(1);
    }
    
    /* Save the terminal attributes so we can restore them later. */
    if (tcgetattr(STDIN_FILENO, &saved_attributes) == -1) {
        handle_error(TCGETATTR);
        exit(1);
    }
    
    /* Reset terminal modes when program exits */
    atexit(reset_input_mode);
    
    /* Set the funny terminal modes. */
    if (tcgetattr(STDIN_FILENO, &tattr) == -1) {
        handle_error(TCGETATTR);
        exit(1);
    }
    
    tattr.c_iflag = ISTRIP;	/* only lower 7 bits */
    tattr.c_oflag = 0;		/* no processing	 */
    tattr.c_lflag = 0;		/* no processing	 */
    tattr.c_cc[VMIN] = 1;
    tattr.c_cc[VTIME] = 0;
    
    if (tcsetattr(STDIN_FILENO, TCSANOW, &tattr) == -1) {
        handle_error(TCSETATTR);
        exit(1);
    }
}

void setup_encrypter(void) {
    if (encrypt) {
        int i;

        key_size = 16; /* 128 bits */
        key = calloc(1, key_size);
        read_fd(key_fd, key, key_size); /* Read key from key file */

        if ((td = mcrypt_module_open("twofish", NULL, "cfb", NULL)) == MCRYPT_FAILED) {
            handle_error(MCRYPT_OPEN);
            free(key);
            free(IV);
            exit(1);
        }

        IV_size = mcrypt_enc_get_iv_size(td);

        IV = malloc(IV_size);

        for (i = 0; i < IV_size; i++) {
            IV[i] = 0xA;
        }
    }
}

void encrypt_data(char* message, int length) {
    if (encrypt) {
        if ((td = mcrypt_module_open("twofish", NULL, "cfb", NULL)) == MCRYPT_FAILED) {
            handle_error(MCRYPT_OPEN);
            free(key);
            free(IV);
            exit(1);
        }

        if ((ret = mcrypt_generic_init(td, key, key_size, IV)) < 0) {
            mcrypt_perror(ret);
            handle_error(MCRYPT_INIT);
            free(key);
            free(IV);
            exit(1);
        }

        mcrypt_generic(td, message, length);
    }
}

void decrypt_data(char* message, int length) {
    if (encrypt) {
        if ((td = mcrypt_module_open("twofish", NULL, "cfb", NULL)) == MCRYPT_FAILED) {
            handle_error(MCRYPT_OPEN);
            free(key);
            free(IV);
            exit(1);
        }

        if ((ret = mcrypt_generic_init(td, key, key_size, IV)) < 0) {
            mcrypt_perror(ret);
            handle_error(MCRYPT_INIT);
            free(key);
            free(IV);
            exit(1);
        }

        mdecrypt_generic(td, message, length);
    }
}

void deinit_encrypter(void) {
    if (encrypt) {
        mcrypt_generic_deinit(td);
        mcrypt_module_close(td);
    }
}

void poll_input(void) {
    nfds_t nfds = 2;
    struct pollfd fds[nfds];
    
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN | POLLHUP | POLLERR;
    
    fds[1].fd = sock_fd;
    fds[1].events = POLLIN | POLLHUP | POLLERR;
    
    buffer = (char*) malloc(BUFFER_SIZE * sizeof(char));
    
    while (1) {
        if ((ret = poll(fds, nfds, 0)) == -1) {
            handle_error(POLL);
            exit(1);
        }
        
        if (fds[0].revents & POLLIN) {
            count = read_fd(STDIN_FILENO, buffer, BUFFER_SIZE);
            
            if (log_fd > 0) {
                dprintf(log_fd, "SENT %ld bytes: ", count);
            }
            
            size_t i = 0;

            setup_encrypter();
            
            while (count > 0) {
                switch (buffer[i]) {
                    case CR:
                    case LF:
                        write_fd(STDOUT_FILENO, cr_lf, 2);
                        break;
                    case CTRL_C:
                        write_fd(STDOUT_FILENO, ctrl_c, 2);
                        break;
                    case CTRL_D:
                        write_fd(STDOUT_FILENO, ctrl_d, 2);
                        break;
                    default:
                        write_fd(STDOUT_FILENO, &buffer[i], 1);
                        break;
                }

                encrypt_data(&buffer[i], 1);
                write_fd(sock_fd, &buffer[i], 1);
                write_log_fd(log_fd, &buffer[i], 1);
                
                i++;
                count--;
            }
            
            write_log_fd(log_fd, lf, 1);

            deinit_encrypter();
        }
        
        if (fds[1].revents & POLLIN) {
            count = read_fd(sock_fd, buffer, BUFFER_SIZE);
            
            if (log_fd > 0) {
                dprintf(log_fd, "RECEIVED %ld bytes: ", count);
            }
            
            size_t i = 0;
            
            if (count == 0) {
                exit(0);
            }

            setup_encrypter();
            
            while (count > 0) {
                write_log_fd(log_fd, &buffer[i], 1);

                decrypt_data(&buffer[i], 1);

                switch (buffer[i]) {
                    case CR:
                    case LF:
                        write_fd(STDOUT_FILENO, cr_lf, 2);
                        break;
                    case CTRL_C:
                        write_fd(STDOUT_FILENO, ctrl_c, 2);
                        break;
                    case CTRL_D:
                        write_fd(STDOUT_FILENO, ctrl_d, 2);
                        break;
                    default:
                        write_fd(STDOUT_FILENO, &buffer[i], 1);
                        break;
                }
                
                i++;
                count--;
            }
            
            write_log_fd(log_fd, lf, 1);

            deinit_encrypter();
        }
    }
}

int main(int argc, char* argv[]) {
    struct option arguments[] = {
        { "port", required_argument, NULL, PORT },
        { "log", required_argument, NULL, LOG },
        { "host", required_argument, NULL, HOST },
        { "encrypt", required_argument, NULL, ENCRYPT },
        { 0, 0, 0, 0 }
    };
    
    /* Detect various long options */
    int option, port, host, log_opt;
    option = port = host = log_opt = -1;
    
    /* Store desired port number and host name with default host of localhost */
    char* port_number, * host_name;
    host_name = "localhost";
    
    /* Structs for getaddrinfo() function */
    struct addrinfo hints, * server_info, * p;
    
    /* Allocate memory in buffer to store char */
    buffer = (char*) malloc(BUFFER_SIZE * sizeof(char));

    /* Parse argv array for provided options */
    while ((option = getopt_long(argc, argv, "", arguments, NULL)) != -1) {
        switch (option) {
            case PORT:
                port = option; 
                port_number = optarg;
                break;
            case LOG:
                log_opt = option;
                log_filename = optarg;
                break;
            case HOST:
                host = option;
                host_name = optarg;
                break;
            case ENCRYPT:
                encrypt = option;
                key_filename = optarg;
                break;
            /* Unrecognized argument */
            default:
                fprintf(stderr, "\rcorrect usage: ./lab1b-client --port=port# --log=filename --host=hostname --encrypt=keyfile\r\n");
                exit(1);
        }
    }
    
    /* If no recognized long options but received a command line argument, must be wrong usage */
    if (!port && argc > 1) {
        fprintf(stderr, "./lab1b-client: unrecognized argument '%s'\r\ncorrect usage: ./lab1b-client --port=port# --log=filename --host=hostname --encrypt=keyfile\r\n", argv[1]);
        exit(1);
    }
    
    /* Port option is mandatory */
    if (port == -1) {
        fprintf(stderr, "./lab1b-client: incorrect usage\r\nMust provide a port and port number\r\n");
        exit(1);
    }
    
    /* Create log file if --log is given */
    if (log_filename) {
        log_fd = creat_or_open_fd(log_filename, O_WRONLY | O_TRUNC, S_IRWXU);
    }

    /* Open key file if --ecnrypt is given */
    if (key_filename) {
        key_fd = open_fd(key_filename, O_RDONLY);
    }

    /* Set terminal modes for character at a time, no echo mode */
    set_input_mode ();
    
    /* Clear out the hints struct */
    memset(&hints, 0, sizeof(hints));
    
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    /* Look for addresses with desired attributes */
    if ((ret = getaddrinfo(host_name, port_number, &hints, &server_info)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\r\n", gai_strerror(ret));
        exit(1);
    }
    
    /* Loop through linked list of returned addresses */
    for (p = server_info; p != NULL; p = p->ai_next) {
        if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }
        
        if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock_fd);
            continue;
        }
        
        /* If we got here, then we successfully connected */
        break;
    }
    
    /* We couldn't connect to any of the addresses or none were found */
    if (p == NULL) {
        fprintf(stderr, "connect failed: Connection refused\r\n");
        exit(1);
    }
    
    /* We don't need the linked list anymore, just free the memory */
    freeaddrinfo(server_info);
    
    /* Poll server and keyboard for input */
    poll_input();
    
    /* Everything works!! */
    exit(0);
}