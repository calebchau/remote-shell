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
#define PIPE "pipe"
#define FORK "fork"
#define OPEN "open"
#define CLOSE "close"
#define DUP "dup"
#define EXECVP "execvp"
#define POLL "poll"
#define KILL "kill"
#define READ "read"
#define WRITE "write"
#define SIGNAL "signal"
#define SOCKET "socket"
#define BIND "bind"
#define ACCEPT "accept"
#define MCRYPT_OPEN "mcrypt open"
#define MCRYPT_INIT "mcrypt init"
#define MCRYPT_DEINIT "mcrypt deinit"
#define PORT 'p'
#define ENCRYPT 'e'
#define CR '\r'
#define LF '\n'
#define CTRL_C '\003'
#define CTRL_D '\004'

typedef void (*sighandler_t)(int);

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
/* Two pipes to hold the fd's for inter-process communication */
int pipe_to_child[2];
int pipe_from_child[2];
/* Variable to store the pid of the child process */
pid_t child_pid = -1;
/* File descriptors for socket connection and key file */
int sock_fd, client_sock_fd, key_fd;
/* Detect if --encrypt option is given */
int encrypt;
char* key_filename = NULL;
/* Variables for encryption */
MCRYPT td;
char* key, * IV;
int key_size, IV_size;

void handle_error(char* operation) {
    int err_no = errno;
    char* err_message = strerror(err_no);
    
    fprintf(stderr, "%s failed: %s\r\n", operation, err_message);
}

void connect_process(int fd[2]) {
    if (pipe(fd) == -1) {
        handle_error(PIPE);
        exit(1);
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

void dup2_fd(int old_fd, int new_fd) {
    if (dup2(old_fd, new_fd) == -1) {
        handle_error(DUP);
        exit(1);
    }
}

void kill_process(pid_t pid, int signum) {
    if (kill(pid, signum) == -1) {
        handle_error(KILL);
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

void signal_handler(int signum) {
    if (signum == SIGPIPE) {
        write_fd(STDERR_FILENO, "SIGPIPE received...\r\n", 21);
    }
}

void register_signal(int signum, sighandler_t handler) {
    if (signal(signum, handler) == SIG_ERR) {
        handle_error(SIGNAL);
        exit(1);
    }
}

void report_exit_status(void) {
    int exit_status, signal_status;
    exit_status = signal_status = -1;
    waitpid(child_pid, &exit_status, 0);
    
    signal_status = exit_status & 0x007f;
    exit_status = (exit_status & 0xff00) >> 8;
    
    fprintf(stderr, "SHELL EXIT SIGNAL=%d STATUS=%d\r\n", signal_status, exit_status);

    exit(0);
}

void setup_encrypter(void) {
    if (encrypt) {
        int i;

        key_size = 16;
        key = calloc(1, key_size);
        read_fd(key_fd, key, key_size);

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

/* Parent Process */ 
void communicate(void) {
    close_fd(pipe_to_child[0]);
    close_fd(pipe_from_child[1]);
    
    nfds_t nfds = 2;
    struct pollfd fds[nfds];
    
    fds[0].fd = client_sock_fd;
    fds[0].events = POLLIN | POLLHUP | POLLERR;
    
    fds[1].fd = pipe_from_child[0];
    fds[1].events = POLLIN | POLLHUP | POLLERR;
    
    buffer = (char*) malloc(BUFFER_SIZE * sizeof(char));
    
    while (1) {
        if ((ret = poll(fds, nfds, 0)) == -1) {
            handle_error(POLL);
            exit(1);
        }
        
        if (fds[0].revents & POLLIN) {
            count = read_fd(client_sock_fd, buffer, BUFFER_SIZE);
            
            size_t i = 0;

            if (count == 0) {
                close_fd(pipe_to_child[1]);
                report_exit_status();
            }

            setup_encrypter();
            
            while (count > 0) {
                decrypt_data(&buffer[i], 1);

                switch (buffer[i]) {
                    case CR:
                    case LF:
                        write_fd(pipe_to_child[1], lf, 1);
                        break;
                    case CTRL_C:
                        kill_process(child_pid, SIGINT);
                        break;
                    case CTRL_D:
                        close_fd(pipe_to_child[1]);
                        break;
                    default:
                        write_fd(pipe_to_child[1], &buffer[i], 1);
                        break;
                }
                
                i++;
                count--;
            }

            deinit_encrypter();
        }
        
        /* Read from shell (from_child_pipe[0]) and echo to STDOUT */
        if (fds[1].revents & POLLIN) {
            count = read_fd(pipe_from_child[0], buffer, BUFFER_SIZE);
            
            size_t i = 0;

            setup_encrypter();
            
            while (count > 0) {
                encrypt_data(&buffer[i], 1);

                switch (buffer[i]) {
                    case LF:
                        write_fd(client_sock_fd, cr_lf, 2);
                        break;
                    default:
                        write_fd(client_sock_fd, &buffer[i], 1);
                        break;
                }
                
                i++;
                count--;
            }

            deinit_encrypter();
        }
        
        if (fds[1].revents & (POLLHUP | POLLERR)) {
            count = read_fd(pipe_from_child[0], buffer, BUFFER_SIZE);
            
            if (count == 0) {
                report_exit_status();
            } else {
                size_t i = 0;

                setup_encrypter();
                
                while (count > 0) {
                    encrypt_data(&buffer[i], 1);

                    switch (buffer[i]) {
                        case LF:
                            write_fd(client_sock_fd, cr_lf, 2);
                            break;
                        default:
                            write_fd(client_sock_fd, &buffer[i], 1);
                            break;
                    }
                    
                    i++;
                    count--;
                }

                deinit_encrypter();
            }
        }
    }
}

/* Child Process */
void execvp_shell(void) {
    /* Perform all redirections for the shell's fds */
    close_fd(pipe_to_child[1]);
    close_fd(pipe_from_child[0]);
    dup2_fd(pipe_to_child[0], STDIN_FILENO);
    dup2_fd(pipe_from_child[1], STDOUT_FILENO);
    dup2_fd(pipe_from_child[1], STDERR_FILENO);
    close_fd(pipe_to_child[0]);
    close_fd(pipe_from_child[1]);
    
    /* Arguments for execvp call */
    char* execvp_argv[2];
    char* execvp_filename = "/bin/bash";
    execvp_argv[0] = execvp_filename;
    execvp_argv[1] = NULL;
    
    /* Execute a bash shell */
    if (execvp(execvp_filename, execvp_argv) == -1) {
        handle_error(EXECVP);
        exit(1);
    }
}

int main(int argc, char* argv[]) {
    struct option arguments[] = {
        { "port", required_argument, NULL, PORT },
        { "encrypt", required_argument, NULL, ENCRYPT },
        { 0, 0, 0, 0 }
    };
    
    int option, port;
    socklen_t client_size;
    option = port = client_size = -1;

    char* port_number;

    struct addrinfo hints, * server_info, * p;
    struct sockaddr_in client_address;
    
    buffer = (char*) malloc(BUFFER_SIZE * sizeof(char));
    
    while ((option = getopt_long(argc, argv, "", arguments, NULL)) != -1) {
        switch (option) {
            case PORT:
                port = option; 
                port_number = optarg;
                register_signal(SIGPIPE, signal_handler);
                break;
            case ENCRYPT:
                encrypt = option;
                key_filename = optarg;
                break;
            /* Unrecognized argument */
            default:
                fprintf(stderr, "\rcorrect usage: ./lab1b-server --port=port# --encrypt=keyfile\r\n");
                exit(1);
        }
    }
    
    /* If no recognized long options but received a command line argument, must be wrong usage */
    if (!port && argc > 1) {
        fprintf(stderr, "./lab1b-server: unrecognized argument '%s'\r\ncorrect usage: ./lab1b-server --port=port# --encrypt=keyfile\r\n", argv[1]);
        exit(1);
    }
    
    /* Port option is mandatory */
    if (port == -1) {
        fprintf(stderr, "./lab1b-server: incorrect usage\r\nMust provide a port and port number\r\n");
        exit(1);
    }

    if (key_filename) {
        key_fd = open_fd(key_filename, O_RDONLY);
    }

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((ret = getaddrinfo(NULL, port_number, &hints, &server_info)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\r\n", gai_strerror(ret));
        exit(1);
    }

    for (p = server_info; p != NULL; p = p->ai_next) {
        if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }

        if (bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock_fd);
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "bind failed: Could not bind to socket\r\n");
        exit(1);
    }

    freeaddrinfo(server_info);
    
    listen(sock_fd, 5);
    client_size = sizeof(client_address);
    
    while (1) {
        if ((client_sock_fd = accept(sock_fd, (struct sockaddr*) &client_address, &client_size)) == -1) {
            handle_error(ACCEPT);
            exit(1);
        }
        
        connect_process(pipe_to_child);
        connect_process(pipe_from_child);
        
        child_pid = fork();
        
        if (child_pid > 0) { /* Parent process */
            communicate();
        } else if (child_pid == 0) { /* Child process */
            execvp_shell();
        } else { /* fork() failed */
            handle_error(FORK);
            exit(1);
        }
    }
    
    /* Everything works!! */
    exit(0);
}