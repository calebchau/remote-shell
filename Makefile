# NAME: Caleb Chau
# EMAIL: caleb.h.chau@gmail.com
# ID: 204805602

# Variables for files and file names
PROJECT_FILES = lab1b-client.c lab1b-server.c Makefile my.key README 
EXECUTABLES = lab1b-client lab1b-server
PROJECT_NAME = lab1b
STUDENT_ID = 204805602

# Variable for compiler flags
CFLAGS = -g -Wall -Wextra -lmcrypt

default:
	gcc -o lab1b-client lab1b-client.c $(CFLAGS) 
	gcc -o lab1b-server lab1b-server.c $(CFLAGS)

client:
	gcc -o lab1b-client lab1b-client.c $(CFLAGS)

server:
	gcc -o lab1b-server lab1b-server.c $(CFLAGS)

clean:
	rm -f $(EXECUTABLES) $(PROJECT_NAME)-$(STUDENT_ID).tar.gz *.txt

dist:
	tar -czf $(PROJECT_NAME)-$(STUDENT_ID).tar.gz $(PROJECT_FILES)