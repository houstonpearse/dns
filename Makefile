# Sample Makefile
# CC - compiler
# OBJ - compiled source files that should be linked
# COPT - compiler flags
# BIN - binary
CC=gcc
OBJ=dns_message.o dns_cache.o
COPT=-Wall -Wpedantic
BIN=dns_svr


# Rules of the form
#     target_to_be_made : dependencies_to_be_up-to-date_first
#     <tab>commands_to_make_target
# (Note that spaces will not work.)

$(BIN): dns_svr.c $(OBJ)
	$(CC) -o $(BIN) dns_svr.c $(OBJ) $(COPT)


# Wildcard rule to make any  .o  file,
# given a .c and .h file with the same leading filename component
%.o: %.c %.h
	$(CC) -c $< $(COPT) -g

format:
	clang-format -i *.c *.h

clean:
	rm -f *.o dns_svr part1
	rm -f dns_svr.log
	rm -f -r *.dSYM
