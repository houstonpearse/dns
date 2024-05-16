# Sample Makefile
# CC - compiler
# OBJ - compiled source files that should be linked
# COPT - compiler flags
# BIN - binary
CC=gcc
OBJ=dns_message.o
COPT=-Wall -Wpedantic -g
BIN_PHASE1=part1
BIN_PHASE2=dns_svr

# Running "make" with no argument will make the first target in the file
all: $(BIN_PHASE1) $(BIN_PHASE2)

# Rules of the form
#     target_to_be_made : dependencies_to_be_up-to-date_first
#     <tab>commands_to_make_target
# (Note that spaces will not work.)

$(BIN_PHASE2): main.c $(OBJ)
	$(CC) -o $(BIN_PHASE2) main.c $(OBJ) $(COPT)

$(BIN_PHASE1): part1.c $(OBJ)
	$(CC) -o $(BIN_PHASE1) part1.c $(OBJ) $(COPT)

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
