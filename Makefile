CC=gcc
OBJ=dns_message.o dns_cache.o connection.o logger.o
COPT=-Wall -Wpedantic
BIN=dns_svr

$(BIN): src/dns_svr.c $(OBJ)
	$(CC) -pthread -o $(BIN) src/dns_svr.c $(OBJ) $(COPT)

%.o: src/%.c src/%.h
	$(CC) -c $< $(COPT) -g

format:
	clang-format -i *.c *.h

clean:
	rm -f *.o $(BIN) 
	rm -f dns_svr.log
