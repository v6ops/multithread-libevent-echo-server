CC = gcc
CFLAGS = -g -Wall -D WITH_IPv6
OBJS = src/server.c src/workqueue.c 
OBJS2 = src/server-ssl.c src/workqueue.c 
LDFLAGS = -levent -lpthread
LDFLAGS2 = -levent -lpthread -lssl -lcrypto
TARGET = build/server.o
TARGET2 = build/server-ssl.o

all: $(TARGET) $(TARGET2)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(TARGET2): $(OBJS2)
	$(CC) $(OBJS2) -o $@ $(LDFLAGS2)

clean:
	rm -f $(TARGET) $(TARGET2)
