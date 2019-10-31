SRCS = $(shell find -name '*.c')
OBJS = $(SRCS:.c=.o)
EXEC = client
CFLAGS = -ansi -pedantic-errors -Wall
LFLAGS =
CC = gcc
$(EXEC): $(OBJS)
	$(CC) -o $@ $^ $(LFLAGS)

$(OBJS): $(SRCS)
	$(CC) -c $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(OBJS) $(EXEC)



