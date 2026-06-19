CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11
TARGET  = rhc_poc
ATTACK  = attack_demo
SRCS    = rhc.c main.c

all: $(TARGET) $(ATTACK)

$(TARGET): $(SRCS) rhc.h
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

$(ATTACK): rhc.c attack_demo.c rhc.h
	$(CC) $(CFLAGS) -D_POSIX_C_SOURCE=199309L -o $(ATTACK) rhc.c attack_demo.c

clean:
	rm -f $(TARGET) $(ATTACK)

run: all
	./$(TARGET)

attack: $(ATTACK)
	./$(ATTACK)

.PHONY: all clean run attack
