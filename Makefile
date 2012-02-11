ROOT=/opt/memcached
INCLUDE=-I${ROOT}/include -I/usr/local/Cellar/hiredis/0.10.0/include/hiredis/

CC = gcc
CFLAGS=-std=gnu99 -g -DNDEBUG -Wall -fno-strict-aliasing -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
 -Wredundant-decls ${INCLUDE} -DHAVE_CONFIG_H -lhiredis
LDFLAGS=-shared

all: redis_engine.so

install: all
	${CP} redis_engine.so ${ROOT}/lib

SRC = redis_engine.c
OBJS = ${SRC:%.c=%.o}

redis_engine.so: $(OBJS)
	${LINK.c} -o $@ ${OBJS}

%.o: %.c
	${COMPILE.c} $< -o $@   

clean:  
	$(RM) redis_engine.so $(OBJS)


