src :=	\
	src/project.c 			\
	src/network_layers.c    \
	src/server.c            \
	src/client.c            \
	src/listen.c            \
	src/devices.c           \
	src/queue.c				\
	src/tinycthread.c
	
lib := -lpcap -lpthread
exec := project
inc := -Iinc

all:
	gcc $(src) -g -o $(exec) $(inc) $(lib)
	
