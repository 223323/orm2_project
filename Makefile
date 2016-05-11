src :=	\
	src/project.c 			\
	src/network_layers.c    \
	src/server.c            \
	src/client.c            \
	src/listen.c            \
	src/devices.c           \
	src/queue.c				\
	src/packet.c			\
	src/tinycthread.c
	
lib := -lpcap -lpthread -lrt
exec := project
inc := -Iinc

all:
	gcc $(src) -g -o $(exec) $(inc) $(lib)


lines:
	wc -l `find src ! -name "tiny*" ! -name "src"`
