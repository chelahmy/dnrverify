CC = gcc
LIBS = -lstdc++ -lboost_system -lcrypto
CFLAGS = 
OUTFILE = dnrverify
OBJS = main.o dnrverify.o version.o
SRCS = main.cpp dnrverify.cpp version.cpp

all: $(OUTFILE) 

$(OUTFILE): $(OBJS)
	$(CC) $(LIBS) -o $(OUTFILE) $(OBJS)
$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) -c $(SRCS)

clean:
	rm -rf *.o $(OUTFILE)

