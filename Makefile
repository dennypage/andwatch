#CC=clang
#CFLAGS=-Wall -Wextra -O2

lib_sqlite = -l sqlite3
lib_pcap = -l pcap
lib_curl = -l curl

all: andwatchd andwatch-query andwatch-query-ma andwatch-update-ma

andwatchd-objs = andwatchd.o util.o db.o pcap.o packet.o notify.o
andwatch-query-objs = andwatch-query.o util.o db.o
andwatch-query-ma-objs = andwatch-query-ma.o util.o db.o
andwatch-update-ma-objs = andwatch-update-ma.o util.o db.o

all-objs = $(andwatchd-objs) $(andwatch-query-objs) $(andwatch-query-ma-objs) $(andwatch-update-ma-objs)

$(all-objs): andwatch.h

andwatchd: $(andwatchd-objs)
	$(CC) -o $(@) $(andwatchd-objs) $(lib_pcap) $(lib_sqlite)

andwatch-query: $(andwatch-query-objs)
	$(CC) -o $(@) $(andwatch-query-objs) $(lib_sqlite)

andwatch-query-ma: $(andwatch-query-ma-objs)
	$(CC) -o $(@) $(andwatch-query-ma-objs) $(lib_sqlite)

andwatch-update-ma: $(andwatch-update-ma-objs)
	$(CC) -o $(@) $(andwatch-update-ma-objs) $(lib_sqlite) $(lib_curl)

.PHONY: clean
clean:
	rm -f andwatchd andwatch-query andwatch-query-ma andwatch-update-ma $(all-objs)
