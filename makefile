all:
	gcc -o smp smp.c file_entry.c hash/hash.c log/log.c map/map.c vec/vec.c mkdir_p/mkdir_p.c -lcrypto -larchive -lz -DLOG_USE_COLOR
