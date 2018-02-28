all:
	gcc -o build_pack build_pack.c hash.c log/log.c map/map.c vec/vec.c mkdir_p/mkdir_p.c -lcrypto -larchive -DLOG_USE_COLOR
