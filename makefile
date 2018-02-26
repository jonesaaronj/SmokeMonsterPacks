all:
	gcc -o build_pack build_pack.c vec/vec.c map/map.c mkdir_p/mkdir_p.c -lcrypto -larchive
