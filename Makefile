.PHONY: all
all:
	rm -f bin/*
	$(MAKE) -C tee
	cp tee/bin/enclave.signed.so server/
	sync

.PHONY: clean
clean:
	$(MAKE) -C tee clean
	rm -f server/enclave.signed.so  server/server
	sync
