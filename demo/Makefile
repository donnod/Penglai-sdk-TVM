all:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C fork-host
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host-mage
	make -C hello-mage-0
	make -C hello-mage-1
	make -C hello-mage-2
	make -C hello-world
	make -C relay-page
	make -C mem
	make -C IPC
	make -C FS
	make -C test-stop
	make -C psa
	make -C seperated_filesystem_simple

	#CC=$(CC) LINK=$(LINK) AR=$(AR) make -C  mphost_normal

clean:
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C fork-host clean
	CC=$(CC) LINK=$(LINK) AR=$(AR) make -C host-mage clean
	make -C hello-mage-0 clean
	make -C hello-mage-1 clean
	make -C hello-mage-2 clean
	make -C hello-world clean
	make -C relay-page clean
	make -C mem clean
	make -C IPC clean
	make -C FS clean
	make -C test-stop clean
	make -C psa clean
	make -C seperated_filesystem_simple clean
