default:
	make -C src -f Makefile.32
	mv src/bbproxy core/bbproxy/bbproxy32
	make -C src -f Makefile.64
	mv src/bbproxy core/bbproxy/bbproxy64
	cp version core/version
	make -C core
	cp core/bbproxy-core.zip bbproxy-core-`cat version`.zip

source:
	make clean
	tar czf bbproxy-core-`cat version`.tar.gz -C .. --exclude bbproxy-core-`cat version`.tar.gz bbproxy

clean:
	make -C src clean
	make -C core clean
	rm -f bbproxy-core-*.zip
	rm -f bbproxy-core-*.tar.gz
