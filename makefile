test: test.o ff1.o ff3.o fpe_locl.o
	cc -o test test.o ff1.o ff3.o fpe_locl.o -lm -lgmp -lcrypto -O2

test.o: test.c fpe.h
	cc -c test.c

ff1.o: ff1.c fpe.h fpe_locl.h
	cc -c ff1.c

ff3.o: ff3.c fpe.h fpe_locl.h
	cc -c ff3.c

fpe_locl.o: fpe_locl.c fpe_locl.h
	cc -c fpe_locl.c

clean:
	rm ff1.o ff3.o test.o fpe_locl.o
