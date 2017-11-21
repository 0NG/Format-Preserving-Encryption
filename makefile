libfpe.a: ff1.o ff3.o fpe_locl.o
	ar rcs libfpe.a ff1.o ff3.o fpe_locl.o

ff1.o: ff1.c fpe.h fpe_locl.h
	cc -c ff1.c -O2

ff3.o: ff3.c fpe.h fpe_locl.h
	cc -c ff3.c -O2

fpe_locl.o: fpe_locl.c fpe_locl.h
	cc -c fpe_locl.c -O2 

test: test.c libfpe.a
	gcc test.c -o test -L. -lfpe -lcrypto -lm -O2 -Wno-unused-result

clean:
	rm ff1.o ff3.o fpe_locl.o
