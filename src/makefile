CC      = cc
CFLAGS  = -w -Wall -Wextra
LDFLAGS = -Wl,--allow-multiple-definition -lssl -lcrypto
RM      = rm -f

default: tiaes 

tiaes:
	$(CC) $(CFLAGS) -o tiaes tiaes.c cryputils.c encr.c decr.c keyutils.c sha256.c $(LDFLAGS)

debug:
	$(CC) $(CFLAGS) -g -o tiaes tiaes.c cryputils.c encr.c decr.c keyutils.c sha256.c $(LDFLAGS)

strip:
	$(CC) $(CFLAGS) -o tiaes tiaes.c cryputils.c encr.c decr.c keyutils.c sha256.c $(LDFLAGS) -s

test:
	$(CC) $(CFLAGS) -o test tests.c cryputils.c encr.c keyutils.c sha256.c $(LDFLAGS)

clean:
	$(RM) tiaes test foo
