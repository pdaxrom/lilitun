TARGET=lilitun

PREFIX=/opt/lilitun

BINDIR=$(PREFIX)/bin
ETCDIR=$(PREFIX)/etc

CC = gcc

INSTALL = install

all:	$(TARGET)

CFLAGS = -Wall -Wpedantic -g

LDFLAGS = -pthread -g

OBJS = lilitun.o aes.o http.o utils.o getrandom.o conn-tunnel.o

http.o: mime.h

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

mime.h:
	perl create_mime.pl > $@

distclean:	clean

clean:
	rm -f $(TARGET) $(OBJS) mime.h

install: all
	$(INSTALL) -d $(DESTDIR)$(ETCDIR)
	$(INSTALL) -D -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	$(INSTALL) -D -m 755 run-client.sh $(DESTDIR)$(BINDIR)/run-client.sh
	$(INSTALL) -D -m 755 run-server.sh $(DESTDIR)$(BINDIR)/run-server.sh
