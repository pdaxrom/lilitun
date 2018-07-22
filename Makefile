TARGET=lilitun

PREFIX=/opt/lilith

BINDIR=$(PREFIX)/bin
ETCDIR=$(PREFIX)/etc

CC=gcc

INSTALL=install

all:	$(TARGET)

CFLAGS = -O2 -Wall

OBJS = simpletun.o aes.o

$(TARGET): $(OBJS)
	$(CC) -o $@ $^

distclean:	clean

clean:
	rm -f $(TARGET) $(OBJS)

install: all
	$(INSTALL) -d $(DESTDIR)$(ETCDIR)
	$(INSTALL) -D -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	$(INSTALL) -D -m 755 run-client.sh $(DESTDIR)$(BINDIR)/run-client.sh
	$(INSTALL) -D -m 755 run-server.sh $(DESTDIR)$(BINDIR)/run-server.sh
