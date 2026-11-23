# SPDX-License-Identifier: GPL-2.0-only
#
# icmp-pulse
#
#   make                 build client and server
#   make client          build the router client only (icmp-pulse)
#   make server          build the server only (icmp-pulse-server)
#   make test            build and run the self tests
#   make install         install client and server
#   make install-client  install the client, its init script and UCI config
#   make install-server  install the server, its systemd unit and keys file
#
# Honours CC, CFLAGS, LDFLAGS, DESTDIR, PREFIX (and SBINDIR, SYSCONFDIR,
# SYSTEMDUNITDIR) so that it can be driven by a distribution or OpenWrt build.

VERSION := $(shell sed -n 's/^\#define ICMP_PULSE_VERSION "\(.*\)"/\1/p' common/version.h)

CC             ?= cc
CFLAGS         ?= -O2
LDFLAGS        ?=
DESTDIR        ?=
PREFIX         ?= /usr/local
SBINDIR        ?= $(PREFIX)/sbin
SYSCONFDIR     ?= /etc
SYSTEMDUNITDIR ?= /etc/systemd/system

WARN       = -Wall -Wextra
ALL_CFLAGS = -std=gnu99 $(WARN) -Icommon $(CFLAGS)

HEADERS    = common/proto.h common/chachapoly.h common/version.h
COMMON_OBJ = common/proto.o common/chachapoly.o

CLIENT = client/icmp-pulse
SERVER = server/icmp-pulse-server
TEST   = tests/proto_test

all: client server

client: $(CLIENT)
server: $(SERVER)

$(CLIENT): client/icmp-pulse.o $(COMMON_OBJ)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) -o $@ $^

$(SERVER): server/icmp-pulse-server.o $(COMMON_OBJ)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) -o $@ $^

$(TEST): tests/proto_test.o $(COMMON_OBJ)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c $(HEADERS)
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

test: $(TEST)
	./$(TEST)

install: install-client install-server

# install-client uses mkdir/cp/chmod only: BusyBox on OpenWrt may lack 'install'
install-client: client
	mkdir -p $(DESTDIR)$(SBINDIR) $(DESTDIR)$(SYSCONFDIR)/init.d $(DESTDIR)$(SYSCONFDIR)/config
	cp $(CLIENT) $(DESTDIR)$(SBINDIR)/icmp-pulse
	chmod 0755 $(DESTDIR)$(SBINDIR)/icmp-pulse
	sed 's|/usr/sbin/icmp-pulse|$(SBINDIR)/icmp-pulse|' files/icmp-pulse.init \
		> $(DESTDIR)$(SYSCONFDIR)/init.d/icmp-pulse
	chmod 0755 $(DESTDIR)$(SYSCONFDIR)/init.d/icmp-pulse
	[ -f $(DESTDIR)$(SYSCONFDIR)/config/icmp-pulse ] || { \
		cp files/icmp-pulse.config $(DESTDIR)$(SYSCONFDIR)/config/icmp-pulse && \
		chmod 0600 $(DESTDIR)$(SYSCONFDIR)/config/icmp-pulse; }

install-server: server
	install -d $(DESTDIR)$(SBINDIR) $(DESTDIR)$(SYSTEMDUNITDIR)
	install -d -m 0750 $(DESTDIR)$(SYSCONFDIR)/icmp-pulse
	install -m 0755 $(SERVER) $(DESTDIR)$(SBINDIR)/icmp-pulse-server
	sed 's|/usr/sbin/icmp-pulse-server|$(SBINDIR)/icmp-pulse-server|' \
		files/icmp-pulse-server.service > $(DESTDIR)$(SYSTEMDUNITDIR)/icmp-pulse-server.service
	chmod 0644 $(DESTDIR)$(SYSTEMDUNITDIR)/icmp-pulse-server.service
	[ -f $(DESTDIR)$(SYSCONFDIR)/icmp-pulse/keys ] || \
		install -m 0600 files/icmp-pulse.keys $(DESTDIR)$(SYSCONFDIR)/icmp-pulse/keys

version:
	@echo $(VERSION)

clean:
	rm -f client/*.o server/*.o common/*.o tests/*.o $(CLIENT) $(SERVER) $(TEST)

.PHONY: all client server test install install-client install-server version clean
