CC := /usr/bin/clang
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -fno-common -fstack-protector-strong
LDFLAGS := -Wl,-bind_at_load

sp_release_seatbelt_v2: sp_release_seatbelt_v2.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
