CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -Werror -O2 -Iinclude
LDFLAGS :=
LDLIBS  := -lsqlite3

SRC_DIR := src
OBJ_DIR := build
BIN     := cve_scanner

TOOLS_DIR := tools
JSON_DIR  := data/nvd_json
DB_PATH   := data/nvd.sqlite3
EXPLOITS  := data/exploits.csv
SAMPLE_EXP := $(TOOLS_DIR)/sample_exploits.csv
UPDATE_SCRIPT := $(TOOLS_DIR)/update_nvd_sqlite.py

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

.PHONY: all clean debug release install uninstall db exploits clean-db
all: $(DB_PATH) $(EXPLOITS) $(BIN)

debug: CFLAGS := -std=c11 -Wall -Wextra -O0 -g -Iinclude
debug: clean all

release: clean all
	strip $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@
$(DB_PATH): $(UPDATE_SCRIPT) $(wildcard $(JSON_DIR)/*)
	@mkdir -p data
	@if [ ! -f "$(UPDATE_SCRIPT)" ]; then \
		echo "No update script $(UPDATE_SCRIPT)"; exit 1; \
	fi
	@if [ -z "$(wildcard $(JSON_DIR)/*)" ]; then \
		echo "JSON not found in $(JSON_DIR). Downloading..."; \
		$(UPDATE_SCRIPT) $(DB_PATH) --json-dir $(JSON_DIR) --download; \
	else \
		$(UPDATE_SCRIPT) $(DB_PATH) --json-dir $(JSON_DIR); \
	fi

$(EXPLOITS):
	@mkdir -p data
	@if [ -f "$(SAMPLE_EXP)" ]; then \
		cp "$(SAMPLE_EXP)" "$(EXPLOITS)"; \
	else \
		echo "id,cve,description,path" > "$(EXPLOITS)"; \
	fi

db: $(DB_PATH)
exploits: $(EXPLOITS)

clean-db:
	rm -f $(DB_PATH) $(EXPLOITS)
clean:
	rm -rf $(OBJ_DIR) $(BIN)

PREFIX ?= /usr/local
install: $(BIN)
	install -d $(PREFIX)/bin
	install -m 0755 $(BIN) $(PREFIX)/bin/$(BIN)

uninstall:
	rm -f $(PREFIX)/bin/$(BIN)
