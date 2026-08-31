CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
LDFLAGS ?=

BIN = elfscan
SRC = main.c

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

# byte-level encoding checks, planted sleds in real binaries, and a
# false-positive ceiling measured against the system's own binaries
check: $(BIN)
	python3 tests/run.py ./$(BIN)

# malformed ELF: truncated, garbage headers, absurd e_phnum/e_phoff,
# wrong class, wrong endianness.  A scanner is pointed at hostile files
# by definition, so none of it may crash, hang or read out of bounds.
fuzz:
	$(CC) -O1 -g -fsanitize=address,undefined -o $(BIN).san $(SRC)
	python3 tests/fuzz.py ./$(BIN).san

# the test suite under ASan + UBSan
asan:
	$(CC) -O1 -g -fsanitize=address,undefined -o $(BIN).san $(SRC)
	python3 tests/run.py ./$(BIN).san

# what the heuristics say about this machine's own binaries
survey: $(BIN)
	python3 tests/survey.py ./$(BIN)

clean:
	rm -f $(BIN) $(BIN).san

.PHONY: all check fuzz asan survey clean
