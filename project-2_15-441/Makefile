TOP_DIR = .
INC_DIR = $(TOP_DIR)/inc
SRC_DIR = $(TOP_DIR)/src
BUILD_DIR = $(TOP_DIR)/build
CC=gcc
FLAGS = -pthread -fPIC -g -ggdb -pedantic -Wall -Wextra -DDEBUG -I$(INC_DIR)
OBJS = $(BUILD_DIR)/cmu_packet.o $(BUILD_DIR)/cmu_tcp.o $(BUILD_DIR)/backend.o $(BUILD_DIR)/buffer.o $(BUILD_DIR)/recv.o $(BUILD_DIR)/send.o

# --- ADDED FOR TESTING ----
TEST_SRC_DIR = $(TOP_DIR)/tests
TEST_BUILD_DIR = $(TOP_DIR)/build_test
TESTS = tests/test_buffer tests/test_server tests/test_client
# --- END ADDED FOR TESTING ----

all: server client tests/testing_server tests/testing_still_server tests testing

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(FLAGS) -c -o $@ $<

server: $(OBJS) $(SRC_DIR)/server.c
	$(CC) $(FLAGS) $(SRC_DIR)/server.c -o server $(OBJS)

client: $(OBJS) $(SRC_DIR)/client.c
	$(CC) $(FLAGS) $(SRC_DIR)/client.c -o client $(OBJS)

tests/testing_%: tests/testing_%.c $(OBJS) 
	$(CC) $(FLAGS) $@.c -o $@ $(OBJS)


tests/test_%: $(TEST_SRC_DIR)/test_%.c $(OBJS) 
	$(CC) $(FLAGS) $@.c -o $@ $(OBJS)
testing: $(TESTS)


format:
	pre-commit run --all-files

test:
	sudo -E python3 tests/test_cp1.py
	sudo -E python3 tests/test_cp1_basic_ack_packets.py

clean:
	rm -f $(BUILD_DIR)/*.o peer client server
	rm -f tests/testing_server
