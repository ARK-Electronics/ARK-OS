.PHONY: all clean rebuild

BUILD_DIR := build

all: $(BUILD_DIR)/uart_loopback_test

$(BUILD_DIR)/uart_loopback_test: $(BUILD_DIR)/Makefile src/main.cpp
	$(MAKE) -C $(BUILD_DIR)

$(BUILD_DIR)/Makefile: CMakeLists.txt
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake ..

clean:
	rm -rf $(BUILD_DIR)

rebuild: clean all
