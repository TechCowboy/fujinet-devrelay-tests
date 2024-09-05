
TARGET_EXEC ?= snoopy

BUILD_DIR ?= ./build
SRC_DIRS ?= ./src

CC=gcc
AS=gcc

SRCS := $(shell find $(SRC_DIRS) -name *.cpp -or -name *.c -or -name *_adam.asm)
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

CFLAGS	= -Wall -Wformat=0 -O2 -fomit-frame-pointer 
ASFLAGS = -Wall -c

INC_DIRS := $(shell find $(SRC_DIRS) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $(TARGET_EXEC)

# c source
$(BUILD_DIR)/%.c.o: %.c
	$(MKDIR_P) $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# asm source
$(BUILD_DIR)/%.asm.o: %.asm
	$(MKDIR_P) $(dir $@)
	$(AS) $(ASFLAGS) -c $< -o $@

.PHONY: clean

clean:
	$(RM) -r -f $(BUILD_DIR)

-include $(DEPS)

MKDIR_P ?= mkdir -p
