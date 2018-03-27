ARTIFACT = demo

#Project root dir
#ROOT_DIR := $(notdir $(CURDIR))
ROOT_DIR := $(CURDIR)

SRC_DIR := $(ROOT_DIR)/code
LIB_DIR := $(ROOT_DIR)/libs

OUTPUT_DIR = target
TARGET = $(OUTPUT_DIR)/$(ARTIFACT)

CC = gcc -g
LD = $(CC)

# -fstack-protector #-Wall
FLAGS = -O2 -Wno-unused-result 
DEPS = -Wp,-MMD,$(@:%.o=%.d),-MT,$@

INCLUDES += -I$(SRC_DIR)/pub
INCLUDES += -I$(SRC_DIR)/common/include
INCLUDES += -I$(SRC_DIR)/manager/include
INCLUDES += -I$(SRC_DIR)/security/include
INCLUDES += -I$(SRC_DIR)/ipc/include


LIBS += -L$(LIB_DIR) -lc -lm -lgmapi -lgmurl -lpthread 

#Macro to expand files recursively: parameters $1 -  directory, $2 - extension, i.e. cpp
rwildcard = $(wildcard $(addprefix $1/*.,$2)) $(foreach d,$(wildcard $1/*),$(call rwildcard,$d,$2))

#Source list
SRCS = $(call rwildcard, $(SRC_DIR), c)

#Object files list
OBJS = $(addprefix $(OUTPUT_DIR)/,$(addsuffix .o, $(basename $(SRCS))))
#OBJS = $(addprefix $(OUTPUT_DIR)/,$(subst .c,.o,$(notdir $(SRCS))))


.PHONY:all clean

#Linking rule
$(TARGET):$(OBJS)
	$(LD) $(FLAGS) -o $(TARGET) $(OBJS) $(LIBS)
	@echo DONE!

#Compiling rule
$(OUTPUT_DIR)/%.o:%.c
	@mkdir -p $(dir $@)
	@$(CC) $(FLAGS) -c $(DEPS) -o $@ $(INCLUDES) $(CCFLAGS) $<


#Rules section for default compilation and linking
all: $(TARGET)

clean:
	@-rm -fr $(OUTPUT_DIR)
