######### SGX TOOLS ######################
SGX_SDK ?= /opt/Intel/sgxsdk
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

######## App Settings ########
App_C_Files := enable_device.c
App_C_Flags := -fPIC -Wno-attributes -IInclude -IApp -I$(SGX_SDK)/include
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -lsgx_capable
App_C_Objects := $(App_C_Files:.c=.o)
App_Name := app

.PHONY: all run

all: $(App_Name)

run: all

######## App Objects ########
	
enable_device.o: enable_device.c
	@$(CC) $(App_C_Flags) -c $< -o $@

$(App_Name): enable_device.o
	@$(CC) $^ -o $@ $(App_Link_Flags)

.PHONY: clean

clean:
	@rm -f $(App_Name) $(App_C_Objects)

