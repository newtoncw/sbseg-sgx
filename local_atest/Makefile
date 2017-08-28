######### SGX TOOLS ######################
SGX_SDK ?= /opt/intel/sgxsdk
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

######## App Settings ########
App_C_Files := App/App.c App/Lib_ocalls.c
App_C_Flags := -fPIC -Wno-attributes -IInclude -IApp -I$(SGX_SDK)/include
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -lsgx_urts_sim -lpthread -lsgx_uae_service_sim
App_C_Objects := $(App_C_Files:.c=.o)
App_Name := app

######## Enclave Settings ########
Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0

######## Enclave 1 Settings ########
Enclave1_C_Files := Enclave1/Lib_ecalls.c
Enclave1_C_Flags := -nostdinc -fvisibility=hidden -fpie -fstack-protector -IInclude -IEnclave1 \
	-I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport
Enclave1_Cpp_Flags := $(Enclave1_C_Flags) -std=c++03 -nostdinc++

Enclave1_C_Objects := $(Enclave1_C_Files:.c=.o)

Enclave1_Name := enclave1.so
Signed_Enclave1_Name := enclave1.signed.so
Enclave1_Config_File := Enclave1/Enclave1.config.xml

######## Enclave 2 Settings ########
Enclave2_C_Files := Enclave2/Lib_ecalls.c
Enclave2_C_Flags := -nostdinc -fvisibility=hidden -fpie -fstack-protector -IInclude -IEnclave2 \
	-I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport
Enclave2_Cpp_Flags := $(Enclave2_C_Flags) -std=c++03 -nostdinc++

Enclave2_C_Objects := $(Enclave2_C_Files:.c=.o)

Enclave2_Name := enclave2.so
Signed_Enclave2_Name := enclave2.signed.so
Enclave2_Config_File := Enclave2/Enclave2.config.xml

.PHONY: all run

all: $(App_Name) $(Signed_Enclave1_Name) $(Signed_Enclave2_Name)

run: all

######## App Objects ########
App/Enclave1_u.c: $(SGX_EDGER8R) Enclave1/Enclave1.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave1/Enclave1.edl --search-path ../Enclave1 --search-path $(SGX_SDK)/include

App/Enclave1_u.o: App/Enclave1_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@

App/Enclave2_u.c: $(SGX_EDGER8R) Enclave2/Enclave2.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave2/Enclave2.edl --search-path ../Enclave2 --search-path $(SGX_SDK)/include

App/Enclave2_u.o: App/Enclave2_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@

App/Lib_ocalls.o: App/Lib_ocalls.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	
App/App.o: App/App.c
	@$(CC) $(App_C_Flags) -c $< -o $@

$(App_Name): App/Enclave1_u.o App/Enclave2_u.o $(App_C_Objects)
	@$(CC) $^ -o $@ $(App_Link_Flags)

######## Enclave 1 Objects ########
Enclave1/Enclave1_t.c: $(SGX_EDGER8R) Enclave1/Enclave1.edl
	@cd Enclave1 && $(SGX_EDGER8R) --trusted ../Enclave1/Enclave1.edl --search-path ../Enclave1 --search-path $(SGX_SDK)/include

Enclave1/Enclave1_t.o: Enclave1/Enclave1_t.c
	@$(CC) $(Enclave1_C_Flags) -c $< -o $@

Enclave1/Lib_ecalls.o: Enclave1/Lib_ecalls.c
	@$(CC) $(Enclave1_C_Flags) -c $< -o $@

$(Enclave1_Name): Enclave1/Enclave1_t.o $(Enclave1_C_Objects)
	@$(CC) $^ -o $@ $(Enclave_Link_Flags)

$(Signed_Enclave1_Name): $(Enclave1_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave1/Enclave1_private.pem -enclave $(Enclave1_Name) -out $@ -config $(Enclave1_Config_File)

######## Enclave 2 Objects ########
Enclave2/Enclave2_t.c: $(SGX_EDGER8R) Enclave2/Enclave2.edl
	@cd Enclave2 && $(SGX_EDGER8R) --trusted ../Enclave2/Enclave2.edl --search-path ../Enclave2 --search-path $(SGX_SDK)/include

Enclave2/Enclave2_t.o: Enclave2/Enclave2_t.c
	@$(CC) $(Enclave2_C_Flags) -c $< -o $@

Enclave2/Lib_ecalls.o: Enclave2/Lib_ecalls.c
	@$(CXX) $(Enclave2_C_Flags) -c $< -o $@

$(Enclave2_Name): Enclave2/Enclave2_t.o $(Enclave2_C_Objects)
	@$(CC) $^ -o $@ $(Enclave_Link_Flags)

$(Signed_Enclave2_Name): $(Enclave2_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave2/Enclave2_private.pem -enclave $(Enclave2_Name) -out $@ -config $(Enclave2_Config_File)

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave1_Name) $(Signed_Enclave1_Name) $(Enclave2_Name) $(Signed_Enclave2_Name) $(App_C_Objects) App/Enclave1_u.* App/Enclave2_u.* $(Enclave1_C_Objects) $(Enclave2_C_Objects) Enclave1/Enclave1_t.* Enclave2/Enclave2_t.*
