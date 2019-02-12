#include "stdio.h"
#include "sgx_capable.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "sgx_error.h"

int main(void) {
	sgx_device_status_t sgx_device_status;
	sgx_status_t ret;

	ret = sgx_cap_enable_device(&sgx_device_status);

	if(ret == SGX_SUCCESS) {
		switch(sgx_device_status) {
			case SGX_ENABLED:
				printf("The platform is enabled for Intel SGX.\n");
				break;
			case SGX_DISABLED_REBOOT_REQUIRED:
				printf("This platform is disabled for Intel SGX. It is configured to be enabled after the next reboot.\n");
				break;
			case SGX_DISABLED_MANUAL_ENABLE:
				printf("The platform is disabled for Intel SGX but can be enabled manually through the BIOS menu. The Software Control Interface is not available to enable Intel SGX on this platform.\n");
				break;
			case SGX_DISABLED_HYPERV_ENABLED:
				printf("The detected version of Windows* 10 is incompatible with Hyper-V*. Intel SGX cannot be enabled on the target machine unless Hyper-V* is disabled.\n");
				break;
			case SGX_DISABLED_LEGACY_OS:
				printf("The operating system does not support UEFI enabling of the Intel SGX device. If UEFI is supported by the operating system in general, but support for enabling the Intel SGX device does not exist, this function will return the more general SGX_DISABLED.\n");
				break;
			case SGX_DISABLED_UNSUPPORTED_CPU:
				printf("Intel SGX is not supported by this processor.\n");
				break;
			case SGX_DISABLED:
				printf("This platform is disabled for Intel SGX. More details about the ability to enable Intel SGX are unavailable. There may be cases where Intel SGX can be manually enabled in the BIOS.\n");
				break;
			default:
				printf("UNKNOWN RESPONSE\n");
		}
	} else {
		/*switch(ret) {
			case SGX_ERROR_INVALID_PARAMETER:
				printf("The sgx_device_status pointer is invalid.\n");
				break;
			case SGX_ERROR_NO_PRIVILEGE:
				printf("The application does not have the required privileges to read an EFI variable. Run the application with the administrator privileges to enable the Intel SGX device status.\n");
				break;
			case SGX_ERROR_HYPERV_ENABLED:
				printf("The detected version of Windows* 10 is incompatible with Hyper-V*. In this case, you need to disable Hyper-V* on the target machine.\n");
				break;
			default:
				printf("An unexpected error is detected.\n");
		}*/
	}

	return 0;
}
