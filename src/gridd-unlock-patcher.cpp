/* SPDX-License-Identifier: GPL-3.0-or-later */

#undef NDEBUG

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <LIEF/ELF.hpp>
#include <LIEF/PE.hpp>
#include "nls-root_ca-certificates.hpp"

using namespace LIEF;

bool is_linux_guest;
// TODO: `mmap`ing this might be lighter
FILE *gridd_filep = NULL;
uint8_t *gridd_data = NULL;

FILE *cert_fp = NULL;
char *user_root_ca = NULL;

const char *gridd_hardcoded_cert_one;
const char *gridd_hardcoded_cert_two;

void usage(char *program_name)
{
	printf("Usage: %s [OPTIONS]\n\n", program_name);
	printf("Options:\n"
	       "\t-h\tShow this help message.\n"
	       "\t-g\t<GRID executable>\n"
	       "\t-c\t<root CA certificate>\n\n");

	printf("For Windows guests, the GRID executable is Display.Driver/nvxdapix.dll.\n");
	printf("For Linux guests, the GRID executable is nvidia-gridd.\n");
}

int initialise_patcher(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "hg:c:")) != -1) {
		// Required parameter is in global "optarg"
		switch (opt) {
		case '?':
		/* fall through */
		case 'h':
			usage(argv[0]);
			return -1;
		case 'g':
			gridd_filep = fopen(optarg, "rb+");
			is_linux_guest = strstr(optarg, ".dll") == NULL;
			break;
		case 'c':
			cert_fp = fopen(optarg, "rb");
			break;
		}
	}

	if (gridd_filep == NULL || cert_fp == NULL) {
		usage(argv[0]);
		return -1;
	}

	gridd_hardcoded_cert_one = is_linux_guest ? gridd_hardcoded_cert_one_linux : gridd_hardcoded_cert_one_windows;
	gridd_hardcoded_cert_two = is_linux_guest ? gridd_hardcoded_cert_two_linux : gridd_hardcoded_cert_two_windows;

	return 0;
}
void cleanup(void)
{
	if (user_root_ca)
		free(user_root_ca);
	if (gridd_data)
		free(gridd_data);
	if (cert_fp)
		fclose(cert_fp);
	if (gridd_filep)
		fclose(gridd_filep);
}

void hexdump(uint8_t *buf, size_t size)
{
	for (int i = 0; i < size; i++) {
		if (i % 0x10 == 0)
			printf("\n%04X: ", i);
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

int read_user_cert(size_t *user_ca_size)
{
	char *temp_buffer = (char *)malloc(*user_ca_size);
	assert(temp_buffer != NULL);

	size_t status = fread((void *)temp_buffer, *user_ca_size - 1, 1, cert_fp);
	assert(status > 0);

	// Make it a valid string
	temp_buffer[*user_ca_size - 1] = 0;

	// Basic checks that the input is a PEM
	if (strstr(temp_buffer, PEM_BEGIN_CERTIFICATE) == NULL|| strstr(temp_buffer, PEM_END_CERTIFICATE) == NULL)
		return -1;

	if (is_linux_guest) {
		user_root_ca = temp_buffer;
	} else {
		*user_ca_size -= strlen(PEM_BEGIN_CERTIFICATE) + strlen(PEM_END_CERTIFICATE);

		// Just allocate it all
		user_root_ca = (char *)calloc(1, *user_ca_size);
		assert(user_root_ca != NULL);

		size_t skipped_bytes = 0;
		for (int i = 0; i < *user_ca_size - 1; i++) {
			if (temp_buffer[i + strlen(PEM_BEGIN_CERTIFICATE)] != '\n')
				user_root_ca[i - skipped_bytes] = temp_buffer[i + strlen(PEM_BEGIN_CERTIFICATE)];
			else
				skipped_bytes++;
		}

		free(temp_buffer);
		*user_ca_size -= skipped_bytes;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct stat gridd_fp_stats, cert_fp_stats;

	printf("gridd-unlock-patcher: Patching GRID daemons with custom NLS certificates.\n");
	if (initialise_patcher(argc, argv) == -1) {
		cleanup();
		return -1;
	}

	/* Find the hardcoded certificates */
	// Read the nvidia-gridd binary
	fstat(fileno(gridd_filep), &gridd_fp_stats);
	gridd_data = (uint8_t *)malloc(gridd_fp_stats.st_size);
	assert(gridd_data != NULL);

	size_t status = fread((void *)gridd_data, gridd_fp_stats.st_size, 1, gridd_filep);
	assert(status > 0);

	// Parse the binary
	std::vector<uint8_t> gridd_vec(gridd_data, gridd_data + gridd_fp_stats.st_size);

	std::unique_ptr<LIEF::ELF::Binary> gridd_elf = nullptr;
	std::unique_ptr<LIEF::PE::Binary> gridd_dll = nullptr;
	if (is_linux_guest)
		gridd_elf = ELF::Parser::parse(gridd_vec);
	else
		gridd_dll = PE::Parser::parse(gridd_vec);
	if (!gridd_elf && !gridd_dll) {
		printf("Failed to parse GRID executable! Are you sure it's either an ELF or a PE?\n");
		cleanup();
		return -1;
	}

	uint64_t image_base = is_linux_guest ? gridd_elf->imagebase() : gridd_dll->imagebase();

	auto s_rdata = is_linux_guest ? (LIEF::Section *)gridd_elf->get_section(".rodata")
					: (LIEF::Section *)gridd_dll->get_section(".rdata");
	auto s_data = is_linux_guest ? (LIEF::Section *)gridd_elf->get_section(".data")
					: (LIEF::Section *)gridd_dll->get_section(".data");
	if (!s_rdata || !s_data) {
		printf("Failed to parse GRID executable! Are you sure it's a GRID executable?\n");
		cleanup();
		return -1;
	}

	// There are two hardcoded certificates
	size_t cert_one_offset = s_rdata->search(gridd_hardcoded_cert_one);
	size_t cert_two_offset = s_rdata->search(gridd_hardcoded_cert_two);
	if (cert_one_offset == -1 || cert_two_offset == -1) {
		printf("Failed to find the hardcoded NLS certificates!\n");
		cleanup();
		return -1;
	}

	printf("Found the two hardcoded NLS certificates at 0x%x and 0x%x.\n",
		s_rdata->offset() + cert_one_offset, s_rdata->offset() + cert_two_offset);

	/* Patch in the provided certificate */
	// Validate the size of the provided root CA
	fstat(fileno(cert_fp), &cert_fp_stats);
	size_t user_ca_size = cert_fp_stats.st_size + 1;
	// TODO: Align up, we can use cert two's padding too
	size_t total_cert_size = cert_two_offset + (strlen(gridd_hardcoded_cert_two) + 1) - cert_one_offset;
	if (user_ca_size > total_cert_size) {
		printf("The provided certificate (size %d) is larger than available space (size %d)!\n",
			user_ca_size, total_cert_size);
		cleanup();
		return -1;
	}

	// Read the certificate in guest-native form.
	if (read_user_cert(&user_ca_size) == -1) {
		printf("Failed to process provided certificate! Are you sure it's an OpenSSL PEM?\n");
		cleanup();
		return -1;
	}

	// Overwrite the first certificate, NULL the second
	// - TODO: Consider an insecure mode that doesn't check that the certificate matches a hardcoded root CA.
	uint8_t *cert_start = gridd_data + s_rdata->offset() + cert_one_offset;
	memcpy((void *)cert_start, (void *)user_root_ca, user_ca_size);
	memset((void *)(cert_start + user_ca_size), 0, total_cert_size - user_ca_size);

	printf("Replaced the hardcoded certificates with the provided one.\n");

	// Erase the XREF to the second certificate
	// - TODO: This would be better if it searched for both. Alternatively, use Zydis to get XREFs into this
	uint64_t search_target_base_addr = s_rdata->virtual_address();
	if (!is_linux_guest)
		search_target_base_addr += image_base;
	uint64_t cert_xrefs_array = s_data->offset() + s_data->search(search_target_base_addr + cert_one_offset);

	printf("Found the list of certificates at 0x%x.\n", cert_xrefs_array);
	// PEs have some mapping oddities, and this is off by a bit. Don't confuse users.
	printf("Erasing the dangling reference to the old certificate at 0x%x (Expect offset for Windows daemon).\n",
		*(uint64_t *)(gridd_data + cert_xrefs_array + sizeof(uint64_t)) - image_base);

	memset((void *)(gridd_data + cert_xrefs_array + sizeof(uint64_t)), 0, sizeof(uint64_t));

	/* Make it HTTP/2 compliant */
	// TODO: Theoretically, it'd be better to exchange `strstr` for `strcasestr`. But I'd rather be done for now.
	size_t x_nls_sig_offset = s_rdata->search("X-NLS-Signature");
	if (x_nls_sig_offset != -1) {
		uint8_t *x_nls_sig_start = gridd_data + s_rdata->offset() + x_nls_sig_offset;
		memcpy((void *)x_nls_sig_start, "x-nls-signature", strlen("x-nls-signature"));
		printf("Patched the HTTP header \"X-NLS-Signature\" for HTTP/2 compliance.\n");
	}

	// Write the nvidia-gridd binary
	fseek(gridd_filep, 0, SEEK_SET);
	fwrite((void *)gridd_data, gridd_fp_stats.st_size, 1, gridd_filep);

	cleanup();
	printf("Done!\n");
	return 0;
}
