// An identity of ZeroTier made from a seed, for podssh (T-733): both ends of
// a pair make the node's identity from the pair's secret, so that a client
// knows the node's address with no word between them. It is
// `Identity::generate` of `node/Identity.cpp` with the seed in the place of
// the random bytes; the memory-hard hash below is that file's, copied, so
// this file is under the MPL-2.0 as it is (ZeroTier, Inc.).

#include <cstring>
#include <string>
#include <vector>

#include "node/Constants.hpp"
#include "node/Utils.hpp"

// The ECC helpers that make a public key from a private one are private to
// `ECC`; this file alone opens them, after every header but `ECC.hpp`'s own
// is in, so that no other declaration changes.
#define private public
#include "node/ECC.hpp"
#undef private

#include "node/Identity.hpp"
#include "node/SHA512.hpp"
#include "node/Salsa20.hpp"
#include "node/Utils.hpp"

using namespace ZeroTier;

namespace {

// `node/Identity.cpp`'s constants, which a new identity type alone changes.
const unsigned char FIRST_BYTE_LESS_THAN = 17;
const unsigned long MEMORY = 2097152;

// `_computeMemoryHardHash` of `node/Identity.cpp`.
void memory_hard_hash(const void* publicKey, unsigned int publicKeyBytes, void* digest, void* genmem)
{
	SHA512(digest, publicKey, publicKeyBytes);
	memset(genmem, 0, MEMORY);
	Salsa20 s20(digest, (char*)digest + 32);
	s20.crypt20((char*)genmem, (char*)genmem, 64);
	for (unsigned long i = 64; i < MEMORY; i += 64) {
		unsigned long k = i - 64;
		memcpy((char*)genmem + i, (char*)genmem + k, 64);
		s20.crypt20((char*)genmem + i, (char*)genmem + i, 64);
	}
	for (unsigned long i = 0; i < (MEMORY / sizeof(uint64_t));) {
		unsigned long idx1 = (unsigned long)(Utils::ntoh(((uint64_t*)genmem)[i++]) % (64 / sizeof(uint64_t)));
		unsigned long idx2 = (unsigned long)(Utils::ntoh(((uint64_t*)genmem)[i++]) % (MEMORY / sizeof(uint64_t)));
		uint64_t tmp = ((uint64_t*)genmem)[idx2];
		((uint64_t*)genmem)[idx2] = ((uint64_t*)digest)[idx1];
		((uint64_t*)digest)[idx1] = tmp;
		s20.crypt20(digest, digest, 64);
	}
}

}	// namespace

extern "C" {

// The secret identity, as text, of the 64 bytes of `seed`, into `out`; its
// length, or -1. The same seed makes the same identity on each host.
int podssh_zt_identity_of_seed(const unsigned char* seed, char* out, unsigned int cap)
{
	ECC::Pair kp;
	memcpy(kp.priv.data, seed, ZT_ECC_PRIVATE_KEY_SET_LEN);
	unsigned char digest[64];
	std::vector<char> genmem(MEMORY);
	ECC::_calcPubED(kp);
	Address address;
	// `ECC::generateSatisfying`'s steps, and `Identity::generate`'s retry of
	// a reserved address, from the seed.
	do {
		do {
			++(((uint64_t*)kp.priv.data)[1]);
			--(((uint64_t*)kp.priv.data)[2]);
			ECC::_calcPubDH(kp);
			memory_hard_hash(kp.pub.data, ZT_ECC_PUBLIC_KEY_SET_LEN, digest, genmem.data());
		} while (digest[0] >= FIRST_BYTE_LESS_THAN);
		address.setTo(digest + 59, ZT_ADDRESS_LENGTH);
	} while (address.isReserved());

	// The text form of `Identity::toString`: address, type 0, public, private.
	char text[ZT_IDENTITY_STRING_BUFFER_LENGTH];
	char addr[16];
	address.toString(addr);
	std::string s(addr);
	s += ":0:";
	s += Utils::hex(kp.pub.data, ZT_ECC_PUBLIC_KEY_SET_LEN, text);
	s += ":";
	s += Utils::hex(kp.priv.data, ZT_ECC_PRIVATE_KEY_SET_LEN, text);
	Identity id;
	if (! id.fromString(s.c_str()) || ! id.locallyValidate() || ! id.hasPrivate()) {
		return -1;
	}
	id.toString(true, text);
	size_t n = strlen(text);
	if (n > cap) {
		return -1;
	}
	memcpy(out, text, n);
	return (int)n;
}

}
