// The few calls of ZeroTier's core that its C API does not give, for
// podssh (T-733): a planet of the caller's own roots, signed by a key made
// for it and dropped, as a test's world or a self-hosted one; and the MAC
// address of a member of a network. podssh's own code, over the MPL-2.0 core.

#include <cstring>
#include <vector>

#include "node/Constants.hpp"
#include "node/ECC.hpp"
#include "node/Identity.hpp"
#include "node/InetAddress.hpp"
#include "node/MAC.hpp"
#include "node/World.hpp"

using namespace ZeroTier;

extern "C" {

// A planet of id `id` and time `ts` whose roots are the `count` public
// identities of `identities` (each a text), each at the one endpoint
// `endpoints[i]` ("IP/PORT"). Its bytes go to `out`; their length, or -1.
int podssh_zt_world(uint64_t id, uint64_t ts, const char* const* identities, const char* const* endpoints,
	unsigned int count, unsigned char* out, unsigned int cap)
{
	std::vector<World::Root> roots;
	for (unsigned int i = 0; i < count; ++i) {
		World::Root root;
		if (! root.identity.fromString(identities[i])) {
			return -1;
		}
		InetAddress at(endpoints[i]);
		if (! at) {
			return -1;
		}
		root.stableEndpoints.push_back(at);
		roots.push_back(root);
	}
	const ECC::Pair signer = ECC::generate();
	World world = World::make(World::TYPE_PLANET, id, ts, signer.pub, roots, signer);
	Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH> bytes;
	world.serialize(bytes, false);
	if (bytes.size() > cap) {
		return -1;
	}
	std::memcpy(out, bytes.data(), bytes.size());
	return (int)bytes.size();
}

// The MAC address of the member `address` (40 bits) on the network `nwid`.
uint64_t podssh_zt_mac(uint64_t address, uint64_t nwid)
{
	return MAC(Address(address), nwid).toInt();
}

}
