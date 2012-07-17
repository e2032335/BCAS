#ifndef BCAS_KEYSET_H
#define BCAS_KEYSET_H

typedef struct {
	u8 WorkKeyID;
	u8 Key[8];
} Key_t;

typedef struct {
	u8 BroadcastGroupID;
	Key_t Keys[2];
	const char *Name;
} Keyset_t;

namespace BCAS {
	namespace Keyset {
		s32 Register(const Keyset_t *Keyset);
		void Unregister(u8 BroadcasterGroupID);
		s32 GetKey(u8 BroadcasterGroupID, u8 WorkKeyID, u8 *Key);
		s32 GetKeyset(u8 BroadcasterGroupID, Keyset_t &KS);
	}
}

#endif
