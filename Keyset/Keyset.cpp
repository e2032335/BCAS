#include <string.h>
#include "Global.h"
#include "Keyset.h"

static Keyset_t KeysetTable[256] = {
	0xff,
};

s32 BCAS::Keyset::Register(const Keyset_t *Keyset)
{
	if (Keyset == NULL)
		return -1;

	KeysetTable[Keyset->BroadcastGroupID] = *Keyset;

	return 0;
}

void BCAS::Keyset::Unregister(u8 BroadcasterGroupID)
{
	KeysetTable[BroadcasterGroupID].BroadcastGroupID = BroadcasterGroupID ^ 0xff;
}

s32 BCAS::Keyset::GetKey(u8 BroadcasterGroupID, u8 WorkKeyID, u8 *Key)
{
	if (Key == NULL)
		return -1;

	Keyset_t *Set = &KeysetTable[BroadcasterGroupID];
	int Index = WorkKeyID & 1;

	if (Set->BroadcastGroupID != BroadcasterGroupID)
		return -2;

	if (Set->Keys[Index].WorkKeyID != WorkKeyID)
		return -3;

	memcpy(Key, Set->Keys[Index].Key, 8);

	return 0;
}

s32 BCAS::Keyset::GetKeyset(u8 BroadcasterGroupID, Keyset_t &KS)
{
	Keyset_t *Set = &KeysetTable[BroadcasterGroupID];

	if (Set->BroadcastGroupID != BroadcasterGroupID)
		return -1;

	KS = *Set;

	return 0;
}
