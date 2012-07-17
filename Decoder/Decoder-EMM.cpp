#include <stdio.h>
#include <string.h>
#include "Global.h"
#include "Decoder.h"
#include "Crypto.h"
#include "Generator.h"
#include "Keyset.h"

typedef u8 CRC32_t[4];
typedef u8 MAC_t[4];

static u8 CardID[8];
static u8 CardKey[8];

s32 BCAS::Decoder::DecodeEMM(const u8 *Payload, u32 Size, bool Individual)
{
	u8 Plaintext[256];
	u8 MAC[4];

	if (Size < 6 + sizeof(MAC_t))
		return -1;

	if (memcmp(Payload, CardID, 6) != 0)
		return -2;

	const u8 *Body = NULL;
	const u8 *Verify = NULL;
	u8 *Output = NULL;
	u16 SizeVerify = 0;
	u16 Total = 0;
	u8 Protocol;

	if (Individual) {
		const BCAS::EMD::Header_t *EMM = reinterpret_cast<const BCAS::EMD::Header_t *>(Payload);

		Protocol = EMM->ProtocolNumber;
		Body = EMM->Unknown0;
		Verify = Plaintext + 9;
		Output = Plaintext + 9;
		memcpy(Plaintext, EMM, 6);
		Plaintext[6] = Payload[ 8];
		Plaintext[7] = Payload[ 9];
		Plaintext[8] = Payload[11];
		Size -= 12;
		SizeVerify = Size - 4;
		Total = Size + 9;
	} else {
		const BCAS::EMM::Header_t *EMM = reinterpret_cast<const BCAS::EMM::Header_t *>(Payload);

		Protocol = EMM->ProtocolNumber;
		Body = &EMM->BroadcasterGroupID;
		Output = Plaintext + 8;
		Verify = Plaintext;
		memcpy(Plaintext, EMM, 8);
		Size -= 8;
		SizeVerify = Size + 4;
		Total = Size + 8;
	}

	BCAS::Crypto::Transform(Protocol, CardKey, Body, Size, Output, true);

	BCAS::Crypto::GenerateMAC(Protocol, CardKey, Verify, SizeVerify, MAC);

	if (memcmp(MAC, Verify + SizeVerify, 4))
		return -3;

	printf("EMM:");
	for (u16 i = 0 ; i < Total ; i++)
		printf(" %02x", Plaintext[i]);
	printf("\n");

	return 0;
}

void BCAS::Decoder::SetCardID(const u8 *ID)
{
	if (ID != NULL)
		memcpy(CardID, ID, 8);
}

void BCAS::Decoder::SetCardKey(const u8 *Key)
{
	if (Key != NULL)
		memcpy(CardKey, Key, 8);
}
