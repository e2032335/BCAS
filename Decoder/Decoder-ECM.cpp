#include <string.h>
#include "Global.h"
#include "Decoder.h"
#include "Crypto.h"
#include "Keyset.h"

typedef struct {
	// 0x00
	u8 ProtocolNumber;
	// 0x01
	u8 BroadcasterGroupID;
	// 0x02
	u8 WorkKeyID;
	// 0x03
	u8 ScramblingKeyOdd[8];
	// 0x0b
	u8 ScramblingKeyEven[8];
	// 0x13
	u8 ProgramType;
	// 0x14
	u8 Date[2];
	// 0x16
	u8 Time[3];
	// 0x19
	u8 RecordingControl;
} ECM_t;

typedef u8 CRC32_t[4];
typedef u8 MAC_t[4];

static s32 DecryptECM(const ECM_t *ECM, u32 Size, u8 *Output, u8 *Key)
{
	if (ECM == NULL || Size < sizeof(ECM_t) + sizeof(MAC_t))
		return -1;

	BCAS::Keyset::GetKey(ECM->BroadcasterGroupID, ECM->WorkKeyID, Key);

	*Output++ = ECM->ProtocolNumber;
	*Output++ = ECM->BroadcasterGroupID;
	*Output++ = ECM->WorkKeyID;

	BCAS::Crypto::Transform(ECM->ProtocolNumber, Key, ECM->ScramblingKeyOdd, Size, Output, true);

	return 0;
}

s32 BCAS::Decoder::DecodeECM(const u8 *Payload, u32 Size, u8 *Keys, u8 *Nanos)
{
	u8 Plaintext[256];
	u8 Key[8];
	u8 MAC[4];

	if (Payload == NULL || Size < sizeof(ECM_t) + sizeof(MAC_t))
		return -1;

	const ECM_t *ECM = reinterpret_cast<const ECM_t *>(Payload);

	if (DecryptECM(ECM, Size, Plaintext, Key) < 0) {
		if (Keys != NULL)
			memset(Keys, 0, 16);

		return -2;
	}

	Size -= sizeof(MAC_t);
	BCAS::Crypto::GenerateMAC(ECM->ProtocolNumber, Key, Plaintext, Size, MAC);
	if (memcmp(MAC, Plaintext + Size, sizeof(MAC_t)))
		return -3;

	ECM = reinterpret_cast<const ECM_t *>(Plaintext);

	if (Keys != NULL)
		memcpy(Keys, ECM->ScramblingKeyOdd, 16);
	if (Nanos != NULL)
		memcpy(Nanos, ECM + 1, Size - sizeof(ECM_t));

	return 0;
}
