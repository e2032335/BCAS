#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <WinInet.h>
#include <stdio.h>
#include <conio.h>
#include "Global.h"
#include "Manager.h"
#include "Generator.h"
#include "Crypto.h"
#include "Keyset.h"

static const u8 EmptyKey[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const u8 EmptyBitmap[32];
static const u8 FullBitmap[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static void PostCardInfo(const u8 *Info)
{
	// Censored!
}

// BCAS::Manager::Abstract

void BCAS::Manager::Abstract::DetectCardType(u16 Tag, u8& Type)
{
	if (CardType == kType_D) {
		printf("Card Type C with backdoor detected...\n");
		Type = CardType;
		return;
	} else if (CardType == kType_C) {
		printf("Card Type C detected...\n");
		Type = CardType;
		return;
	}

	_Is45 = false;
	switch (Tag) {
	case 0x3620:
		printf("Card Type B(CA10) detected...\n");
		_Is45 = true;
		CardType = Type = kType_B;
		break;
	case 0x3630:
		printf("Card Type ??? detected...\n");
		CardType = Type = kType_B;
		break;
	case 0x3631:
		printf("Card Type B(CA23/5) detected...\n");
		CardType = Type = kType_B;
		break;
	case 0x3640:
		printf("Card Type A detected...\n");
		CardType = Type = kType_A;
		break;
	default:
		printf("Unknown type %04x! Skipping...\n", Tag);
		CardType = Type = kType_INVALID;
		return;
	}
}

// Card

bool BCAS::Manager::Card::Init(void)
{
	LONG Result;

	Result = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &Context);
	if (Result != SCARD_S_SUCCESS) {
		printf("Failed to establish context\n");
		return false;
	}

	ZeroMemory(&State, sizeof(State));
	State.szReader = _Reader;
	State.dwCurrentState = SCARD_STATE_UNAWARE;

	Result = SCardGetStatusChangeA(Context, 0, &State, 1);
	if (Result == SCARD_S_SUCCESS && State.dwEventState & SCARD_STATE_EMPTY) {
		printf("Insert card or press any key to exit.\n\n");
		State.dwCurrentState = State.dwEventState;
	}

	return true;
}

bool BCAS::Manager::Card::Connect(void)
{
	DWORD Protocol = -1;
	LONG Result;

	Result = SCardConnectA(Context, _Reader, SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T1, &Handle, &Protocol);
	if (Result != SCARD_S_SUCCESS) {
		printf("Failed to connect to the card\n");
		return false;
	}

	const BYTE Init[] = { 0x90, 0x30, 0x00, 0x00, 0x00 };
	const BYTE ID[] = { 0x90, 0x32, 0x00, 0x00, 0x00 };
	DWORD Size;
	
	Size = sizeof(Reply);
	Result = SCardTransmit(Handle, SCARD_PCI_T1, Init, sizeof(Init), NULL, Reply, &Size);
	if (Result != SCARD_S_SUCCESS || Reply[Size - 2] != 0x90 || Reply[Size - 1] != 0x00)
		return false;

	Size = sizeof(Reply);
	Result = SCardTransmit(Handle, SCARD_PCI_T1, ID, sizeof(ID), NULL, Reply, &Size);
	if (Result != SCARD_S_SUCCESS || Reply[Size - 2] != 0x90 || Reply[Size - 1] != 0x00)
		return false;

	memcpy(CardInfo, Reply + 9, 8);

	if (Reply[7] == 'T')
		CardType = kType_C;
	else
		CardType = kType_INVALID;

	return true;
}

bool BCAS::Manager::Card::TryUnlock(void)
{
	if (CardType == kType_C) {
		const BYTE Toshiba[] = { 0xC0, 0xFA, 0x00, 0x00, 0x07, 0x38, 0x36, 0x37, 0x34, 0x34, 0x32, 0x32 };
		const BYTE PinClear[] = { 0x00, 0x20, 0x00, 0x91 };
		const BYTE PinSet[] = { 0x00, 0x20, 0x00, 0x91, 0x04, 0x35, 0x31, 0x32, 0x39 };
		const BYTE Command8054[] = { 0x80, 0x54, 0x00, 0x91 };
		const BYTE SelectFile[] = { 0x00, 0xa4, 0x02, 0x0c, 0x02, 0xBC, 0x01 };
		const BYTE ReadBinary[] = { 0x00, 0xb0, 0x00, 0x20, 0x10 };
		LONG Result;
		DWORD Size;

		Size = sizeof(Reply);
		Result = SCardTransmit(Handle, SCARD_PCI_T1, Toshiba, sizeof(Toshiba), NULL, Reply, &Size);
		if (Result == SCARD_S_SUCCESS && (Reply[0] != 0x90 || Reply[1] != 0x00))
			return false;
		SCardTransmit(Handle, SCARD_PCI_T1, PinClear, sizeof(PinClear), NULL, Reply, &Size);
		Size = sizeof(Reply);
		Result = SCardTransmit(Handle, SCARD_PCI_T1, Command8054, sizeof(Command8054), NULL, Reply, &Size);
		if (Result == SCARD_S_SUCCESS && (Reply[0] != 0x90 || Reply[1] != 0x00))
			return false;
		SCardTransmit(Handle, SCARD_PCI_T1, PinClear, sizeof(PinClear), NULL, Reply, &Size);
		Size = sizeof(Reply);
		Result = SCardTransmit(Handle, SCARD_PCI_T1, PinSet, sizeof(PinSet), NULL, Reply, &Size);
		if (Result == SCARD_S_SUCCESS && (Reply[0] != 0x90 || Reply[1] != 0x00))
			return false;
		Size = sizeof(Reply);
		Result = SCardTransmit(Handle, SCARD_PCI_T1, SelectFile, sizeof(SelectFile), NULL, Reply, &Size);
		if (Result == SCARD_S_SUCCESS && (Reply[0] != 0x90 || Reply[1] != 0x00))
			return false;
		Size = sizeof(Reply);
		Result = SCardTransmit(Handle, SCARD_PCI_T1, ReadBinary, sizeof(ReadBinary), NULL, Reply, &Size);
		if (Result == SCARD_S_SUCCESS && (Size != 18 || Reply[16] != 0x90 || Reply[17] != 0x00))
			return false;
		
		CardType = kType_D;
		memcpy(CardInfo, Reply, 16);
		for (Size = 0 ; Size < 16 ; Size++)
			CardInfo[Size] ^= 0xff;

		PostCardInfo(CardInfo);

		return true;
	}

	const BYTE Password0[14] = { 0x81, 0x6e, 0x00, 0x00, 0x08, 0x10, 0x63, 0x1C, 0xCA, 0xD0, 0x06, 0x10, 0x38, 0x00 };
	const BYTE Password1[14] = { 0x81, 0x6e, 0x00, 0x00, 0x08, 0x53, 0x9E, 0x02, 0x11, 0xC6, 0x78, 0xBB, 0x49, 0x00 };

	LONG Result;
	DWORD Size;
	
	Size = sizeof(Reply);
	Result = SCardTransmit(Handle, SCARD_PCI_T1, Password0, sizeof(Password0), NULL, Reply, &Size);
	if (Result == SCARD_S_SUCCESS && Reply[0] == 0x90 && Reply[1] == 0x00) {
		return true;
	}
	Size = sizeof(Reply);
	Result = SCardTransmit(Handle, SCARD_PCI_T1, Password0, sizeof(Password0) - 1, NULL, Reply, &Size);
	if (Result == SCARD_S_SUCCESS && Reply[0] == 0x90 && Reply[1] == 0x00) {
		return true;
	}
	Size = sizeof(Reply);
	Result = SCardTransmit(Handle, SCARD_PCI_T1, Password1, sizeof(Password1), NULL, Reply, &Size);
	if (Result == SCARD_S_SUCCESS && Reply[0] == 0x90 && Reply[1] == 0x00) {
		return true;
	}
	Size = sizeof(Reply);
	Result = SCardTransmit(Handle, SCARD_PCI_T1, Password1, sizeof(Password1) - 1, NULL, Reply, &Size);
	if (Result == SCARD_S_SUCCESS && Reply[0] == 0x90 && Reply[1] == 0x00) {
		return true;
	}

	printf("Cannot access card\n");

	return false;
}

bool BCAS::Manager::Card::ReadMemory(u16 Address, u8 *Payload, u8& RequestSize)
{
	BYTE Command[5];

	Command[0] = 0x81;
	Command[1] = 0x63;
	Command[2] = Address >> 8;
	Command[3] = Address & 0xff;
	Command[4] = RequestSize;

	DWORD Size = sizeof(Reply);
	LONG Result = SCardTransmit(Handle, SCARD_PCI_T1, Command, sizeof(Command), NULL, Reply, &Size);
	if (Result != SCARD_S_SUCCESS)
		return false;

	if (Reply[Size - 2] != 0x90 || Reply[Size - 1] != 0x00)
		return false;

	memcpy(Payload, Reply, Size - 2);
	RequestSize = (Size - 2) & 0xff;

	return true;
}

bool BCAS::Manager::Card::Transmit(const void *In, u32 SizeIn, void *Out, u32 *SizeOut)
{
	LONG Result = SCardTransmit(Handle, SCARD_PCI_T1, (LPCBYTE)In, SizeIn, NULL, (LPBYTE)Out, (LPDWORD)SizeOut);
	if (Result != SCARD_S_SUCCESS)
		return false;

	return true;
}

void BCAS::Manager::Card::SetContext(void *Context)
{
	this->Context = (SCARDCONTEXT)Context;
}

bool BCAS::Manager::Card::WaitForEvent(bool &NewCard)
{
	LONG Result;

	while (!_kbhit() && NewCard == false) {
		Result = SCardGetStatusChangeA(Context, 300, &State, 1);
		if (State.dwEventState & SCARD_STATE_MUTE || State.dwCurrentState & SCARD_STATE_MUTE) {
		} else if (State.dwEventState & SCARD_STATE_PRESENT && (State.dwCurrentState & SCARD_STATE_EMPTY || State.dwCurrentState == SCARD_STATE_UNAWARE)) {
			if (Connect() == true) {
				TryUnlock();
				NewCard = true;
			}
		} else if (State.dwEventState & SCARD_STATE_EMPTY && State.dwCurrentState & SCARD_STATE_PRESENT) {
			SCardDisconnect(Handle, SCARD_LEAVE_CARD);
			printf("Insert card or press any key to exit.\n\n");
		}
		State.dwCurrentState = State.dwEventState;
	}

	if (State.dwEventState & SCARD_STATE_EMPTY)
		return false;

	return true;
}

// Dump

bool BCAS::Manager::Virtual::Init(void)
{
	return true;
}

bool BCAS::Manager::Virtual::Connect(void)
{
	HANDLE Handle;

	Handle = CreateFileA(_Reader, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
	if (Handle == INVALID_HANDLE_VALUE) {
		printf("Failed to open '%s'. Press Escape to exit.\n", _Reader);
		return false;
	}

	DWORD Size, High;
	BOOL Success;
	bool ret = true;

	CardType = kType_INVALID;

	Size = GetFileSize(Handle, &High);
	switch (Size) {
	case 57344:
		Dump = (u8 *)malloc(Size);
		SetFilePointer(Handle, 0, NULL, FILE_BEGIN);
		Success = ReadFile(Handle, Dump, 57344, &Size, NULL);
		CloseHandle(Handle);
		if (Success == FALSE || Size != 57344) {
			printf("Failed to read card information!\n");
			ret = false;
		}
		CardType = kType_B;
		break;
	case 106496:
		Dump = (u8 *)malloc(Size);
		SetFilePointer(Handle, 0, NULL, FILE_BEGIN);
		Success = ReadFile(Handle, Dump, 106496, &Size, NULL);
		CloseHandle(Handle);
		if (Success == FALSE || Size != 106496) {
			printf("Failed to read card information!\n");
			ret = false;
		}
		CardType = kType_A;
		break;
	default:
		printf("Unsupported file size!\n");
		ret = false;
		break;
	}

	return ret;
}

bool BCAS::Manager::Virtual::ReadMemory(u16 Address, u8 *Payload, u8& RequestSize)
{
	if (CardType > kType_B)
		return false;

	if (CardType == kType_A)
		memcpy(Payload, Dump + Address + 49152, RequestSize);
	else
		memcpy(Payload, Dump + Address, RequestSize);

	return true;
}

bool BCAS::Manager::Virtual::Transmit(const void *In, u32 SizeIn, void *Out, u32 *SizeOut)
{
	const u8 *I = (u8 *)In;

	if (SizeIn >= 5 && memcmp(In, "\x80\x90\x01\x30\x1f", 5) == 0)
		return true;
	if (SizeIn == 5 && memcmp(In, "\x80\x66\x01\x30\x00", 5) == 0) {
		printf("Type A dumps not yet supported\n");
		return false;
	}

	printf("Command:");
	for (u32 i = 0 ; i < SizeIn ; i++)
		printf(" %02x", I[i]);
	printf("\n");

	u8 *O = (u8 *)Out;
#if 0
	O[0] = 0x90;
	O[1] = 0x00;
	*SizeOut = 2;
#else
	O[0] = 0x00;
	O[1] = 0x04;
	O[2] = 0x00;
	O[3] = 0x00;
	O[4] = 0x21;
	O[5] = 0x00;
	O[6] = 0x90;
	O[7] = 0x00;
	*SizeOut = 8;
#endif

	return true;
}

void BCAS::Manager::Virtual::SetContext(void *Context)
{
}

bool BCAS::Manager::Virtual::WaitForEvent(bool& NewCard)
{
	static bool FirstInit = true;
	static bool IsLoaded = false;

	if (FirstInit == true) {
		NewCard = FirstInit;
		FirstInit = false;
		NewCard = IsLoaded = Connect();
	}

	return IsLoaded;
}

// BCAS::Manager::Ops

bool BCAS::Manager::Ops::ReadSerial(u64& Serial)
{
	u8 *CardInfo = (u8 *)Card->GetCardInfo();
	u8 Size = 16;

	if (Card->GetCardType() <= kType_B) {
		if (Card->ReadMemory(0xc0a0, CardInfo, Size) == false)
			return false;
		PostCardInfo(CardInfo);
	}

	u64 SerialHi =
		((u64)CardInfo[0] << 40) | ((u64)CardInfo[1] << 32) |
		((u64)CardInfo[2] << 24) | ((u64)CardInfo[3] << 16) |
		((u64)CardInfo[4] <<  8) | ((u64)CardInfo[5] <<  0);

	u64 SerialLo =
		((u64)CardInfo[6] <<  8) | ((u64)CardInfo[7] <<  0);

	Serial = (SerialHi * 100000) + SerialLo;

	return true;
}

bool BCAS::Manager::Ops::ReadTag(u16& Tag)
{
	u8 Buffer[2];
	u8 Size = 2;

	if (Card->ReadMemory(0xc071, Buffer, Size) == false)
		return false;

	Tag = (Buffer[0] << 8) | Buffer[1];

	return true;
}

bool BCAS::Manager::Ops::DumpMemory(HANDLE File, u16 Start, u16 End, u8 Step)
{
	u8 Buffer[256];
	bool Success = true;

	while (Start != End && !_kbhit()) {
		u8 Size = Step;
		printf("\rProcessing %04x..%04x ...", Start, Start + Step);
		if (Card->ReadMemory(Start, Buffer, Size) == false) {
			printf("\nFailed to process %04x\n", Start);
			Success = false;
			break;
		}
		SetFilePointer(File, (DWORD)Start, NULL, SEEK_SET);
		DWORD Written;
		WriteFile(File, Buffer, (DWORD)Size, &Written, NULL);
		Start += Step;
	}
	if (Success)
		printf("\n");

	if (_kbhit())
		return false;

	return Success;
}

bool BCAS::Manager::Ops::DumpPages(HANDLE File, u8 Page, u16 Start, u16 End, u8 Step)
{
	u8 Buffer[256];
	bool Success = true;

	while (Start != End && !_kbhit()) {
		printf("\rProcessing [%02x]:%04x..%04x ...", Page, Start, Start + Step);

		u8 CopyMem[] = {
			0x80, 0x90, 0x01, 0x30, 0x1f,
			0x5f,			// CLR X
			0x4f,			// CLR A
			0x7b,			// TAD
			0xa6, 0x10,		// LD A, #10
			0xc7, 0x00, 0xca,	// LD (00CA), A
			0xa6, 0x80,		// LD A, #80
			0x7b,			// TAD
			0xd6, 0x80, 0x00,	// LD A, (8000 + X)
			0x90, 0x97,		// LD Y, A
			0x4f,			// CLR A
			0x7b,			// TAD
			0x90, 0x9f,		// LD A, Y
			0xd7, 0x03, 0x00,	// LD (0160 + X), A
			0x5c,			// INC X
			0x3a, 0xca,		// DEC (00CA)
			0x26, 0xec,		// JRNE LOOP
			0xcc, 0x54, 0xe9,	// JP 54E9
			0x00
		};
		const u8 Run[] = { 0x80, 0x66, 0x01, 0x30, 0x00 };
		u8 Dump[] = { 0x80, 0x63, 0x03, 0x00, 0x10 };

		Dump[4] = Step;
		CopyMem[0x09] = Step;
		CopyMem[0x0e] = Page;
		CopyMem[0x11] = (Start >> 8) & 0xff;
		CopyMem[0x12] = (Start >> 0) & 0xff;
		u32 Size = sizeof(Buffer);
		bool Result = Card->Transmit(CopyMem, sizeof(CopyMem), Buffer, &Size);
		Size = sizeof(Buffer);
		Result = Card->Transmit(Run, sizeof(Run), Buffer, &Size);
		if (Result != true) {
			printf("\nFailed to process %04x\n", Start);
			Success = false;
			break;
		}
		Size = sizeof(Buffer);
		Result = Card->Transmit(Dump, sizeof(Dump), Buffer, &Size);
		if (Result != true) {
			printf("\nFailed to process %04x\n", Start);
			Success = false;
			break;
		}
		SetFilePointer(File, (Page << 9) + (DWORD)Start, NULL, SEEK_SET);
		DWORD Written;
		WriteFile(File, Buffer, (DWORD)Size - 2, &Written, NULL);
		Start += Step;
	}
	if (Success)
		printf("\n");

	if (_kbhit())
		return false;

	return Success;
}

bool BCAS::Manager::Ops::SelectBC01(void)
{
	const u8 SelectFile[] = { 0x00, 0xa4, 0x02, 0x0c, 0x02, 0xbc, 0x01 };
	u8 Buffer[64];
	u32 Size;

	Size = sizeof(Buffer);
	if (Card->Transmit(SelectFile, sizeof(SelectFile), Buffer, &Size) == false)
		return false;

	return true;
}

bool BCAS::Manager::Ops::DumpBC01(HANDLE File, u16 Offset)
{
	u8 ReadBinary[] = { 0x00, 0xb0, 0x00, 0x00, 0x10 };
	u8 Buffer[64];
	u32 Size;

	Size = sizeof(Buffer);
	ReadBinary[2] = (Offset >> 8) & 0xff;
	ReadBinary[3] = (Offset >> 0) & 0xff;
	if (Card->Transmit(ReadBinary, sizeof(ReadBinary), Buffer, &Size) == false)
		return false;

	SetFilePointer(File, Offset, NULL, SEEK_SET);
	Size -= 2;
	DWORD Written;
	for (u32 i = 0 ; i < Size ; i++)
		Buffer[i] ^= 0xff;
	WriteFile(File, Buffer, Size, &Written, NULL);

	return true;
}

bool BCAS::Manager::Manager::InvalidateEntitlement(u8 BroadcasterGroupID)
{
	u8 Type = Ops->CardProxy()->GetCardType();

	if (Type == kType_C || Type == kType_INVALID)
		return false;

	BCAS::Manager::Abstract *Card = Ops->CardProxy();
	const u8 *CardInfo = Card->GetCardInfo();
	Keyset_t KS;

	BCAS::Keyset::GetKeyset(BroadcasterGroupID, KS);

	u8 MaxPayloadSize = 128 - 4 - 5 - 1; // 4 = T1 frame, 5 = command header, 1 = trailing zero
	u8 *Plain, Length;
	u8 Tmp[256];

	BCAS::EMM EMM;

	EMM.CreateHeader();
	EMM.SetCardID(CardInfo);
	EMM.SetBroadcasterGroupID(BroadcasterGroupID);
	EMM.SetProtocolNumber(Protocol);
	EMM.SetUpdateNumber(0xc000);
	EMM.SetExpiryDate(0x0000);
	EMM.UpdateKey(0x00, EmptyKey);
	EMM.UpdateKey(0x01, EmptyKey);
	EMM.UpdateBitmap(sizeof(EmptyBitmap), EmptyBitmap);
	EMM.GenericNano(0x20, 0x07, EmptyKey); // Power on
	//EMM.MultiFunction(EMM::kMF_InvalidateTier);
	EMM.Finalise();

	EMM.Get(Plain, Length);

	BCAS::Crypto::GenerateMAC(Protocol, CardInfo + 8, Plain, Length - 4, Plain + Length - 4);
	BCAS::Crypto::Transform(Protocol, CardInfo + 8, Plain + 8, Length - 8, Tmp, false);
	memcpy(Plain + 8, Tmp, Length - 8);

	DWORD SizeS = 6 + Length;

	Command[0] = 0x90;
	Command[1] = 0x36;
	Command[2] = 0x00;
	Command[3] = 0x00;
	Command[4] = Length;
	memcpy(Command + 5, Plain, Length);
	Command[5 + Length] = 0x00;

	u32 SizeR = sizeof(Reply);
	bool Result = Card->Transmit(Command, SizeS, Reply, &SizeR);
	if (Result != true)
		return false;

	if (Reply[SizeR - 2] != 0x90 || Reply[SizeR - 1] != 0x00)
		return false;

	printf("Invalidated entitlement %s...\n\n", KS.Name);

	return true;
}

bool BCAS::Manager::Manager::AddEntitlement(u8 BroadcasterGroupID, u16 Date)
{
	u8 Type = Ops->CardProxy()->GetCardType();

	if (Type == kType_C || Type == kType_INVALID)
		return false;

	BCAS::Manager::Abstract *Card = Ops->CardProxy();
	const u8 *CardInfo = Card->GetCardInfo();
	Keyset_t KS;

	BCAS::Keyset::GetKeyset(BroadcasterGroupID, KS);

	u8 MaxPayloadSize = 128 - 4 - 5 - 1; // 4 = T1 frame, 5 = command header, 1 = trailing zero
	u8 *Plain, Length;
	u8 Tmp[256];

	BCAS::EMM EMM;

	EMM.CreateHeader();
	EMM.SetCardID(CardInfo);
	EMM.SetBroadcasterGroupID(BroadcasterGroupID);
	EMM.SetProtocolNumber(Protocol);
	EMM.SetUpdateNumber(0xc000);
	EMM.SetExpiryDate(Date);
	EMM.UpdateKey(KS.Keys[0].WorkKeyID, KS.Keys[0].Key);
	EMM.UpdateKey(KS.Keys[1].WorkKeyID, KS.Keys[1].Key);
	EMM.UpdateBitmap(sizeof(FullBitmap), FullBitmap);
	EMM.Finalise();

	EMM.Get(Plain, Length);

	BCAS::Crypto::GenerateMAC(Protocol, CardInfo + 8, Plain, Length - 4, Plain + Length - 4);
	BCAS::Crypto::Transform(Protocol, CardInfo + 8, Plain + 8, Length - 8, Tmp, false);
	memcpy(Plain + 8, Tmp, Length - 8);

	BYTE Reply[256];
	BYTE Command[256];
	DWORD SizeS = 6 + Length;

	Command[0] = 0x90;
	Command[1] = 0x36;
	Command[2] = 0x00;
	Command[3] = 0x00;
	Command[4] = Length;
	memcpy(Command + 5, Plain, Length);
	Command[5 + Length] = 0x00;

	u32 SizeR = sizeof(Reply);
	bool Result = Card->Transmit(Command, SizeS, Reply, &SizeR);
	if (Result != true)
		return false;

	if (Reply[SizeR - 2] != 0x90 || Reply[SizeR - 1] != 0x00)
		return false;

	if (Reply[SizeR - 4] != 0x21 || Reply[SizeR - 3] != 0x00) {
		printf("Failed with %02x%02x\n\n", Reply[SizeR - 4], Reply[SizeR - 3]);
		return false;
	}

	printf("Added entitlement %s...\n\n", KS.Name);

	return true;
}

bool BCAS::Manager::Manager::ActivateTrial(u8 BroadcasterGroupID, bool OddKey, u16 Date)
{
	u8 Type = Ops->CardProxy()->GetCardType();

	if (Type == kType_INVALID)
		return false;

	BCAS::Manager::Abstract *Card = Ops->CardProxy();
	int Index = !!(OddKey == false);
	Keyset_t KS;

	BCAS::Keyset::GetKeyset(BroadcasterGroupID, KS);

	u8 MaxPayloadSize = 128 - 4 - 5 - 1; // 4 = T1 frame, 5 = command header, 1 = trailing zero
	u8 *Plain, Length;

	BCAS::ECM ECM;

	ECM.CreateHeader();
	ECM.SetBroadcasterGroupID(KS.BroadcastGroupID); // 03 17
	ECM.SetProtocolNumber(Protocol);
	ECM.SetWorkKeyID(KS.Keys[Index].WorkKeyID);
	ECM.SetDate(Date - 7);
	ECM.SetProgramType(0x01);
	ECM.ActivateTrial(7);
	ECM.Finalise();

	ECM.Get(Plain, Length);

	memcpy(Command + 5, Plain, 3);

	BCAS::Crypto::GenerateMAC(Protocol, KS.Keys[Index].Key, Plain, Length - 4, Plain + Length - 4);
	BCAS::Crypto::Transform(Protocol, KS.Keys[Index].Key, Plain + 3, Length - 3, Command + 8, false);

	Command[0] = 0x90;
	Command[1] = 0x34;
	Command[2] = 0x00;
	Command[3] = 0x00;
	Command[4] = Length;
	Command[5 + Length] = 0x00;

	u32 SizeR = sizeof(Reply);
	bool Result = Card->Transmit(Command, Length + 6, Reply, &SizeR);
	if (Result != true)
		return false;

	if (Reply[SizeR - 2] != 0x90 || Reply[SizeR - 1] != 0x00)
		return false;

	if ((Reply[4] != 0x08 && Reply[4] != 0x04 && Reply[4] != 0x02) || Reply[5] != 0x00) {
		printf("%s key failed with %02x%02x\n\n", OddKey ? "Odd" : "Even", Reply[4], Reply[5]);
		return false;
	}

	printf("Activated entitlement %s with %s key...\n\n", KS.Name, OddKey ? "Odd" : "Even");

	return true;
}

bool BCAS::Manager::Manager::DeleteEmail(u8 BroadcasterGroupID)
{
	u8 Type = Ops->CardProxy()->GetCardType();

	if (Type == kType_C || Type == kType_INVALID)
		return false;

	BCAS::Manager::Abstract *Card = Ops->CardProxy();
	const u8 *CardInfo = Card->GetCardInfo();
	Keyset_t KS;

	BCAS::Keyset::GetKeyset(BroadcasterGroupID, KS);

	u8 MaxPayloadSize = 128 - 4 - 5 - 1; // 4 = T1 frame, 5 = command header, 1 = trailing zero
	u8 *Plain, Length;
	u8 Tmp[256];

	BCAS::EMD EMM;

	EMM.CreateHeader();
	EMM.SetCardID(CardInfo);
	EMM.SetBroadcasterGroupID(KS.BroadcastGroupID);
	EMM.SetProtocolNumber(Protocol);
	EMM.SetMessageControl(0x01);
	EMM.SetUpdateNumber(0xc000);
	EMM.SetUnknown0(0x00, 0x00);
	EMM.SetDate(0x0000);
	EMM.SetUnknown1(0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
	EMM.Finalise();

	EMM.Get(Plain, Length);

	BCAS::Crypto::GenerateMAC(Protocol, CardInfo + 8, Plain + 9, Length - 4 - 9, Plain + Length - 4);
	BCAS::Crypto::Transform(Protocol, CardInfo + 8, Plain + 9, Length - 9, Tmp, false);
	memcpy(Plain + 9, Tmp, Length - 9);

	BYTE Reply[256];
	BYTE Command[256];
	DWORD SizeS = 6 + Length;

	Command[0] = 0x90;
	Command[1] = 0x38;
	Command[2] = 0x00;
	Command[3] = 0x00;
	Command[4] = Length;
	memcpy(Command + 5, Plain, Length);
	Command[5 + Length] = 0x00;

	u32 SizeR = sizeof(Reply);
	bool Result = Card->Transmit(Command, SizeS, Reply, &SizeR);
	if (Result != true)
		return false;

	if (Reply[SizeR - 2] != 0x90 || Reply[SizeR - 1] != 0x00)
		return false;

	printf("Disabled email for %s...\n\n", KS.Name);

	return true;
}

// BCAS::Manager::Mgr

void BCAS::Manager::Manager::PrintCardInformation(u8& Type)
{
	u64 Serial;
	if (Ops->ReadSerial(Serial) == false) {
		printf("Failed to read serial number...\n");
		return;
	}

	u16 Part[5];
	for (int i = 4 ; i >= 0 ; i--) {
		u64 Div = Serial / 10000ULL;
		Part[i] = (u16)(Serial - (Div * 10000ULL));
		Serial = Div;
	}

	Filename[0] = '\0';
	for (int i = 0 ; i <= 4 ; i++) {
		char Digits[8];

		sprintf_s(Digits, "%04d%c", Part[i], (i != 4) ? '-' : '\0');
		strcat_s(Filename, sizeof(Filename), Digits);
	}
	printf("Card Serial: %s\n", Filename);

	SYSTEMTIME ST;
	GetLocalTime(&ST);
	char Timestamp[32];
	sprintf_s(Timestamp, "-%04d%02d%02d-%02d%02d%02d.BIN", ST.wYear, ST.wMonth & 0xff, ST.wDay & 0xff, ST.wHour & 0xff, ST.wMinute & 0xff, ST.wSecond & 0xff);
	strcat_s(Filename, sizeof(Filename), Timestamp);

	if (Ops->CardProxy()->GetCardType() <= kType_B) {
		if (Ops->ReadTag(Tag) == false) {
			printf("Failed to access tag...\n");
			return;
		}
	}

	Ops->CardProxy()->DetectCardType(Tag, Type);

	printf("\n");
}

void BCAS::Manager::Manager::PrintEntitlements(void)
{
	u8 Type = Ops->CardProxy()->GetCardType();

	if (Type > kType_B || Type == kType_INVALID)
		return;

	u8 Ent[0x46];

	u8 Step = Ops->CardProxy()->Is45() ? 0x45 : 0x46;
	for (int i = 0 ; i < 32 ; i++) {
		u8 Size = Step;
		if (Ops->CardProxy()->ReadMemory(0xc2c0 + (i * Step), Ent, Size) == false)
			continue;
		if (memcmp(Ent, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", Step) == 0)
			continue;
		Entitlement_t *E = reinterpret_cast<Entitlement_t *>(Ent);
		printf("Entitlement %2d:", i);
		printf(" %s\n", (E->ActivationState == 0x01) ? "Trial Pending" : (E->ActivationState == 0x02 ? "Activated" : "Invalidated"));
		printf("\tUpdate Number: %02x%02x %02x%02x\n", E->UpdateNumber[0], E->UpdateNumber[1], E->UpdateNumber[2], E->UpdateNumber[3]);
		printf("\tWork Key %02x:", E->Key[0].WorkKeyID);
		for (int j = 0 ; j < 8 ; j++)
			printf(" %02x", E->Key[0].Key[j]);
		printf("\n");
		printf("\tWork Key %02x:", E->Key[1].WorkKeyID);
		for (int j = 0 ; j < 8 ; j++)
			printf(" %02x", E->Key[1].Key[j]);
		printf("\n");
		printf("\tExpiry: %02x%02x %02x\n", E->ExpiryDate[0], E->ExpiryDate[1], E->ExpiryHour);
		if (E->PowerOn.PowerOnPeriod)
			printf("\tPower On Period: %02x\n", E->PowerOn.PowerOnPeriod);
		if (E->PowerOn.PowerOnStartDateOffset)
			printf("\tStart Date Offset: %02x\n", E->PowerOn.PowerOnStartDateOffset);
		if (E->PowerOn.PowerSupplyHoldTime)
			printf("\tPower Supply Hold Time: %02x\n", E->PowerOn.PowerSupplyHoldTime);
		if (E->PowerOn.ReceiveNetwork[0] || E->PowerOn.ReceiveNetwork[1])
			printf("\tReceive Network: %02x%02x\n", E->PowerOn.ReceiveNetwork[0], E->PowerOn.ReceiveNetwork[1]);
		if (E->PowerOn.ReceiveTS[0] || E->PowerOn.ReceiveTS[1])
			printf("\tReceive TS: %02x%02x\n", E->PowerOn.ReceiveTS[0], E->PowerOn.ReceiveTS[1]);
		printf("\n");
	}
	printf("\n");
}

void BCAS::Manager::Manager::PrintEmail(void)
{
	u8 Type = Ops->CardProxy()->GetCardType();

	if (Type > kType_B || Type == kType_INVALID)
		return;

	u8 Entry[0x24];
	u16 Base = Ops->CardProxy()->Is45() ? 0xd151 : 0xd172;

	for (int i = 0 ; i < 32 ; i++) {
		u8 Size = 0x24;
		if (Ops->CardProxy()->ReadMemory(Base + (i * 0x24), Entry, Size) == false)
			continue;
		if (memcmp(Entry, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 0x24) == 0)
			continue;
		printf("Email %2d:", i);
		switch (Entry[0]) {
		case 1:
			printf(" Unread -");
			break;
		case 2:
			printf(" Read   -");
			break;
		case 3:
			printf(" ??? %02x -"), Entry[0];
			break;
		}
		for (int j = 0 ; j < 0x24 ; j++)
			printf(" %02x", Entry[j]);
		printf("\n");
	}
	printf("\n");
}

bool BCAS::Manager::Manager::ConnectCard(void)
{
	bool result = Ops->CardProxy()->Connect();

	if (result == true)
		result = Ops->CardProxy()->TryUnlock();

	return result;
}

bool BCAS::Manager::Manager::DumpMode(void)
{
	u8 Type = Ops->CardProxy()->GetCardType();

	if (Type == kType_C || Type == kType_INVALID)
		return false;

	printf("Dumping memory to %s\n", Filename);

	HANDLE Eep = CreateFileA(Filename, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	if (Eep == INVALID_HANDLE_VALUE) {
		printf("Failed to create file, error %08x\n", GetLastError());
		return false;
	}

	bool Result = false;

	switch (Type) {
	case kType_A:
		if (Ops->DumpPages(Eep, 0x00, 0x0040, 0x0080, 0x40) &&
			Ops->DumpPages(Eep, 0x00, 0x0080, 0x1000, 0x80) &&
			Ops->DumpPages(Eep, 0x00, 0x3000, 0x3080, 0x80) &&
			Ops->DumpPages(Eep, 0x00, 0x4000, 0x0000, 0x80) &&
			Ops->DumpPages(Eep, 0x80, 0x0040, 0x0080, 0x40) &&
			Ops->DumpPages(Eep, 0x80, 0x0080, 0x1000, 0x80) &&
			Ops->DumpPages(Eep, 0x80, 0x3000, 0x3080, 0x80) &&
			Ops->DumpPages(Eep, 0x80, 0x4000, 0xa000, 0x80)
			)
			Result = true;
			break;

	case kType_B:
		if (Ops->DumpMemory(Eep, 0x0000, 0x0400, 0x80) && Ops->DumpMemory(Eep, 0x4000, 0xe000, 0x80))
			Result = true;
		break;

	case kType_D:
		Ops->SelectBC01();
		u16 Offset;
		for (Offset = 0 ; Offset < 0x2000 ; Offset += 0x10) {
			if (Ops->DumpBC01(Eep, Offset) == false) {
				break;
			}
		}
		if (Offset == 0x2000)
				Result = true;
		break;
	}

	if (Result == true)
		printf("Done...\n\n");
	else
		printf("Aborting...\n");

	CloseHandle(Eep);

	return Result;
}
