#include <string.h>
#include "Global.h"
#include "Generator.h"

BCAS::Gen::Error BCAS::EMM::CreateHeader(void)
{
	if (sizeof(EMM::Header_t) + sizeof(Gen::MAC_t) > MaxLength)
		return Gen::OutOfSpace;

	Position = (u8)sizeof(Header_t);

	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);

	memset(EMM, 0, sizeof(Header_t));

	EMM->Length = sizeof(EMM::Header_t) - sizeof(EMM->CardID) - sizeof(EMM->Length);

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMM::SetCardID(const u8 *ID)
{
	if (ID == NULL)
		return Gen::NullPointer;

	EMM::Header_t *EMM = reinterpret_cast<EMM::Header_t *>(Buffer);

	memcpy(EMM->CardID, ID, sizeof(EMM->CardID));

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMM::SetProtocolNumber(u8 ProtocolNumber)
{
	EMM::Header_t *EMM = reinterpret_cast<EMM::Header_t *>(Buffer);

	EMM->ProtocolNumber = ProtocolNumber;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMM::SetBroadcasterGroupID(u8 BroadcasterGroupID)
{
	EMM::Header_t *EMM = reinterpret_cast<EMM::Header_t *>(Buffer);

	EMM->BroadcasterGroupID = BroadcasterGroupID;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMM::SetUpdateNumber(u16 UpdateNumber)
{
	EMM::Header_t *EMM = reinterpret_cast<EMM::Header_t *>(Buffer);

	EMM->UpdateNumber[0] = (UpdateNumber >> 8) & 0xff;
	EMM->UpdateNumber[1] = (UpdateNumber >> 0) & 0xff;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMM::SetExpiryDate(u16 ExpiryDate)
{
	EMM::Header_t *EMM = reinterpret_cast<EMM::Header_t *>(Buffer);

	EMM->ExpiryDate[0] = (ExpiryDate >> 8) & 0xff;
	EMM->ExpiryDate[1] = (ExpiryDate >> 0) & 0xff;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMM::UpdateKey(u8 Index, const u8 *Key)
{
	if (Key == NULL)
		return Gen::NullPointer;

	if (Position + sizeof(UpdateTierKey_t) + sizeof(Gen::MAC_t) > MaxLength)
		return Gen::OutOfSpace;

	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);
	UpdateTierKey_t *K = reinterpret_cast<UpdateTierKey_t *>(Buffer + Position);

	K->Nano = kUpdateKey;
	K->Length = sizeof(K->Index) + sizeof(K->Key);
	K->Index = Index;
	memcpy(K->Key, Key, sizeof(K->Key));

	EMM->Length += sizeof(UpdateTierKey_t);
	Position += sizeof(UpdateTierKey_t);

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMM::UpdateBitmap(u8 Length, const u8 *Bitmap)
{
	if (Bitmap == NULL)
		return Gen::NullPointer;

	if (Length > 32)
		return Gen::InvalidArgument;

	if (Position + sizeof(UpdateTierBitmap_t) + sizeof(Gen::MAC_t) > MaxLength)
		return Gen::OutOfSpace;

	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);
	UpdateTierBitmap_t *T = reinterpret_cast<UpdateTierBitmap_t *>(Buffer + Position);

	T->Nano = kUpdateBitmap;
	T->Length = Length;
	memcpy(T->Bitmap, Bitmap, Length);

	EMM->Length += sizeof(Gen::Nano_t) + Length;
	Position += sizeof(Gen::Nano_t) + Length;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMM::GenericNano(u8 Nano, u8 Length, const u8 *Payload)
{
	if (Payload == NULL)
		return Gen::NullPointer;

	if (Position + sizeof(Gen::Nano_t) + Length > MaxLength)
		return Gen::OutOfSpace;

	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);
	Gen::Nano_t *N = reinterpret_cast<Gen::Nano_t *>(Buffer + Position);

	N->Nano = Nano;
	N->Length = Length;
	memcpy(N->Payload, Payload, Length);

	EMM->Length += sizeof(Gen::Nano_t) + Length;
	Position += sizeof(Gen::Nano_t) + Length;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMM::MultiFunction(u8 Function)
{
	if (Position + sizeof(MultiFunction_t) + sizeof(Gen::MAC_t) > MaxLength)
		return Gen::OutOfSpace;

	MultiFunction_t *M = reinterpret_cast<MultiFunction_t *>(Buffer + Position);

	M->Nano = kMultiFunction;
	M->Length = sizeof(M->Function);
	M->Function = Function;

	Position += sizeof(MultiFunction_t);

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMM::Finalise(void)
{
	if (Position + sizeof(Gen::MAC_t) > MaxLength)
		return Gen::OutOfSpace;

	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);
	
	memset(Buffer + Position, 0x00, sizeof(Gen::MAC_t));

	EMM->Length += sizeof(Gen::MAC_t);
	Position += sizeof(Gen::MAC_t);

	return Gen::OK;
}

void BCAS::EMM::Get(u8 *& Payload, u8 & Size)
{
	Payload = Buffer;
	Size = Position;
}

BCAS::Gen::Error BCAS::ECM::CreateHeader(void)
{
	if (sizeof(Header_t) + sizeof(Gen::MAC_t) > MaxLength)
		return Gen::OutOfSpace;

	Position = (u8)sizeof(Header_t);

	Header_t *ECM = reinterpret_cast<Header_t *>(Buffer);

	memset(ECM, 0, sizeof(Header_t));
	ECM->ProtocolNumber = 0x00;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::SetProtocolNumber(u8 ProtocolNumber)
{
	Header_t *ECM = reinterpret_cast<Header_t *>(Buffer);

	ECM->ProtocolNumber = ProtocolNumber;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::SetBroadcasterGroupID(u8 BroadcasterGroupID)
{
	Header_t *ECM = reinterpret_cast<Header_t *>(Buffer);

	ECM->BroadcasterGroupID = BroadcasterGroupID;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::SetWorkKeyID(u8 WorkKeyID)
{
	Header_t *ECM = reinterpret_cast<Header_t *>(Buffer);

	ECM->WorkKeyID = WorkKeyID;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::SetOddKey(const u8 *OddKey)
{
	if (OddKey == NULL)
		return Gen::NullPointer;

	Header_t *ECM = reinterpret_cast<Header_t *>(Buffer);

	memcpy(ECM->OddKey, OddKey, 8);

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::SetEvenKey(const u8 *EvenKey)
{
	if (EvenKey == NULL)
		return Gen::NullPointer;

	Header_t *ECM = reinterpret_cast<Header_t *>(Buffer);

	memcpy(ECM->EvenKey, EvenKey, 8);

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::SetProgramType(u8 ProgramType)
{
	Header_t *ECM = reinterpret_cast<Header_t *>(Buffer);

	ECM->ProgramType = ProgramType;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::SetDate(u16 Date)
{
	Header_t *ECM = reinterpret_cast<Header_t *>(Buffer);

	ECM->Date[0] = (Date >> 8) & 0xff;
	ECM->Date[1] = (Date >> 0) & 0xff;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::SetTime(const u8 *Time)
{
	if (Time == NULL)
		return Gen::NullPointer;

	Header_t *ECM = reinterpret_cast<Header_t *>(Buffer);

	memcpy(ECM->Time, Time, 3);

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::SetRecordingControl(u8 RecordingControl)
{
	Header_t *ECM = reinterpret_cast<Header_t *>(Buffer);

	ECM->RecordingControl = RecordingControl;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::ActivateTrial(u8 Days)
{
	ActivateTrial_t *A = reinterpret_cast<ActivateTrial_t *>(Buffer + Position);

	A->Nano = ECM::kActivateTrial;
	A->Length = sizeof(A->Days);
	A->Days = Days;

	Position += sizeof(ActivateTrial_t);

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::CheckBitmap(u8 Length, const u8 *Bitmap)
{
	if (Length > 32)
		return Gen::InvalidArgument;

	if (Position + sizeof(CheckBitmap_t) + sizeof(Gen::MAC_t) > MaxLength)
		return Gen::OutOfSpace;

	CheckBitmap_t *T = reinterpret_cast<CheckBitmap_t *>(Buffer + Position);

	T->Nano = kCheckBitmap;
	T->Length = Length;
	memcpy(T->Bitmap, Bitmap, Length);

	Position += sizeof(Nano_t) + Length;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::InvalidateTier(const u8 *CardID)
{
	if (CardID == NULL)
		return Gen::NullPointer;

	if (Position + sizeof(InvalidateTier_t) + sizeof(Gen::MAC_t) > MaxLength)
		return Gen::OutOfSpace;

	InvalidateTier_t *I = reinterpret_cast<InvalidateTier_t *>(Buffer + Position);

	I->Nano = kInvalidateTier;
	I->Length = sizeof(I->CardID);
	memcpy(I->CardID, CardID, sizeof(I->CardID));

	Position += sizeof(InvalidateTier_t);

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::MultiFunction(u8 Function)
{
	if (Position + sizeof(MultiFunction_t) + sizeof(Gen::MAC_t) > MaxLength)
		return Gen::OutOfSpace;

	MultiFunction_t *M = reinterpret_cast<MultiFunction_t *>(Buffer + Position);

	M->Nano = kMultiFunction;
	M->Length = sizeof(M->Function);
	M->Function = Function;

	Position += sizeof(MultiFunction_t);

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::GenericNano(u8 Nano, u8 Length, const u8 *Payload)
{
	if (Length > 0 && Payload == NULL)
		return Gen::NullPointer;

	if (Position + sizeof(Nano_t) + Length > MaxLength)
		return Gen::OutOfSpace;

	Nano_t *N = reinterpret_cast<Nano_t *>(Buffer + Position);

	N->Nano = Nano;
	N->Length = Length;
	if (Length > 0)
		memcpy(N->Payload, Payload, Length);

	Position += sizeof(Nano_t) + Length;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::ECM::Finalise(void)
{
	if (Position + sizeof(Gen::MAC_t) > MaxLength)
		return Gen::OutOfSpace;

	memset(Buffer + Position, 0x00, sizeof(Gen::MAC_t));

	Position += sizeof(Gen::MAC_t);

	return Gen::OK;
}

void BCAS::ECM::Get(u8 *& Payload, u8 & Size)
{
	Payload = Buffer;
	Size = Position;
}

// EMM Individual Message

BCAS::Gen::Error BCAS::EMD::CreateHeader(void)
{
	if (sizeof(Header_t) + sizeof(Gen::MAC_t) > MaxLength)
		return Gen::OutOfSpace;

	Position = (u8)sizeof(Header_t);

	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);

	memset(EMM, 0, sizeof(Header_t));

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMD::SetCardID(const u8 *ID)
{
	if (ID == NULL)
		return Gen::NullPointer;

	EMD::Header_t *EMM = reinterpret_cast<EMD::Header_t *>(Buffer);

	memcpy(EMM->CardID, ID, sizeof(EMM->CardID));

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMD::SetProtocolNumber(u8 ProtocolNumber)
{
	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);

	EMM->ProtocolNumber = ProtocolNumber;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMD::SetBroadcasterGroupID(u8 BroadcasterGroupID)
{
	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);

	EMM->BroadcasterGroupID = BroadcasterGroupID;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMD::SetMessageControl(u8 MessageControl)
{
	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);

	EMM->MessageControl = MessageControl;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMD::SetUpdateNumber(u16 UpdateNumber)
{
	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);

	EMM->UpdateNumber[0] = (UpdateNumber >> 8) & 0xff;
	EMM->UpdateNumber[1] = (UpdateNumber >> 0) & 0xff;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMD::SetUnknown0(u8 U0, u8 U1)
{
	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);

	EMM->Unknown0[0] = U0;
	EMM->Unknown0[1] = U1;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMD::SetDate(u16 Date)
{
	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);

	EMM->Date[0] = (Date >> 8) & 0xff;
	EMM->Date[1] = (Date >> 0) & 0xff;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMD::SetUnknown1(u8 U0, u8 U1, u8 U2, u8 U3, u8 U4, u8 U5)
{
	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);

	EMM->Unknown1[0] = U0;
	EMM->Unknown1[1] = U1;
	EMM->Unknown1[2] = U2;
	EMM->Unknown1[3] = U3;
	EMM->Unknown1[4] = U4;
	EMM->Unknown1[5] = U5;

	return Gen::OK;
}

BCAS::Gen::Error BCAS::EMD::Finalise(void)
{
	if (Position + sizeof(Gen::MAC_t) > MaxLength)
		return Gen::OutOfSpace;

	Header_t *EMM = reinterpret_cast<Header_t *>(Buffer);

	memset(Buffer + Position, 0x00, sizeof(Gen::MAC_t));

	Position += sizeof(Gen::MAC_t);

	return Gen::OK;
}

void BCAS::EMD::Get(u8 *& Payload, u8 & Size)
{
	Payload = Buffer;
	Size = Position;
}
