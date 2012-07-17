#ifndef BCAS_MANAGER_H
#define BCAS_MANAGER_H

#include "Keyset.h"

#pragma pack(push)
#pragma pack(1)

typedef struct {
	u8 PowerOnStartDateOffset;
	u8 PowerOnPeriod;
	u8 PowerSupplyHoldTime;
	u8 ReceiveNetwork[2];
	u8 ReceiveTS[2];
} PowerOn_t;

typedef struct {
	// 00
	u8 ActivationState;
	// 01
	u8 UpdateNumber[4];
	// 05
	Key_t Key[2];
	// 17
	u8 Bouquet[32];
	// 37
	u8 Unknown1[3]; //0x00, 0x00, 0xff,
	// 3a
	u8 ExpiryDate[2]; // 0xff, 0xff,
	// 3c
	u8 ExpiryHour; // 0x00,
	// 3d
	PowerOn_t PowerOn;
	// 44
	u8 LRC_CA10; // 0x00,
	u8 LRC_CA25; // 0xd8,
} Entitlement_t;

typedef struct {
	TCHAR *Name;
	u8 Index;
	u8 Entitlement[0x46];
} EntitlementInfo_t;

enum {
	kType_INVALID,
	kType_A,
	kType_B,
	kType_C,
	kType_D,
};

namespace BCAS {
	namespace Manager {
		class Abstract {
		protected:
			bool _Is45;
			u8 CardInfo[16];
			u8 CardType;
			const char *_Reader;
			u8 Command[256];

		public:
			virtual bool Init(void) = 0;
			virtual bool Connect(void) = 0;
			virtual bool TryUnlock(void) = 0;
			virtual bool ReadMemory(u16 Address, u8 *Payload, u8& RequestSize) = 0;

			virtual bool Transmit(const void *In, u32 SizeIn, void *Out, u32 *SizeOut) = 0;
			const u8 *GetCardInfo(void) { return CardInfo; }
			bool Is45(void) { return _Is45; }
			u8 GetCardType(void) { return CardType; }
			void DetectCardType(u16 Tag, u8& Type);
			void SetReader(const char *Reader) { _Reader = Reader; }
			virtual void SetContext(void *Context) = 0;
			virtual bool WaitForEvent(bool& NewCard) = 0;
		};

		class Card : public Abstract {
		private:
			SCARDCONTEXT Context;
			SCARDHANDLE Handle;
			SCARD_READERSTATEA State;
			BYTE Reply[256];

		public:
			bool Init(void);
			bool Connect(void);
			bool TryUnlock(void);
			bool ReadMemory(u16 Address, u8 *Payload, u8& RequestSize);
			bool Transmit(const void *In, u32 SizeIn, void *Out, u32 *SizeOut);
			void SetContext(void *Context);
			bool WaitForEvent(bool& NewCard);
		};

		class Virtual : public Abstract {
		private:
			u8 *Dump;

		public:
			bool Init(void);
			bool Connect(void);
			void Disconnect(void);
			bool TryUnlock(void) { return true; }
			bool ReadMemory(u16 Address, u8 *Payload, u8& RequestSize);
			bool Transmit(const void *In, u32 SizeIn, void *Out, u32 *SizeOut);
			void SetContext(void *Context);
			bool WaitForEvent(bool& NewCard);
		};

		class Ops {
		private:
			Abstract *Card;
			u8 Command[256];
			u8 Reply[256];

		public:
			void SetCard(Abstract *In) { Card = In; }
			bool ReadSerial(u64& Serial);
			bool ReadTag(u16& Tag);
			bool DumpMemory(HANDLE File, u16 Start, u16 End, u8 Step);
			bool DumpPages(HANDLE File, u8 Page, u16 Start, u16 End, u8 Step);
			bool SelectBC01(void);
			bool DumpBC01(HANDLE File, u16 Offset);
			Abstract *CardProxy(void) { return Card; };
		};

		class Manager {
		private:
			Ops *Ops;
			char Filename[64];
			u16 Tag;
			static const u8 Protocol = 0x44;
			u8 Command[256];
			u8 Reply[256];

		public:
			Manager(BCAS::Manager::Ops *O) { Ops = O; }

			bool AddEntitlement(u8 BroadcasterGroupID, u16 Date);
			bool InvalidateEntitlement(u8 BroadcasterGroupID);
			bool ActivateTrial(u8 BroadcasterGroupID, bool OddKey, u16 Date);
			bool DeleteEmail(u8 BroadcasterGroupID);
			bool ConnectCard(void);
			void PrintCardInformation(u8& Type);
			void PrintEntitlements(void);
			void PrintEmail(void);
			bool DumpMode(void);
		};
	}
}

#pragma pack(pop)

#endif
