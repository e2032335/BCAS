#ifndef BCAS_GENERATOR_H
#define BCAS_GENERATOR_H

#pragma warning(push)

#pragma warning(disable:4200)

namespace BCAS {
	namespace Gen {
		enum Error {
			OK,
			OutOfSpace,
			NullPointer,
			InvalidArgument,
		};

		typedef struct {
			u8 Nano;
			u8 Length;
			u8 Payload[0];
		} Nano_t;

		typedef struct {
			u8 MAC[4];
		} MAC_t;
	}

	class EMM {
	private:
		u8 Position;
		static const u8 MaxLength = 255;
		u8 Buffer[256];

		typedef struct {
			u8 Nano;
			u8 Length;
			u8 Index;
			u8 Key[8];
		} UpdateTierKey_t;

		typedef struct {
			u8 Nano;
			u8 Length;
			u8 Bitmap[32];
		} UpdateTierBitmap_t;

		typedef struct {
			u8 Nano;
			u8 Length;
			u8 Function;
		} MultiFunction_t;

	public:
		enum {
			kUpdateKey = 0x10,
			kUpdateBitmap = 0x11,
			kMultiFunction = 0x21,
		};

		enum kMFNanos {
			kMF_InvalidateTier = 0x01,
			kMF_ResetUpdateNumbers = 0x02,
			kMF_ResetTrial = 0xff,
		};

		typedef struct {
			u8 CardID[6];
			u8 Length;
			u8 ProtocolNumber;
			u8 BroadcasterGroupID;
			u8 UpdateNumber[2];
			u8 ExpiryDate[2];
			u8 Payload[0];
		} Header_t;

		EMM() { Position = 0; }

		Gen::Error CreateHeader(void);
		Gen::Error SetCardID(const u8 *ID);
		Gen::Error SetProtocolNumber(u8 ProtocolNumber);
		Gen::Error SetBroadcasterGroupID(u8 BroadcasterGroupID);
		Gen::Error SetUpdateNumber(u16 UpdateNumber);
		Gen::Error SetExpiryDate(u16 ExpiryDate);
		Gen::Error UpdateKey(u8 Index, const u8 *Key);
		Gen::Error UpdateBitmap(u8 Length, const u8 *Bitmap);
		Gen::Error GenericNano(u8 Nano, u8 Length, const u8 *Payload);
		Gen::Error MultiFunction(u8 Function);
		Gen::Error Finalise(void);
		void Get(u8 *& Payload, u8 & Size);
	};

	class ECM {
	private:
		u8 Position;
		static const u8 MaxLength = 255;
		u8 Buffer[256];

		enum kNanos {
			kMultiFunction = 0x21,
			kInvalidateTier = 0x23,
			kActivateTrial = 0x51,
			kCheckBitmap = 0x52,
		};

		enum kMFNanos {
			kMF_InvalidateTier = 0x01,
			kMF_ResetUpdateNumbers = 0x02,
			kMF_ResetTrial = 0xff,
		};

		enum kProgramTypes {
			kInvalidProgramType = 0x04,
		};

		typedef struct {
			u8 ProtocolNumber;
			u8 BroadcasterGroupID;
			u8 WorkKeyID;
			u8 OddKey[8];
			u8 EvenKey[8];
			u8 ProgramType;
			u8 Date[2];
			u8 Time[3];
			u8 RecordingControl;
			u8 Payload[0];
		} Header_t;

		typedef struct {
			u8 Nano;
			u8 Length;
			u8 Payload[0];
		} Nano_t;

		typedef struct {
			u8 Nano;
			u8 Length;
			u8 Days;
		} ActivateTrial_t;

		typedef struct {
			u8 Nano;
			u8 Length;
			u8 Bitmap[32];
		} CheckBitmap_t;

		typedef struct {
			u8 Nano;
			u8 Length;
			u8 CardID[6];
		} InvalidateTier_t;

		typedef struct {
			u8 Nano;
			u8 Length;
			u8 Function;
		} MultiFunction_t;

	public:
		ECM() { Position = 0; }

		Gen::Error CreateHeader(void);
		Gen::Error SetProtocolNumber(u8 ProtocolNumber);
		Gen::Error SetBroadcasterGroupID(u8 BroadcasterGroupID);
		Gen::Error SetWorkKeyID(u8 WorkKeyID);
		Gen::Error SetOddKey(const u8 *OddKey);
		Gen::Error SetEvenKey(const u8 *EvenKey);
		Gen::Error SetProgramType(u8 ProgramType);
		Gen::Error SetDate(u16 Date);
		Gen::Error SetTime(const u8 *Time);
		Gen::Error SetRecordingControl(u8 RecordingControl);
		Gen::Error ActivateTrial(u8 Days);
		Gen::Error CheckBitmap(u8 Length, const u8 *Bitmap);
		Gen::Error InvalidateTier(const u8 *CardID);
		Gen::Error MultiFunction(u8 Function);
		Gen::Error GenericNano(u8 Nano, u8 Length, const u8 *Payload);
		Gen::Error Finalise(void);
		void Get(u8 *& Payload, u8 & Size);
	};

	class EMD {
	private:
		u8 Position;
		static const u8 MaxLength = 255;
		u8 Buffer[256];

	public:
		typedef struct {
			u8 CardID[6];
			u8 ProtocolNumber;
			u8 BroadcasterGroupID;
			u8 MessageControl;
			u8 UpdateNumber[2];
			u8 Unknown0[2];
			u8 Date[2];
			u8 Unknown1[6];
		} Header_t;

		EMD() { Position = 0; }

		Gen::Error CreateHeader(void);
		Gen::Error SetCardID(const u8 *ID);
		Gen::Error SetProtocolNumber(u8 ProtocolNumber);
		Gen::Error SetBroadcasterGroupID(u8 BroadcasterGroupID);
		Gen::Error SetMessageControl(u8 MessageControl);
		Gen::Error SetUpdateNumber(u16 UpdateNumber);
		Gen::Error SetUnknown0(u8 U0, u8 U1);
		Gen::Error SetDate(u16 ExpiryDate);
		Gen::Error SetUnknown1(u8 U0, u8 U1, u8 U2, u8 U3, u8 U4, u8 U5);
		Gen::Error Finalise(void);
		void Get(u8 *& Payload, u8 & Size);
	};
}

#pragma warning(pop)

#endif
