#ifndef BCAS_DECODER_H
#define BCAS_DECODER_H

namespace BCAS {
	namespace Decoder {
		s32 DecodeECM(const u8 *Payload, u32 Size, u8 *Keys, u8 *Nanos);
		s32 DecodeEMM(const u8 *Payload, u32 Size, bool Individual);
		void SetCardID(const u8 *ID);
		void SetCardKey(const u8 *Key);
	}
}

#endif
