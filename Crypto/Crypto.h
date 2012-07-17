#pragma once

namespace BCAS {
	namespace Crypto {
		void Transform(u8 Protocol, const u8 *Password, const u8 *Input, u32 Size, u8 *Output, bool Decryption);
		void GenerateMAC(u8 Protocol, const u8 *Password, const u8 *Payload, u32 Size, u8 *MAC);
	}
}
