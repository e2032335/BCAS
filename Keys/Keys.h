#ifndef BCAS_KEYS_H
#define BCAS_KEYS_H

namespace BCAS {
	namespace Keys {
		static const u8 KEYSET_WOWOW = 0x02;
		static const u8 KEYSET_STARCHANNELHD = 0x03;
		static const u8 KEYSET_E2_110CS = 0x17;
		static const u8 KEYSET_SAFETYNET = 0x1d;
		static const u8 KEYSET_NHK = 0x1e;
		static const u8 KEYSET_EMAIL = 0x20;

		s32 RegisterAll(void);
	}
}

#endif
