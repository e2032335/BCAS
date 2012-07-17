#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include "Global.h"
#include "Generator.h"
#include "Decoder.h"
#include "Keyset.h"
#include "Keys.h"
#include "Crypto.h"
#include "Manager.h"

static int DateState;
static const char * const ExpiryDate[7] = {
	"+7 days",
	"+15 days",
	"+30 days",
	"+90 days",
	"+180 days",
	"+365 days",
	"2038",
};
static u8 CardType;

static u16 ConvertDateToMJD(u16 Year, u8 Month, u8 Day)
{
	u32 l = 0;
	u32 md, yd;

	if ((Month == 1) || (Month == 2))
		l = 1;
	md = (u32)(((double)Month + 1 + l * 12) * 30.6001);
	yd = (u32)(((double)(Year - 1900) - l) * 365.25);

	return (14956 + Day + md + yd);
}

static void ConvertMJDToDate(u16 MJD, SYSTEMTIME *Time)
{
        u32 y1 = static_cast<u32>((static_cast<double>(MJD) - 15078.2) / 365.25);
        u32 y1r = static_cast<u32>(365.25 * static_cast<double>(y1));
        u32 m1 = static_cast<u32>((static_cast<double>(MJD) - 14956.1 - y1r) / 30.6001);
        u32 m1r = static_cast<u32>(30.6001 * static_cast<double>(m1));

        Time->wYear = y1 + 1900;
        Time->wMonth = m1 - 1;
        Time->wDay = MJD - 14956 - y1r - m1r;

        if ((m1 == 14) || (m1 == 15)) {
                Time->wMonth -= 12;
                ++Time->wYear;
        }
}

static void PrintMenu(void)
{
	printf("%s%sF4 Expiry in %s\n", CardType != kType_C ? "F1 Dump card | " : "", CardType <= kType_B ? "F2 Print tiers | F3 Print email | " : "", ExpiryDate[DateState]);
	printf("\n");
	printf("             | W | S |   |   | N | A |\n");
	printf("             | O | H | E | - | H | l |\n");
	printf("             | W | V | 2 | T | K | l |\n");
	printf("-------------*---*---*---*---*---*---*\n");
	if (CardType != kType_C) {
		printf("Update       | 1 | 2 | 3 | 4 | 5 |   |\n");
		printf("Invalidate   | q | w | e | r | t |   |\n");
		printf("Delete email | a | s | d | f | g | h |\n");
	}
	printf("Activate     | z | x | c | v | b |   |\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	int Index = 0;
	int Arg = 1;
	char *VirtualCard = NULL;
	BCAS::Manager::Abstract *Card;

	argc--;
	while (argc > 0) {
		if (strcmp(argv[Arg], "-virtual") == 0) {
			if (argc == 1) {
				printf("Missing file parameter.\n");
				return 1;
			}	
			VirtualCard = _strdup(argv[++Arg]);
			argc--;
		} else if (strcmp(argv[Arg], "-reader") == 0) {
			if (argc == 1) {
				printf("Missing file parameter.\n");
				return 1;
			}
			Index = atoi(argv[++Arg]);
			argc--;
		} else if (strcmp(argv[Arg], "-list") == 0) {
			Index = -1;
		} else {
			printf("Invalid parameter: %s\n", argv[Arg]);
			return 1;
		}
		Arg++;
		argc--;
	}

	if (VirtualCard == NULL) {
		SCARDCONTEXT Ctx;
		LONG Result;
		char *Reader = NULL;

		Result = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &Ctx);

		if (Result != SCARD_S_SUCCESS) {
			printf("Failed to establish context, error: %08x\n", Result);
			return 1;
		}

		DWORD Count = SCARD_AUTOALLOCATE;
		LPTSTR Readers = NULL;

		Result = SCardListReaders(Ctx, NULL, (LPTSTR)&Readers, &Count);
		if (Result != SCARD_S_SUCCESS) {
			if (Result == SCARD_E_NO_READERS_AVAILABLE)
				printf("No card readers available.\n");
			else
				printf("Failed to list card readers, error: %08x\n", Result);
			SCardReleaseContext(Ctx);
			return 1;
		}

		LPTSTR R = Readers;
		Count = 0;
		while (*R != 0) {
			if (Index == Count) {
				Reader = _strdup(R);
				break;
			} else if (Index == -1) {
				printf("Reader %d: %s\n", Count, R);
			}
			R += strlen(R) + 1;
			Count++;
		}
		SCardFreeMemory(Ctx, Readers);

		if (Reader == NULL) {
			if (Index != -1)
				printf("Cannot find a reader at index %d\n", Index);
			SCardReleaseContext(Ctx);
			return 1;
		}
		BCAS::Manager::Card *RealCard = new BCAS::Manager::Card;
		RealCard->SetReader(Reader);
		Card = RealCard;
	} else {
		BCAS::Manager::Virtual *Dump = new BCAS::Manager::Virtual;
		Dump->SetReader(VirtualCard);
		Card = Dump;
	}

	BCAS::Keys::RegisterAll();

	Card->Init();
	BCAS::Manager::Ops *Ops = new BCAS::Manager::Ops;
	Ops->SetCard(Card);

	BCAS::Manager::Manager *Mgr = new BCAS::Manager::Manager(Ops);

	bool Quit = false;
	u16 Date;
	SYSTEMTIME Time;

	GetSystemTime(&Time);
	Date = ConvertDateToMJD(Time.wYear, Time.wMonth & 0xff, Time.wDay & 0xff) + 7;

	while (!Quit) {
		bool NewCard = false;
		bool HasCard;
		u16 Expiry;

		HasCard = Card->WaitForEvent(NewCard);
		if (NewCard == true) {
			Mgr->PrintCardInformation(CardType);
			if (CardType == kType_INVALID)
				break;
			PrintMenu();
			continue;
		}
		if (HasCard == false) {
			if (_kbhit()) {
				int Selection = _getch();
				if (Selection == 27) {
					break;
				}
				if (Selection == 0)
					_getch();
			}
			continue;
		}

		int Key = _getch();
		switch (Key) {
		case 27:
				Quit = true;
				break;

		case 0:
			Key = _getch();
			switch (Key) {
			case 59:
				Mgr->DumpMode();
				break;
			case 60:
				Mgr->PrintEntitlements();
				break;
			case 61:
				Mgr->PrintEmail();
				break;
			case 62:
				DateState = (DateState + 1) % 7;
				switch (DateState) {
				case 0:
					Expiry = 7;
					break;
				case 1:
					Expiry = 15;
					break;
				case 2:
					Expiry = 30;
					break;
				case 3:
					Expiry = 90;
					break;
				case 4:
					Expiry = 180;
					break;
				case 5:
					Expiry = 365 * 2;
					break;
				case 6:
					break;
				}
				if (DateState != 6) {
					GetSystemTime(&Time);
					Date = ConvertDateToMJD(Time.wYear, Time.wMonth & 0xff, Time.wDay & 0xff) + Expiry;
				} else {
					Date = 0xffff;
				}
				break;

			default:
				printf("%d\n", Key);
				break;
			}
			break;

		// UpdateTiers
		case 49:
			Mgr->AddEntitlement(BCAS::Keys::KEYSET_WOWOW, Date);
			break;
		case 50:
			Mgr->AddEntitlement(BCAS::Keys::KEYSET_STARCHANNELHD, Date);
			break;
		case 51:
			Mgr->AddEntitlement(BCAS::Keys::KEYSET_E2_110CS, Date);
			break;
		case 52:
			Mgr->AddEntitlement(BCAS::Keys::KEYSET_SAFETYNET, Date);
			break;
		case 53:
			Mgr->AddEntitlement(BCAS::Keys::KEYSET_NHK, Date);
			break;

		// InvalidateTiers
		case 113:
			Mgr->InvalidateEntitlement(BCAS::Keys::KEYSET_WOWOW);
			break;
		case 119:
			Mgr->InvalidateEntitlement(BCAS::Keys::KEYSET_STARCHANNELHD);
			break;
		case 101:
			Mgr->InvalidateEntitlement(BCAS::Keys::KEYSET_E2_110CS);
			break;
		case 114:
			Mgr->InvalidateEntitlement(BCAS::Keys::KEYSET_SAFETYNET);
			break;
		case 116:
			Mgr->InvalidateEntitlement(BCAS::Keys::KEYSET_NHK);
			break;

		// DeleteEmail
		case 97:
			Mgr->DeleteEmail(BCAS::Keys::KEYSET_WOWOW);
			break;
		case 115:
			Mgr->DeleteEmail(BCAS::Keys::KEYSET_STARCHANNELHD);
			break;
		case 100:
			Mgr->DeleteEmail(BCAS::Keys::KEYSET_E2_110CS);
			break;
		case 102:
			Mgr->DeleteEmail(BCAS::Keys::KEYSET_SAFETYNET);
			break;
		case 103:
			Mgr->DeleteEmail(BCAS::Keys::KEYSET_NHK);
			break;
		case 104:
			Mgr->DeleteEmail(BCAS::Keys::KEYSET_EMAIL);
			break;

		// ActivateTrial
		case 122:
			Mgr->ActivateTrial(BCAS::Keys::KEYSET_WOWOW, false, Date);
			Mgr->ActivateTrial(BCAS::Keys::KEYSET_WOWOW, true, Date);
			break;
		case 120:
			Mgr->ActivateTrial(BCAS::Keys::KEYSET_STARCHANNELHD, false, Date);
			Mgr->ActivateTrial(BCAS::Keys::KEYSET_STARCHANNELHD, true, Date);
			break;
		case 99:
			Mgr->ActivateTrial(BCAS::Keys::KEYSET_E2_110CS, false, Date);
			Mgr->ActivateTrial(BCAS::Keys::KEYSET_E2_110CS, true, Date);
			break;
		case 118:
			Mgr->ActivateTrial(BCAS::Keys::KEYSET_SAFETYNET, false, Date);
			Mgr->ActivateTrial(BCAS::Keys::KEYSET_SAFETYNET, true, Date);
			break;
		case 98:
			Mgr->ActivateTrial(BCAS::Keys::KEYSET_NHK, false, Date);
			Mgr->ActivateTrial(BCAS::Keys::KEYSET_NHK, true, Date);
			break;

		default:
			printf("%d\n", Key);
			break;
		}

		if (!Quit)
			PrintMenu();
	}

	return 0;
}
