#ifndef BCAS_GLOBALS_H
#define BCAS_GLOBALS_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;

#if defined(_MSC_VER)

typedef unsigned __int64 u64;
typedef signed __int64 s64;

#elif defined(__GNUC__)

typedef unsigned long long u64;
typedef signed long long s64;

#endif

#endif
