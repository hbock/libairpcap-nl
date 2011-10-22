#ifndef __APCAP_AIRPCAP_TYPES

#include <stdint.h>

typedef int  BOOL;
typedef int *PBOOL;

#define TRUE  1
#define FALSE 0

typedef uint8_t  BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;

typedef uint8_t *PBYTE;

typedef unsigned short USHORT;

typedef unsigned int  UINT;
typedef unsigned int *PUINT;

/* ULONG on Windows is 32-bit, regardless of the
 * architecture. */
typedef uint32_t ULONG;

typedef char CHAR;
typedef CHAR *PCHAR;
typedef unsigned char UCHAR;

typedef void VOID;
typedef VOID *PVOID;
typedef PVOID HANDLE;

#endif /* __APCAP_AIRPCAP_TYPES */
