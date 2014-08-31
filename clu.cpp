#include <windows.h>	
#include "tron_user.h"
#include "detours.h"    //To hax IDA to be sane.
#include <tlhelp32.h>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <dbg.hpp>
#include <map>

//#define CLU_DEBUG

#ifdef CLU_DEBUG
#define DBG msg
#else
#define DBG
#endif

char *WindowTitleWords[] = { "smells", "like", "some", "random", 
							 "assortment", "of strings", "used",
							 "to", "obfuscate", "window", "titles"};

std::map<ea_t, int> cloak_refs;		// refcounts of cloaked pages
HANDLE proc_handle;
process_id_t pid;

int (idaapi* orig_add_bpt)(bpttype_t type, ea_t ea, int len);	// function pointers in global
int (idaapi* orig_del_bpt)(ea_t ea, const uchar *orig_bytes, int len);
ssize_t (idaapi* orig_read_memory)(ea_t ea, void *buffer, size_t size);
ssize_t (idaapi* orig_write_memory)(ea_t ea, const void *buffer, size_t size);
bool (idaapi* orig_term_debugger)();
int (idaapi* orig_get_debug_event)(debug_event_t *ev, bool ida_is_idle);
int (idaapi* orig_attach_process)(process_id_t pid, int event_id);
int (idaapi* orig_detach_process)();
int (idaapi* orig_exit_process)();

bool CLU_loaded = false;

typedef BOOL (WINAPI *OrigWriteProcessMemory_t)(
  HANDLE hProcess,
  LPVOID lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T nSize,
  SIZE_T* lpNumberOfBytesWritten);
OrigWriteProcessMemory_t OrigWriteProcessMemory = WriteProcessMemory;


BOOL CALLBACK ida_change_title(HWND hwnd, LPARAM lParam)
{
    char title[512]; // longer than enough

    GetWindowText(hwnd, title, 512);
 
	if(strstr(title, "IDA Pro debugging ") == title) {
		// XXX: Doesn't work.. I also tried hooking SetWindowTextA/W 
		// to no avail either.. just have to attach to processes I guess : (
		DBG("DBG: Removing IDA Prefix\n");
	    if(!SetWindowText(hwnd, &title[19])) {
			msg("CLU: Window title set failed: %d\n", GetLastError());
		}
	} else if(strstr(title, "IDA")) {
		DBG("DBG: Title: %s\n", title); // print title
	    if(!SetWindowText(hwnd, 
			WindowTitleWords[rand()%(sizeof(WindowTitleWords)/sizeof(char*))])) {
			msg("CLU: Window title set failed: %d\n", GetLastError());
		}
		GetWindowText(hwnd, title, 512);
		DBG("DBG: NewTitle: %s\n", title);
		WNDENUMPROC change_title = ida_change_title;
		EnumChildWindows(hwnd, change_title, NULL);     
	}

    return 1;
}

static int stealth_ida_windows()
{
	DBG("DBG: Obfusticating Window Titles\n");
    HANDLE procsnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL , 0);
    THREADENTRY32 threads;

    threads.dwSize = sizeof(THREADENTRY32);
    DWORD ida_pid = GetCurrentProcessId();

    if (!Thread32First(procsnap, &threads)) {
		msg("CLU: Thread32First failed\n");
        return -1;
    }

    do {
        if (threads.th32OwnerProcessID == ida_pid 
			|| (pid && threads.th32OwnerProcessID == pid)) {
            /* we'll probably rename it here */
            WNDENUMPROC change_title = ida_change_title;
            EnumThreadWindows(threads.th32ThreadID, change_title, NULL);
        }

    } while (Thread32Next(procsnap, &threads));

    return 0;
}

BOOL WINAPI NewWriteProcessMemory(
  HANDLE hProcess,
  LPVOID lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T nSize,
  SIZE_T* lpNumberOfBytesWritten) {
	DWORD write_pid = GetProcessId(hProcess);
	ea_t page_addr = ((ea_t)lpBaseAddress) & 0xFFFFF000;

	if(write_pid != pid) {
		DBG("DBG: Stray WriteProcess Memory for pid: %d\n", write_pid);
		return OrigWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer,
			  nSize, lpNumberOfBytesWritten);
	}

	if(cloak_refs.find(page_addr) == cloak_refs.end() 
			|| cloak_refs[page_addr] == 0) {
		msg("CLU: WPM called with no cloak for %x!\n", lpBaseAddress);
		return OrigWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer,
			  nSize, lpNumberOfBytesWritten);
	} else {
		if(lpNumberOfBytesWritten) {
			*lpNumberOfBytesWritten = nSize;
		}
		DBG("DBG: WPM called with %x, %x, %d\n", lpBaseAddress, lpBuffer, nSize);
		WRITE_HIDDEN(pid, lpBaseAddress, lpBuffer, nSize); // I think this returns bytes written
		return true;
	}	  
}

// XXX: NEVER CALLED!!! Above detour is used instead
static ssize_t idaapi clu_write_memory(ea_t ea, const void *buffer, size_t size)
{
	DBG("write_memory args: 0x%x 0x%x %d\n", ea, buffer, size);
	//msg("write_memory buffer: 0x%x\n",*(unsigned char *) buffer);

	ea_t page_addr = ea & 0xFFFFF000;

	if(cloak_refs.find(page_addr) == cloak_refs.end() 
			|| cloak_refs[page_addr] == 0) {
		return orig_write_memory(ea, buffer, size);
	} else {
		WRITE_HIDDEN(pid, ea, buffer, size); // I think this returns bytes written
		return size;
	}
}

static ssize_t idaapi clu_read_memory(ea_t ea, void *buffer, size_t size)
{
	ea_t page_addr = ea & 0xFFFFF000;

	if (cloak_refs.find(page_addr) == cloak_refs.end() 
		|| cloak_refs[page_addr] == 0) {
		return orig_read_memory(ea, buffer, size);
	} else {
		DBG("DBG: read_hidden args: 0x%x 0x%x %d\n", ea, buffer, size);
		READ_HIDDEN(pid, ea, buffer, size);
		return size;								// not best way to do this
	}
}

static int idaapi clu_add_bpt(bpttype_t type, ea_t ea, int len) // replacement functions
{
	int ret = 0;
	unsigned char buf = 0;
	DBG("DBG: add_bpt args: %d 0x%x %d\n", type, ea, len);
	
	if (type != BPT_SOFT) {
		msg("CLU: !BPT_SOFT: %d\n", type);
		return orig_add_bpt(type, ea, len);
	}

	if (len != -1) {
		warning("CLU: Breakpoint len != -1\n");
		return 0; // failure
	}

	ea_t page_addr = ea & 0xFFFFF000;
	CMD_CLOAK_ARGS args;

	// XXX: Check for pids again for case where image doesn't load
	// right away..
	if (get_process_qty() <= 0) {
		msg("CLU: No Process Attached!\n");
		return 0;  // this happens a few times, maybe we block a thread
	}

	if(cloak_refs.find(page_addr) == cloak_refs.end() 
			|| cloak_refs[page_addr] == 0) {
		char fake_page[4096];

		args.cloak_start = page_addr;			// address of page to cloak
		args.cloak_end = args.cloak_start + 4096;

		args.fake_start = (DWORD)fake_page;
		args.fake_end = args.fake_start + 4096;
	
		if(!ReadProcessMemory(proc_handle, (LPCVOID)page_addr, fake_page, 4096, NULL)) {
			msg("CLU: Process memory read failed: %x\n", GetLastError()); 
		}
		
		if(!ReadProcessMemory(proc_handle, (LPCVOID)ea, &buf, 1, NULL)) {
			msg("CLU: breakpont read failed: %d\n", GetLastError()); 
		}
		DBG("DBG: Clean memory 0x%x held: 0x%x\n", ea, buf);	
		
		DBG("DBG: Adding Cloak\n");
		ADD_CLOAK(pid, args.cloak_start, args.cloak_end, args.fake_start, args.fake_end);
		cloak_refs[page_addr] = 1;
	} else {
		// in this case we already have a cloaked page
		DBG("DBG: Cloak Exists, bpts: %d\n", cloak_refs[page_addr]);
		++cloak_refs[page_addr];
	}

	if((ret = orig_add_bpt(type, ea, len)) != 1) {
		msg("CLU: orig_add_bpt failed: %d\n", ret);
	}

#ifdef CLU_DEBUG
	clu_read_memory(ea, &buf, 1);
	DBG("DBG: Cloaked memory 0x%x held: 0x%x\n", ea, buf);

	if(!ReadProcessMemory(proc_handle, (LPCVOID)ea, &buf, 1, NULL)) {
		msg("CLU: Fake memory failed: %d\n", GetLastError());
	}
	DBG("DBG: Fake memory 0x%x held: 0x%x\n", ea, buf);
#endif

	return 1;	// success
}

static int idaapi clu_del_bpt(ea_t ea, const uchar *orig_bytes, int len)
{
	int ret = 0;
	DBG("DBG: del_bpt args: 0x%x 0x%x %d\n", ea, orig_bytes, len);

	// why is this called with -1 and add_bpt with 1 ?
	if (len != 1) {
		warning("CLU: Breakpoint len != 1\n");
		return orig_del_bpt(ea, orig_bytes, len); 
	}

	ea_t page_addr = ea & 0xFFFFF000;
	CMD_CLOAK_ARGS args;

	if (get_process_qty() <= 0) {
		msg("CLU: No Process Attached!\n");
		return 0;
	}

	if(cloak_refs.find(page_addr) == cloak_refs.end() 
			|| cloak_refs[page_addr] == 0) {
		msg("CLU: Attempt to delete unknown breakpoint: %x (OK at process exit)\n", ea);
		return orig_del_bpt(ea, orig_bytes, len);
	} else {
		char buf = 0;

		DBG("DBG: orig_bytes: %x\n", *orig_bytes);
		if(!ReadProcessMemory(proc_handle, (LPCVOID)ea, &buf, 1, NULL)) {
			msg("CLU: breakpont read failed: %d\n", GetLastError()); 
		}

#ifdef CLU_DEBUG
		DBG("DBG: Pre-fake memory 0x%x held: 0x%x\n", ea, buf);
		READ_HIDDEN(pid, ea, &buf, 1);
		DBG("DBG: Pre-cloaked hidden memory had %x\n", buf);
#endif

		// Write breakpoint so del_bpt has something to read..
		OrigWriteProcessMemory(proc_handle, (LPVOID)ea, "\xcc", 1, NULL);

		if((ret = orig_del_bpt(ea, orig_bytes, len)) != 1) {
			msg("CLU: orig_del_bpt failed: %d\n", ret);
#ifdef CLU_DEBUG
			if(!ReadProcessMemory(proc_handle, (LPCVOID)ea, &buf, 1, NULL)) {
				msg("CLU: breakpont read failed: %d\n", GetLastError()); 
			}
			DBG("DBG: Postfail-fake memory 0x%x held: 0x%x\n", ea, buf);
			READ_HIDDEN(pid, ea, &buf, 1);
			DBG("DBG: Postfail-cloaked hidden memory had %x\n", buf);
#endif
			//return ret;
		}

		// Restore insn to fake view..
		OrigWriteProcessMemory(proc_handle, (LPVOID)ea, &buf, 1, NULL);

		// -- works because map returns by reference
		if(--cloak_refs[page_addr] == 0) {
			DBG("DBG: Removing Cloak: bpts %d\n", cloak_refs[page_addr]);
			args.cloak_start = page_addr;
			args.cloak_end = args.cloak_start + 4096;

			// when cloak removes bpt is still there
			REMOVE_CLOAK(pid, args.cloak_start, args.cloak_end);
			cloak_refs.erase(page_addr);
			return 1;
		}
	}
	return 1;
}

void remove_cloaks()
{
	if(!pid) {
		msg("CLU: No pid to remove cloaks!\n");
		return;
	}
	for(std::map<ea_t, int>::iterator i = cloak_refs.begin();
		i != cloak_refs.end(); ++i) {
			REMOVE_CLOAK(pid, i->first, i->first + 4096);
	}
}

void clear_clu_data()
{
	cloak_refs.clear();
	if(proc_handle) {
		CloseHandle(proc_handle);
		proc_handle = 0;
	}
	pid = 0;
}

bool idaapi clu_term_debugger()
{
	DBG("DBG: Term debugger\n");
	clear_clu_data();
	return orig_term_debugger();
}

int idaapi clu_get_debug_event(debug_event_t *ev, bool idle)
{
	int ret;
	ret = orig_get_debug_event(ev, idle);
	if(ev && ev->eid == PROCESS_START && !pid) {
		DBG("DBG: Got Process start event for pid %d\n", ev->pid);
		pid = ev->pid;
		stealth_ida_windows();
		proc_handle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
		if(!proc_handle) {
			msg("CLU: OpenProcess failed! %d\n", GetLastError());
		}
	}
	return ret;
}


int idaapi clu_attach_process(process_id_t apid, int event_id)
{
	int ret = 0;
	DBG("DBG: attach process %d\n", apid);
	clear_clu_data();

	stealth_ida_windows();
	pid = apid;
	ret = orig_attach_process(apid, event_id);

	proc_handle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
	if(!proc_handle) {
		msg("CLU: OpenProcess failed! %d\n", GetLastError());
	}

	return ret;
}

int idaapi clu_detach_process()
{
	DBG("DBG: Detach process\n");

	remove_cloaks();
	clear_clu_data();
	return orig_detach_process();
}

int idaapi clu_exit_process()
{
	DBG("DBG: Detach process\n");

	remove_cloaks();
	clear_clu_data();
	return orig_exit_process();
}

int IDAP_init(void)
{
	// Do checks here to ensure your plug-in is being used within
	// an environment it was written for. Return PLUGIN_SKIP if the 	
	// checks fail, otherwise return PLUGIN_KEEP.
	// stealth_ida_windows();
	msg("CLU loaded. Alt-T to initialize (can be re-run to re-cloak titles)\n");
	return PLUGIN_KEEP;
}

void IDAP_term(void)
{
	if (CLU_loaded == false) {
		msg("CLU already unloaded\n");
		return;
	}

	msg("Unloading CLU\n");

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)OrigWriteProcessMemory, NewWriteProcessMemory);
	DetourTransactionCommit();

	// on exit this occurs before plugin is called
	if (dbg == NULL) {
		msg("CLU: dbg NULL on unload\n");
		return;
	}

	dbg->add_bpt = orig_add_bpt;			// restore function pointers
	dbg->del_bpt = orig_del_bpt;
	dbg->read_memory = orig_read_memory;
	dbg->write_memory = orig_write_memory;
	dbg->attach_process = orig_attach_process;
	dbg->detach_process = orig_detach_process;
	dbg->exit_process = orig_exit_process;
	dbg->term_debugger = orig_term_debugger;
	dbg->get_debug_event = orig_get_debug_event;
	CLU_loaded = false;

	return;
}

void IDAP_run(int arg)
{
	// if called with arg 1, put shit back the way it was
	if (arg == 1) {
		IDAP_term();
		return;
	}

	msg("CLU: Cloaking windows\n");
	stealth_ida_windows();

	// dont do anything except hooking twice
	if (CLU_loaded == true) {
		//msg("CLU already loaded\n");
		return;
	}

	// make sure this structure exists
	if (dbg == NULL) {
		msg("CLU: dbg == NULL\n");
		return;
	}

	msg("CLU: Installing hooks\n");
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)OrigWriteProcessMemory, NewWriteProcessMemory);
	DetourTransactionCommit();
	
	CLU_loaded = true;			// set flag
								// print out original addresses
	dbg->flags = DBG_FLAG_REMOTE|DBG_FLAG_NOHOST;

	// XXX: GetProcAddress for WriteProcessMemory and then hook the bitch

	orig_add_bpt = dbg->add_bpt; // back up function pointers
	orig_del_bpt = dbg->del_bpt;
	orig_read_memory = dbg->read_memory;
	orig_write_memory = dbg->write_memory;
	orig_attach_process = dbg->attach_process;

	orig_detach_process =dbg->detach_process;
	orig_exit_process = dbg->exit_process;
	orig_term_debugger = dbg->term_debugger;
	orig_get_debug_event = dbg->get_debug_event;

	dbg->add_bpt = clu_add_bpt; // replace existing functions
	dbg->del_bpt = clu_del_bpt;
	dbg->read_memory = clu_read_memory;
	dbg->write_memory = clu_write_memory;
	dbg->attach_process = clu_attach_process;
	dbg->detach_process = clu_detach_process;
	dbg->exit_process = clu_exit_process;
	dbg->term_debugger = clu_term_debugger;
	dbg->get_debug_event = clu_get_debug_event;

	return;
}

// There isn't much use for these yet, but I set them anyway.
char IDAP_comment[] 	= "CLU";
char IDAP_help[] 	= "CLU";

// The name of the plug-in displayed in the Edit->Plugins menu. It 
// can be overridden in the user's plugins.cfg file.
char IDAP_name[] 	= "CLU";

// The hot-key the user can use to run your plug-in.
char IDAP_hotkey[] 	= "Alt-T";

// The all-important exported PLUGIN object
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
	0,		// Flags (see below)
	IDAP_init,	// Initialisation function
	IDAP_term,	// Clean-up function
	IDAP_run,	// Main plug-in body
	IDAP_comment,	// Comment - unused
	IDAP_help,	// As above - unused
	IDAP_name,	// Plug-in name shown in 
			// Edit->Plugins menu
	IDAP_hotkey	// Hot key to run the plug-in
};