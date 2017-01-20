#include "proxydbg.h"

#include <process.h>
#include <unordered_map>
#include <queue>
using namespace std;

queue<debug_event_t> msgqueue;

//create proxydbg_python.cpp with "swig -classic -c++ -python -o proxydbg_python.cpp  proxydbg_python.h"


BOOL APIENTRY DllMain(HMODULE /* hModule */, DWORD ul_reason_for_call, LPVOID /* lpReserved */)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

/*
Interface
used to export data to python and get update
*/
debugger_t *get_dbg()
{
	return dbg;
}

text_options_t get_dto()
{
	return dto;
}

processor_t get_ph()
{
	return ph;
}

asm_t get_ash()
{
	return ash;
}

idainfo get_inf()
{
	return inf;
}


#define PLUGIN_NAME "proxydbg"
#define PLUGIN_ID 'pt'
#define REGISTER_CLASS 1
#define PAGE_SIZE 0x1000
#define PROCESS_NAME "Remote Process"
#define PROCESS_PID 123
#define COMPARE_BYTES 256
#define DEBUG false

/*
notice:
add following settings to ida\plugins\plugins.cfg and copy bin to ida\plugins\proxy_user.plw
"Proxy_debugger				proxy_user    0       0  DEBUG"

available constants:
dbg ph inf
*/

static const char* register_classes[8] =
{
	"General registers",
	0,
};

static const char* arm_flags[] = {
	"MODE", "MODE", "MODE", "MODE", "MODE", "T", "F", "I",
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	"Q", "V", "C", "Z", "N"
};
#define MAX_REG_NUM 256
static struct register_info_t registers[MAX_REG_NUM] = {
	//PC/IP reigster (REGISTER_IP) will be searched during every loading file
	{ "R0", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "R1", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "R2", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "R3", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "R4", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "R5", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "R6", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "R7", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "R8", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "R9", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "R10", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "R11", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "R12", REGISTER_ADDRESS, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "SP", REGISTER_ADDRESS | REGISTER_SP, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "LR", REGISTER_ADDRESS, REGISTER_CLASS,  dt_dword, NULL, 0 },
	{ "PC", REGISTER_ADDRESS | REGISTER_IP, REGISTER_CLASS, dt_dword, NULL, 0 },
	{ "CPSR", 0, REGISTER_CLASS, dt_dword, arm_flags, 0xF80000FF },
	{ 0, 0, 0, 0, 0, 0} //mark for last one
};

int getnumber(register_info_t* regarr)
{//real-time calc
	int index = 0;
	for (index = 0; index < MAX_REG_NUM; index++) //max 256 registers
	{
		if (regarr[index].name == 0)
			break;
	}
	return index;
}

uchar bpt_bytes[16];

debugger_t debugger = {
	IDD_INTERFACE_VERSION,	//version
	PLUGIN_NAME,			//name
	PLUGIN_ID,				//id
	"ARM",					//processor
	DBG_FLAG_REMOTE,	//flags
	register_classes,		//register_classes
	REGISTER_CLASS,			//register_classes_default
	registers,				//_registers
	getnumber(registers),		//registers_size
	PAGE_SIZE,				//memory_page_size
	bpt_bytes,						//bpt_bytes
	0,						//bpt_size
	(uchar)inf.filetype,	//filetype
	DBG_RESMOD_STEP_INTO | DBG_RESMOD_STEP_OVER | DBG_RESMOD_STEP_OUT,	//resume_modes
	proxy_init_debugger,
	proxy_term_debugger,
	proxy_process_get_info,
	proxy_start_process,
	proxy_attach_process,
	proxy_detach_process,
	proxy_rebase_if_required_to,
	proxy_prepare_to_pause_process,
	proxy_exit_process,
	proxy_get_debug_event,
	proxy_continue_after_event,
	proxy_set_exception_info,
	proxy_stopped_at_debug_event,
	proxy_thread_suspend,
	proxy_thread_continue,
	proxy_set_resume_mode,
	proxy_read_registers,
	proxy_write_register,
	proxy_thread_get_sreg_base,
	proxy_get_memory_info,
	proxy_read_memory,
	proxy_write_memory,
	proxy_is_ok_bpt,
	proxy_update_bpts,
	proxy_update_lowcnds,
	proxy_open_file,
	proxy_close_file,
	proxy_read_file,
	proxy_map_address,
	proxy_set_dbg_options,
	proxy_get_debmod_extensions,
	proxy_update_call_stack,
	proxy_appcall,
	proxy_cleanup_appcall,
	proxy_eval_lowcnd,
	proxy_write_file,
	proxy_send_ioctl,
	proxy_dbg_enable_trace,
	proxy_is_tracing_enabled,
	proxy_rexec,
	proxy_get_debapp_attrs,
};

char* proxynames[] =
{
	"proxy_init_debugger",
	"proxy_term_debugger",
	"proxy_process_get_info",
	"proxy_start_process",
	"proxy_attach_process",
	"proxy_detach_process",
	"proxy_rebase_if_required_to",
	"proxy_prepare_to_pause_process",
	"proxy_exit_process",
	"proxy_get_debug_event",
	"proxy_continue_after_event",
	"proxy_set_exception_info",
	"proxy_stopped_at_debug_event",
	"proxy_thread_suspend",
	"proxy_thread_continue",
	"proxy_set_resume_mode",
	"proxy_read_registers",
	"proxy_write_register",
	"proxy_thread_get_sreg_base",
	"proxy_get_memory_info",
	"proxy_read_memory",
	"proxy_write_memory",
	"proxy_is_ok_bpt",
	"proxy_update_bpts",
	"proxy_update_lowcnds",
	"proxy_open_file",
	"proxy_close_file",
	"proxy_read_file",
	"proxy_map_address",
	"proxy_set_dbg_options",
	"proxy_get_debmod_extensions",
	"proxy_update_call_stack",
	"proxy_appcall",
	"proxy_cleanup_appcall",
	"proxy_eval_lowcnd",
	"proxy_write_file",
	"proxy_send_ioctl",
	"proxy_dbg_enable_trace",
	"proxy_is_tracing_enabled",
	"proxy_rexec",
	"proxy_get_debapp_attrs",
	"proxy_get_register_layout",
	"proxy_raw",
	"proxy_init_debuggee",
};

unordered_map<const char*, PyObject*> pFuncs;

#define MSG(x) MessageBoxA(0, x, x, 0)


//-------------------------------------------------------------------------
// Execute a line in the CLI
bool idaapi ProxyDbg_cli_execute_line(const char *line)
{
	// Do not process empty lines
	if (line[0] == '\0')
		return true;

	char *last_line = (char*)strchr(line, '\n');
	if (last_line != NULL)
		*last_line = '\0';
	last_line = (char*)strchr(line, '\r');
	if (last_line != NULL)
		*last_line = '\0';

	//eval this
	PyGILState_STATE gstate = PyGILState_Ensure();
	if (pFuncs["proxy_raw"] != 0)
	{
		PyObject* pFunc = pFuncs["proxy_raw"];
		PyObject* pArgs = PyTuple_New(1);
		PyTuple_SetItem(pArgs, 0, Py_BuildValue("s", line));
		PyObject_CallObject(pFunc, pArgs);
	}
	PyGILState_Release(gstate);

	return true;
}

static const cli_t cli_packet =
{
	sizeof(cli_t),
	0,
	"Packet",
	"Packet - ProxyDbg plugin",
	"Enter any packet",
	ProxyDbg_cli_execute_line,
	NULL,
	NULL
};

// Control the Packet CLI status
idaman void ida_export enable_packet_cli(bool enable)
{
	if (enable)
		install_command_interpreter(&cli_packet);
	else
		remove_command_interpreter(&cli_packet);
}
//-------------------------------------------------------------------------



int idaapi plugin_init(void)
{

	/*
	called every start up
	called every new loading file
	inf.filetype is filetype_t,  empty file -> 0
	*/
	msg(__FUNCTION__" filetype=%d\n", inf.filetype);
	dbg = &debugger;
	
	if (!Py_IsInitialized())
		return PLUGIN_SKIP;
	PyEval_InitThreads();
	PyGILState_STATE gstate = PyGILState_Ensure();
	PyObject* pName = PyString_FromString("proxydbg");
	PyObject* pModule = PyImport_Import(pName);
	if (!pModule)
	{
		msg("pModule is null\n");
		return PLUGIN_SKIP;
	}
	PyObject* pDict = PyModule_GetDict(pModule);
	if (!pDict)
	{
		msg("pDict is null\n");
		return PLUGIN_SKIP;
	}
	for (int i = 0; i < sizeof(proxynames) / sizeof(proxynames[0]); i++)
	{
		pFuncs[proxynames[i]] = PyDict_GetItemString(pDict, proxynames[i]);
	}
	PyGILState_Release(gstate);

	enable_packet_cli(true);
	define_exception(0xAA55, "INIT_BREAK", "program stop at on attach/start", EXC_HANDLE | EXC_SILENT);

	return PLUGIN_KEEP;
}

void idaapi plugin_term(void)
{
	/*
	called every unloading file
	*/
	msg(__FUNCTION__"\n");
}

void idaapi plugin_run(int /*arg*/)
{
	msg(__FUNCTION__"\n");
}

/// Is it possible to set breakpoint?.
/// This function is called from debthread or from the main thread if debthread
/// is not running yet.
/// It is called to verify hardware breakpoints.
/// \return ref BPT_
int idaapi proxy_is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
	MSG(__FUNCTION__"\n");
	//proxy to python
	int retval;

	if (DEBUG)
	{
		retval = BPT_OK;
	}
	else
	{
		PyGILState_STATE gstate = PyGILState_Ensure();
		if (pFuncs[__FUNCTION__] != 0)
		{
			PyObject* pFunc = pFuncs[__FUNCTION__];
			PyObject* pArgs = PyTuple_New(3);
			PyTuple_SetItem(pArgs, 0, Py_BuildValue("i", type));
			PyTuple_SetItem(pArgs, 1, Py_BuildValue("i", ea));
			PyTuple_SetItem(pArgs, 2, Py_BuildValue("i", len));
			PyObject* pResult = PyObject_CallObject(pFunc, pArgs);
			retval = PyInt_AsLong(pResult);
		}
		PyGILState_Release(gstate);
	}

	return retval;//BPT_OK
}

/// Add/del breakpoints.
/// bpts array contains nadd bpts to add, followed by ndel bpts to del.
/// This function is called from debthread.
/// \return number of successfully modified bpts, -1 if network error
int idaapi proxy_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
	MSG(__FUNCTION__"\n");
	//proxy to python
	int retval = BPT_SKIP;

	if (DEBUG)
	{
		retval = BPT_OK;
	}
	else
	{
		PyGILState_STATE gstate = PyGILState_Ensure();
		if (pFuncs[__FUNCTION__] != 0)
		{
			PyObject* pFunc = pFuncs[__FUNCTION__];
			PyObject* pArgs = PyTuple_New(nadd + ndel);
			char* intstr = "i";
			if (sizeof(bpts->ea) == 8)
				intstr == "L";
			for (int i = 0; i < nadd + ndel; i++)
			{
				PyObject* dict = PyDict_New();
				PyDict_SetItemString(dict, "ea", Py_BuildValue(intstr, bpts[0].ea));
				PyDict_SetItemString(dict, "type", Py_BuildValue("i", bpts[0].type));
				PyDict_SetItemString(dict, "size", Py_BuildValue("i", bpts[0].size));
				if (i < nadd)
				{
					PyDict_SetItemString(dict, "isadd", Py_BuildValue("i", 1));
				}
				else
				{
					PyDict_SetItemString(dict, "isadd", Py_BuildValue("i", 0));
				}
				PyTuple_SetItem(pArgs, i, dict);
			}
			PyObject* pResult = PyObject_CallObject(pFunc, pArgs);
			retval = PyInt_AsLong(pResult);
		}
		PyGILState_Release(gstate);
	}

	return retval;
}

/// Update low-level (server side) breakpoint conditions.
/// This function is called from debthread.
/// \return nlowcnds. -1-network error
int idaapi proxy_update_lowcnds(const lowcnd_t * lowcnds, int nlowcnds)
{
	//   msg("proxy_update_lowcnds called\n");
	MSG(__FUNCTION__"\n");
	return nlowcnds;
}

/// Evaluate a low level breakpoint condition at 'ea'.
/// Other evaluation errors are displayed in a dialog box.
/// This call is rarely used by IDA when the process has already been suspended
/// for some reason and it has to decide whether the process should be resumed
/// or definitely suspended because of a breakpoint with a low level condition.
/// This function is called from debthread.
/// \retval  1  condition is satisfied
/// \retval  0  not satisfied
/// \retval -1  network error
int idaapi proxy_eval_lowcnd(thid_t /*tid*/, ea_t ea)
{
	MSG(__FUNCTION__"\n");
	return 1;
}

/// Enable/Disable tracing.
/// "trace_flags" can be a set of STEP_TRACE, INSN_TRACE, BBLK_TRACE or FUNC_TRACE.
/// See thread_t::trace_mode in debugger.h.
/// This function is called from the main thread.
bool idaapi proxy_dbg_enable_trace(thid_t tid, bool enable, int trace_flags)
{
	return false;
}

/// Is tracing enabled? ONLY used for tracers.
/// "trace_bit" can be one of the following: STEP_TRACE, INSN_TRACE, BBLK_TRACE or FUNC_TRACE
bool idaapi proxy_is_tracing_enabled(thid_t tid, int tracebit)
{
	return false;
}

void proxy_init_debuggee(void*)
{
	PyGILState_STATE gstate = PyGILState_Ensure();
	if (pFuncs[__FUNCTION__] != 0)
	{
		PyObject* pFunc = pFuncs[__FUNCTION__];
		PyObject* pResult = PyObject_CallObject(pFunc, 0);
	}
	PyGILState_Release(gstate);
}

bool idaapi proxy_init_debugger(const char * hostname, int portnum, const char * password)
{
	if (inf.filetype == 0)
		return false;
	msg(__FUNCTION__"\n");
	//proxy to python
	int retval = 0;

	if (hostname == 0 || hostname[0] == 0)
		hostname == "localhost";
	if (portnum == 0)
		portnum = 111;

	if (DEBUG)
	{	//fake initial event
		debug_event_t event;
		memset(&event, 0, sizeof(event));
		event.eid = ::PROCESS_START;
		event.pid = PROCESS_PID;
		event.tid = 0x123;
		event.handled = true;
		event.ea = 0x4000000;
		strcpy(event.modinfo.name, "testmain");
		event.modinfo.base = 0x4000000;
		event.modinfo.size = 0x4000;
		event.modinfo.rebase_to = 0x4000000;
		msgqueue.push(event);


		//fake module init
		memset(&event, 0, sizeof(event));
		event.eid = ::LIBRARY_LOAD;
		event.pid = PROCESS_PID;
		event.tid = 0x456;
		event.handled = true;
		event.ea = 0xB000;
		strcpy(event.modinfo.name, "testmodule");
		event.modinfo.base = 0xB000;
		event.modinfo.size = 0x4000;
		event.modinfo.rebase_to = 0xB000;
		msgqueue.push(event);

		//fake thread start
		memset(&event, 0, sizeof(event));
		event.eid = ::THREAD_START;
		event.pid = PROCESS_PID;
		event.tid = 0x789;
		event.handled = true;
		event.ea = 0xB000;
		msgqueue.push(event);


		//fake initial breakpoint
		debug_event_t exc;
		exc.eid = ::EXCEPTION;
		exc.pid = PROCESS_PID;
		exc.tid = 0x54567;
		exc.ea = 0x6c0000;
		//   msg("Exception occurred at: 0x%llx\n", (uint64_t)exc.ea);
		exc.handled = true;
		exc.exc.code = 0xAA55;
		exc.exc.can_cont = false;
		exc.exc.ea = 0x6c00000;
		qstrncpy(exc.exc.info, "test msg", sizeof(exc.exc.info));
		msgqueue.push(exc);

		retval = true;
	}
	else
	{
		PyGILState_STATE gstate = PyGILState_Ensure();
		if (pFuncs[__FUNCTION__] != 0)
		{
			PyObject* pFunc = pFuncs[__FUNCTION__];
			PyObject* pArgs = PyTuple_New(3);
			PyTuple_SetItem(pArgs, 0, Py_BuildValue("s", hostname));
			PyTuple_SetItem(pArgs, 1, Py_BuildValue("i", portnum));
			PyTuple_SetItem(pArgs, 2, Py_BuildValue("s", password));
			PyObject* pResult = PyObject_CallObject(pFunc, pArgs);
			retval = PyObject_IsTrue(pResult);
		}
		PyGILState_Release(gstate);

		_beginthread(proxy_init_debuggee, 0, 0);
	}
	return retval != 0; //True -> 1
}

/// Terminate debugger.
/// This function is called from the main thread.
/// \return success
bool idaapi proxy_term_debugger(void)
{
	msg(__FUNCTION__"\n");

	return true;
}



/// Set debugger options (parameters that are specific to the debugger module).
/// See the definition of ::set_options_t for arguments.
/// See the convenience function in dbg.hpp if you need to call it.
/// The kernel will call this function after reading the debugger specific
/// config file (arguments are: keyword="", type=#IDPOPT_STR, value="")
/// This function is optional.
/// This function is called from the main thread
//Called with keyword == NULL indicates user has selected "Set specific options" button
// in IDA's Debugger setup dialog
const char *idaapi proxy_set_dbg_options(const char *keyword, int pri, int value_type, const void *value)
{
	/*
	called every loading file
	called every switch debbuger
	*/
	msg(__FUNCTION__" %s\n", keyword);
	return IDPOPT_OK;
}

/// Get pointer to debugger specific functions.
/// This function returns a pointer to a structure that holds pointers to
/// debugger module specific functions. For information on the structure
/// layout, please check the corresponding debugger module. Most debugger
/// modules return NULL because they do not have any extensions. Available
/// extensions may be called from plugins.
/// This function is called from the main thread.
const void *idaapi proxy_get_debmod_extensions(void)
{
	msg(__FUNCTION__"\n");
	return NULL;
}



/// Get a pending debug event and suspend the process.
/// This function will be called regularly by IDA.
/// This function is called from debthread.
/// IMPORTANT: commdbg does not expect immediately after a BPT-related event
/// any other event with the same thread/IP - this can cause erroneous
/// restoring of a breakpoint before resume
/// (the bug was encountered 24.02.2015 in pc_linux_upx.elf)


gdecode_t idaapi proxy_get_debug_event(debug_event_t *event, int timeout_ms)
{
	// proxy to python
	gdecode_t retval = GDE_NO_EVENT;
	memset(event, 0, sizeof(event));
	// first gain from local message
	if (!msgqueue.empty())
	{
		retval = GDE_MANY_EVENTS;
		debug_event_t& cmsg = msgqueue.front();
		memcpy(event, &cmsg, sizeof(debug_event_t));
		msgqueue.pop();
		msg(__FUNCTION__" %d\n", cmsg.eid);
		return retval;
	}

	if (DEBUG)
	{

	}
	else
	{
		// then get from proxy-python
		PyGILState_STATE gstate = PyGILState_Ensure();
		if (pFuncs[__FUNCTION__] != 0)
		{
			PyObject* pFunc = pFuncs[__FUNCTION__];
			PyObject* pResult = PyObject_CallObject(pFunc, 0);
			if (pResult != 0 && PyDict_Check(pResult))
			{
				do
				{
					retval = GDE_MANY_EVENTS;
					event->pid = PROCESS_PID;
					event->tid = 0;
					event->ea = BADADDR;
					event->handled = false;
					event_id_t eid;
					PyObject* eidobj = PyDict_GetItemString(pResult, "eid");
					if (eidobj == 0 || !PyInt_Check(eidobj)) // must have eid
					{
						retval = GDE_NO_EVENT;
						break;
					}
					event->eid = (event_id_t)PyInt_AsUnsignedLongMask(eidobj);
					eid = event->eid;

					PyObject* tidobj = PyDict_GetItemString(pResult, "tid");
					if (tidobj != 0 && PyInt_Check(tidobj))
					{
						event->tid = PyInt_AsUnsignedLongMask(tidobj);
					}
					PyObject* eaobj = PyDict_GetItemString(pResult, "ea");
					if (eaobj != 0 && PyInt_Check(eaobj))
					{
						if (sizeof(event->tid) == 8) // do better in the future
							event->ea = PyInt_AsUnsignedLongLongMask(eaobj);
						else
							event->ea = PyInt_AsUnsignedLongMask(eaobj);
					}
					PyObject* handledobj = PyDict_GetItemString(pResult, "handled");
					if (handledobj != 0 && PyBool_Check(handledobj))
					{
						event->handled = PyObject_IsTrue(handledobj);
					}

					switch (eid)
					{
					case PROCESS_START:
					case PROCESS_ATTACH:
					case LIBRARY_LOAD:
					{
						PyObject* nameobj = PyDict_GetItemString(pResult, "name");//necessary
						if (nameobj == 0 || !PyString_Check(nameobj))
						{
							retval = GDE_NO_EVENT;
							break;
						}
						qstrncpy(event->modinfo.name, PyString_AsString(nameobj), sizeof(event->modinfo.name));
						PyObject* baseobj = PyDict_GetItemString(pResult, "base");
						if (baseobj == 0 || !PyInt_Check(baseobj))
						{
							retval = GDE_NO_EVENT;
							break;
						}
						if (sizeof(event->tid) == 8)
							event->modinfo.base = PyInt_AsUnsignedLongLongMask(baseobj);
						else
							event->modinfo.base = PyInt_AsUnsignedLongMask(baseobj);
						PyObject* sizeobj = PyDict_GetItemString(pResult, "size");
						event->modinfo.size = 0;
						if (sizeobj != 0 && PyInt_Check(sizeobj))
						{
							event->modinfo.size = PyInt_AsLong(sizeobj);
						}
						PyObject* rebaseobj = PyDict_GetItemString(pResult, "rebase_to");
						event->modinfo.rebase_to = BADADDR;
						if (rebaseobj != 0 && PyInt_Check(rebaseobj))
						{
							if (sizeof(event->tid) == 8)
								event->modinfo.rebase_to = PyInt_AsUnsignedLongLongMask(rebaseobj);
							else
								event->modinfo.rebase_to = PyInt_AsUnsignedLongMask(rebaseobj);
						}
						event->handled = true;

						// if this module match loaded file name, we would rebase file into memory
						char filename[256];
						get_root_filename(filename, 256);
						if (strstr(event->modinfo.name, filename) != 0)
						{
							//do rebase
							rebase_program(event->modinfo.base - inf.minEA, 0);
						}

						msg(__FUNCTION__" %d\n", eid);
						break;
					}
					case PROCESS_EXIT:
					case THREAD_EXIT:
					{
						PyObject* exit_codeobj = PyDict_GetItemString(pResult, "exit_code");
						if (exit_codeobj != 0 && PyInt_Check(exit_codeobj))
						{
							event->exit_code = PyInt_AsLong(exit_codeobj);
						}
						msg(__FUNCTION__" %d\n", eid);
						break;
					}
					case LIBRARY_UNLOAD:
					case INFORMATION:
					{
						PyObject* infobj = PyDict_GetItemString(pResult, "info");
						if (infobj != 0 && PyString_Check(infobj))
						{
							strcpy(event->info, PyString_AsString(infobj));
						}
						msg(__FUNCTION__" %d\n", eid);
						break;
					}
					case BREAKPOINT:
						//e_breakpoint_t bpt;    todo
					{
						event->bpt.hea = event->bpt.kea = event->ea;
						PyObject* heaobj = PyDict_GetItemString(pResult, "hea");
						if (heaobj != 0 && PyInt_Check(heaobj))
						{
							if (sizeof(event->tid) == 8)
								event->bpt.hea = PyInt_AsUnsignedLongLongMask(heaobj);
							else
								event->bpt.hea = PyInt_AsUnsignedLongMask(heaobj);
						}
						PyObject* keaobj = PyDict_GetItemString(pResult, "kea");
						if (keaobj != 0 && PyInt_Check(keaobj))
						{
							if (sizeof(event->tid) == 8)
								event->bpt.kea = PyInt_AsUnsignedLongLongMask(keaobj);
							else
								event->bpt.kea = PyInt_AsUnsignedLongMask(keaobj);
						}
						msg(__FUNCTION__" %d\n", eid);
						break;
					}
					case EXCEPTION:
					{
						event->exc.ea = event->ea;
						PyObject* codeobj = PyDict_GetItemString(pResult, "code");
						if (codeobj != 0 && PyInt_Check(codeobj))
						{
							event->exc.code = PyInt_AsLong(codeobj);
						}
						PyObject* infoobj = PyDict_GetItemString(pResult, "info");
						if (infoobj != 0 && PyString_Check(infoobj))
						{
							strcpy(event->exc.info, PyString_AsString(infoobj));
						}
						PyObject* can_contobj = PyDict_GetItemString(pResult, "can_cont");
						if (can_contobj != 0 && PyBool_Check(can_contobj))
						{
							event->exc.can_cont = PyObject_IsTrue(can_contobj);
						}
						msg(__FUNCTION__" %d\n", eid);
						break;
					}
					default:
						break;
					}
				} while (false);
			}
		}
		PyGILState_Release(gstate);
	}

	//todo

	return retval;
}

/// Continue after handling the event.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi proxy_continue_after_event(const debug_event_t *event)
{
	//here msg will block
	//msg(__FUNCTION__"\n");

	if (event == NULL || event->eid == 2) {
		return 1;
	}
	switch (event->eid) {
	case PROCESS_START: 
	{

		break; 
	}
	case PROCESS_EXIT:
		msg("proxy_continue_after_event PROCESS_EXIT\n");
		break;
	case THREAD_START:
		msg("proxy_continue_after_event THREAD_START\n");
		break;
	case THREAD_EXIT:
		msg("proxy_continue_after_event THREAD_EXIT\n");
		break;
	case BREAKPOINT: 
	{
		msg("proxy_continue_after_event BREAKPOINT\n");

		break; 
	}
	case STEP: 
	{
		msg("proxy_continue_after_event trying to step\n");
		debug_event_t cont;
		cont.eid = ::STEP;
		cont.pid = PROCESS_PID;
		cont.tid = 1;
		cont.ea = 0x6C00;
		cont.handled = true;
		//msgqueue.push(cont);
		break; 
	}
	case EXCEPTION:
		msg("proxy_continue_after_event EXCEPTION\n");
		if (event->exc.code == 0xAA55)
			return 0;
		break;
	case LIBRARY_LOAD:
		msg("proxy_continue_after_event LIBRARY_LOAD\n");
		break;
	case LIBRARY_UNLOAD:
		msg("proxy_continue_after_event LIBRARY_UNLOAD\n");
		break;
	case INFORMATION:
		msg("proxy_continue_after_event INFORMATION\n");
		break;
	case SYSCALL:
		msg("proxy_continue_after_event SYSCALL\n");
		break;
	case WINMESSAGE:
		msg("proxy_continue_after_event WINMESSAGE\n");
		break;
	case PROCESS_ATTACH:
		msg("proxy_continue_after_event PRICESS_ATTACH\n");
		break;
	case PROCESS_DETACH:
		msg("proxy_continue_after_event PROCESS_DETACH\n");
		break; 
	case PROCESS_SUSPEND:
		msg("proxy_continue_after_event PROCESS_SUSPEND\n");
		return 0;
		break;
	case TRACE_FULL:
		msg("proxy_continue_after_event TRACE_FULL\n");
		break;
	case NO_EVENT:
		break;
	}
	return 1;
}

/// Set exception handling.
/// This function is called from debthread or the main thread.
void idaapi proxy_set_exception_info(const exception_info_t *info, int qty)
{
	// just ignore for now
	msg(__FUNCTION__"\n");
}

/// This function will be called by the kernel each time
/// it has stopped the debugger process and refreshed the database.
/// The debugger module may add information to the database if it wants.
///
/// The reason for introducing this function is that when an event line
/// LOAD_DLL happens, the database does not reflect the memory state yet
/// and therefore we can't add information about the dll into the database
/// in the get_debug_event() function.
/// Only when the kernel has adjusted the database we can do it.
/// Example: for imported PE DLLs we will add the exported function
/// names to the database.
///
/// This function pointer may be absent, i.e. NULL.
/// This function is called from the main thread.
void idaapi proxy_stopped_at_debug_event(bool /*dlls_added*/)
{
	msg(__FUNCTION__"\n");
}

/// \name Threads
/// The following functions manipulate threads.
/// These functions are called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi proxy_thread_suspend(thid_t /*tid*/)
{ ///< Suspend a running thread
	MSG(__FUNCTION__"\n");
	return 1;
}

int idaapi proxy_thread_continue(thid_t /*tid*/)
{ ///< Resume a suspended thread
	MSG(__FUNCTION__"\n");
	return 1;
}

int idaapi proxy_set_resume_mode(thid_t /*tid*/, resume_mode_t resmod)
{ ///< Specify resume action
	MSG(__FUNCTION__"\n");
	return 1;
}


/// \name Remote file
/// Open/close/read a remote file.
/// These functions are called from the main thread
/// -1-error
int idaapi proxy_open_file(const char *file, uint32 * fsize, bool readonly)
{
	MSG(__FUNCTION__"\n");
	return -1;
}

void idaapi proxy_close_file(int fn)
{
	MSG(__FUNCTION__"\n");
	return;
}

ssize_t idaapi proxy_read_file(int fn, uint32 off, void * buf, size_t size)
{
	MSG(__FUNCTION__"\n");
	return -1;
}


/// This function is called from main thread
ssize_t idaapi proxy_write_file(int fn, uint32 off, const void * buf, size_t size)
{
	MSG(__FUNCTION__"\n");
	return -1;
}

/// \name Memory manipulation
/// The following functions manipulate bytes in the memory.

/// Get information on the memory areas.
/// The debugger module fills 'areas'. The returned vector MUST be sorted.
/// This function is called from debthread.
/// \retval  -3  use idb segmentation
/// \retval  -2  no changes
/// \retval  -1  the process does not exist anymore
/// \retval   0  failed
/// \retval   1  new memory layout is returned
int idaapi proxy_get_memory_info(meminfo_vec_t &areas)
{
	msg(__FUNCTION__"\n");
	// proxy to python 
	int retval = -2;

	if (DEBUG)
	{
		//fake info
		memory_info_t info;
		memset(&info, 0, sizeof(info));
		info.name = "test";
		info.sclass = "test1";
		info.startEA = 0xB000;
		info.endEA = 0x1B000;
		info.sbase = 0x10;
		
		areas.add_unique(info);
		retval = 1;
	}
	else
	{
		PyGILState_STATE gstate = PyGILState_Ensure();
		if (pFuncs[__FUNCTION__] != 0)
		{
			PyObject* pFunc = pFuncs[__FUNCTION__];
			PyObject* pResult = PyObject_CallObject(pFunc, 0);
			if (PyList_Check(pResult))
			{
				for (int i = 0; i < PyList_Size(pResult); i++)
				{
					memory_info_t meminfo;
					memset(&meminfo, 0, sizeof(meminfo));
					PyObject* memitem = PyList_GetItem(pResult, i);
					if (PyDict_Check(memitem))
					{
						PyObject* nameitem = PyDict_GetItemString(memitem, "name");
						if (!PyString_Check(nameitem))
							continue;
						meminfo.name = PyString_AsString(nameitem);
						PyObject* sclassitem = PyDict_GetItemString(memitem, "sclass");
						if (!PyString_Check(sclassitem))
							continue;
						meminfo.sclass = PyString_AsString(sclassitem);
						PyObject* startEAitem = PyDict_GetItemString(memitem, "startEA");
						if (!PyInt_Check(startEAitem))
							continue;
						meminfo.startEA = PyInt_AsLong(startEAitem);
						PyObject* endEAitem = PyDict_GetItemString(memitem, "endEA");
						if (!PyInt_Check(endEAitem))
							continue;
						meminfo.endEA = PyInt_AsLong(endEAitem);
						PyObject* permitem = PyDict_GetItemString(memitem, "perm");
						if (!PyInt_Check(permitem))
							continue;
						meminfo.perm = PyInt_AsLong(permitem);
						meminfo.bitness = 1;

						areas.add_unique(meminfo);
					}
				}
			}
			retval = 1;
		}
		PyGILState_Release(gstate);
	}

	return retval;
}

/// Read process memory.
/// Returns number of read bytes.
/// This function is called from debthread.
/// \retval 0  read error
/// \retval -1 process does not exist anymore
ssize_t idaapi proxy_read_memory(ea_t ea, void *buffer, size_t size)
{
	msg(__FUNCTION__" %x %x\n", ea, size);
	//proxy to python
	int retval = 0;

	if (DEBUG)
	{
		memset(buffer, 0xcc, size);
		retval = size;
	}
	else
	{
		PyGILState_STATE gstate = PyGILState_Ensure();
		if (pFuncs[__FUNCTION__] != 0)
		{
			PyObject* pFunc = pFuncs[__FUNCTION__];
			PyObject* pArgs = PyTuple_New(2);
			PyTuple_SetItem(pArgs, 0, Py_BuildValue("i", ea));
			PyTuple_SetItem(pArgs, 1, Py_BuildValue("i", size));
			PyObject* pResult = PyObject_CallObject(pFunc, 0);
			if (PyString_Check(pResult))
			{
				memcpy(buffer, PyString_AsString(pResult), size);
			}
		}
		PyGILState_Release(gstate);
	}

	return size;
}

ssize_t idaapi proxy_read_memory(ea_t ea, void *buffer, size_t size, bool sync)
{
	msg(__FUNCTION__" %x %x\n", ea, size);
	//proxy to python
	int retval = 0;

	if (DEBUG)
	{
		memset(buffer, 0xcc, size);
		retval = size;
	}
	else
	{
		if (pFuncs[__FUNCTION__] != 0)
		{
			PyObject* pFunc = pFuncs[__FUNCTION__];
			PyObject* pArgs = PyTuple_New(2);
			PyTuple_SetItem(pArgs, 0, Py_BuildValue("i", ea));
			PyTuple_SetItem(pArgs, 1, Py_BuildValue("i", size));
			PyObject* pResult = PyObject_CallObject(pFunc, 0);
			if (PyString_Check(pResult))
			{
				memcpy(buffer, PyString_AsString(pResult), size);
			}
		}
	}

	return size;
}

/// Write process memory.
/// This function is called from debthread.
/// \return number of written bytes, -1 if fatal error
ssize_t idaapi proxy_write_memory(ea_t ea, const void *buffer, size_t size)
{
	MSG(__FUNCTION__"\n");
	//proxy to python
	int retval = 0;

	if (DEBUG)
	{
		retval = size;
	}
	else
	{
		PyGILState_STATE gstate = PyGILState_Ensure();
		if (pFuncs[__FUNCTION__] != 0)
		{
			PyObject* pFunc = pFuncs[__FUNCTION__];
			PyObject* pArgs = PyTuple_New(2);
			PyTuple_SetItem(pArgs, 0, Py_BuildValue("i", ea));
			PyTuple_SetItem(pArgs, 1, Py_BuildValue("s#", buffer, size));
			PyObject* pResult = PyObject_CallObject(pFunc, 0);
			if (PyObject_IsTrue(pResult))
			{
				retval = size;
			}
		}
		PyGILState_Release(gstate);
	}

	return retval;
}


/// Map process address.
/// This function may be absent.
/// This function is called from debthread.
/// \param off      offset to map
/// \param regs     current register values. if regs == NULL, then perform
///                 global mapping, which is independent on used registers
///                 usually such a mapping is a trivial identity mapping
/// \param regnum   required mapping. maybe specified as a segment register number
///                 or a regular register number if the required mapping can be deduced
///                 from it. for example, esp implies that ss should be used.
/// \return mapped address or #BADADDR


ea_t idaapi proxy_map_address(ea_t off, const regval_t * regs, int regnum)
{
	//msg(__FUNCTION__"off=%x regnum=%d\n", off, regnum);
	return BADADDR;
}


/// Rebase database if the debugged program has been rebased by the system.
/// This function is called from the main thread.
void idaapi proxy_rebase_if_required_to(ea_t new_base)
{
	//here msg will block
//	msg(__FUNCTION__"%x\n", new_base);
}



/// Return information about the n-th "compatible" running process.
/// If n is 0, the processes list is reinitialized.
/// This function is called from the main thread.
/// \retval 1  ok
/// \retval 0  failed
/// \retval -1 network error
int idaapi proxy_process_get_info(int n, process_info_t *info)
{
	//can be extended in the future
	if (n) {
		return 0;
	}
	qstrncpy(info->name, PROCESS_NAME, sizeof(info->name));
	info->pid = PROCESS_PID;//at will
	return 1;
}



/// Start an executable to debug.
/// This function is called from debthread.
/// \param path              path to executable
/// \param args              arguments to pass to executable
/// \param startdir          current directory of new process
/// \param dbg_proc_flags    \ref DBG_PROC_
/// \param input_path        path to database input file.
///                          (not always the same as 'path' - e.g. if you're analyzing
///                          a dll and want to launch an executable that loads it)
/// \param input_file_crc32  CRC value for 'input_path'
/// \retval  1                    ok
/// \retval  0                    failed
/// \retval -2                    file not found (ask for process options)
/// \retval  1 | #CRC32_MISMATCH  ok, but the input file crc does not match
/// \retval -1                    network error
int idaapi proxy_start_process(const char * path, const char *args, const char * startdir,
	int dbg_proc_flags, const char *input_path, uint32 input_file_crc32)
{
	MSG(__FUNCTION__"\n");
	return 1;
}

/// Attach to an existing running process.
/// event_id should be equal to -1 if not attaching to a crashed process.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi proxy_attach_process(pid_t pid, int event_id)
{
	msg(__FUNCTION__"\n");


	return 1;
}

/// Detach from the debugged process.
/// May be called while the process is running or suspended.
/// Must detach from the process in any case.
/// The kernel will repeatedly call get_debug_event() and until ::PROCESS_DETACH.
/// In this mode, all other events will be automatically handled and process will be resumed.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi proxy_detach_process(void)
{
	MSG(__FUNCTION__"\n");
	return 1;
}



/// Prepare to pause the process.
/// Normally the next get_debug_event() will pause the process
/// If the process is sleeping then the pause will not occur
/// until the process wakes up. The interface should take care of
/// this situation.
/// If this function is absent, then it won't be possible to pause the program.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi proxy_prepare_to_pause_process(void)
{
	
	// proxy to python
	int retval = 0;

	if (DEBUG)
	{
		retval = 1;
	}
	else
	{
		PyGILState_STATE gstate = PyGILState_Ensure();
		if (pFuncs[__FUNCTION__] != 0)
		{
			PyObject* pFunc = pFuncs[__FUNCTION__];
			PyObject* pResult = PyObject_CallObject(pFunc, 0);
			if (PyInt_Check(pResult))
			{
				retval = PyInt_AsLong(pResult);
			}
		}
		PyGILState_Release(gstate);
	}

	msg(__FUNCTION__" %d\n", retval);
	return retval;
}

/// Stop the process.
/// May be called while the process is running or suspended.
/// Must terminate the process in any case.
/// The kernel will repeatedly call get_debug_event() and until ::PROCESS_EXIT.
/// In this mode, all other events will be automatically handled and process will be resumed.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi proxy_exit_process(void)
{
	msg(__FUNCTION__"\n");

	debug_event_t stop;
	stop.eid = ::PROCESS_EXIT;
	stop.pid = PROCESS_PID;
	stop.tid = 1;
	stop.ea = inf.minEA;
	stop.exit_code = 0;
	msgqueue.push(stop);

	return 1;
}

/// Get (store to out_pattrs) process/debugger-specific runtime attributes.
/// This function is called from main thread.
void idaapi proxy_get_debapp_attrs(debapp_attrs_t *out_pattrs)
{
	/*
	called every loading file
	called every run / attach option
	called every switch debugger
	*/
	msg(__FUNCTION__"\n");

	out_pattrs->addrsize = (inf.lflags & LFLG_64BIT) ? 8 : 4;
	if (inf.filetype == f_PE) {
		if (inf.lflags & LFLG_64BIT) {
			out_pattrs->platform = "win64";
		}
		else {
			out_pattrs->platform = "win32";
		}
	}
	else if (inf.filetype == f_ELF) {
		if (inf.lflags & LFLG_64BIT) {
			out_pattrs->platform = "linux64";
		}
		else {
			out_pattrs->platform = "linux";
		}
	}
	else if (inf.filetype == f_MACHO) {
		if (inf.lflags & LFLG_64BIT) {
			out_pattrs->platform = "macosx64";
		}
		else {
			out_pattrs->platform = "macosx";
		}
	}
	else {
		//file unload
		out_pattrs->platform = "gdb";
	}
	return;
}

/// Calculate the call stack trace.
/// This function is called when the process is suspended and should fill
/// the 'trace' object with the information about the current call stack.
/// If this function is missing or returns false, IDA will use the standard
/// mechanism (based on the frame pointer chain) to calculate the stack trace
/// This function is called from the main thread.
/// \return success
bool idaapi proxy_update_call_stack(thid_t tid, call_stack_t * trace)
{
	MSG(__FUNCTION__"\n");
	return false;
}

/// Call application function.
/// This function calls a function from the debugged application.
/// This function is called from debthread
/// \param func_ea      address to call
/// \param tid          thread to use
/// \param fti          type information for the called function
/// \param nargs        number of actual arguments
/// \param regargs      information about register arguments
/// \param stkargs      memory blob to pass as stack arguments (usually contains pointed data)
///                     it must be relocated by the callback but not changed otherwise
/// \param retregs      function return registers.
/// \param[out] errbuf  the error message. if empty on failure, see 'event'.
///                     should not be filled if an appcall exception
///                     happened but #APPCALL_DEBEV is set
/// \param[out] event   the last debug event that occurred during appcall execution
///                     filled only if the appcall execution fails and #APPCALL_DEBEV is set
/// \param options      appcall options, usually taken from \inf{appcall_options}.
///                     possible values: combination of \ref APPCALL_  or 0
/// \return ea of stkargs blob, #BADADDR if failed and errbuf is filled
ea_t idaapi proxy_appcall(ea_t func_ea, thid_t tid, const struct func_type_data_t * fti,
	int nargs, const struct regobjs_t * regargs, struct relobj_t * stkargs,
	struct regobjs_t * retregs, qstring * errbuf, debug_event_t * event, int options)
{
	MSG(__FUNCTION__"\n");
	return BADADDR;

}

/// Cleanup after appcall().
/// The debugger module must keep the stack blob in the memory until this function
/// is called. It will be called by the kernel for each successful appcall().
/// There is an exception: if #APPCALL_MANUAL, IDA may not call cleanup_appcall.
/// If the user selects to terminate a manual appcall, then cleanup_appcall will be called.
/// Otherwise, the debugger module should terminate the appcall when the called
/// function returns.
/// This function is called from debthread.
/// \retval  2  ok, there are pending events
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi proxy_cleanup_appcall(thid_t tid)
{
	MSG(__FUNCTION__"\n");
	return 1;

}

/// Perform a debugger-specific function.
/// This function is called from debthread
int idaapi proxy_send_ioctl(int fn, const void * buf, size_t size, void ** poutbuf, ssize_t * poutsize)
{
	MSG(__FUNCTION__"\n");
	return -1;
}


/// Execute a command on the remote computer.
/// \return exit code
int idaapi proxy_rexec(const char *cmdline)
{
	MSG(__FUNCTION__"\n");
	return 0;
}


/// Read thread registers.
/// This function is called from debthread.
/// \param tid      thread id
/// \param clsmask  bitmask of register classes to read
/// \param regval   pointer to vector of regvals for all registers.
///                 regval is assumed to have debugger_t::registers_size elements
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi proxy_read_registers(thid_t tid, int clsmask, regval_t *values)
{
	msg(__FUNCTION__" %d\n", tid);
	int retval = 0;

	if (DEBUG)
	{
		retval = 1;
	}
	else
	{
		PyGILState_STATE gstate = PyGILState_Ensure();
		if (pFuncs[__FUNCTION__] != 0)
		{
			PyObject* pFunc = pFuncs[__FUNCTION__];
			PyObject* pArgs = PyTuple_New(2);
			int regnum = getnumber(registers);
			PyObject* pRegNames = PyList_New(regnum);
			PyTuple_SetItem(pArgs, 0, Py_BuildValue("i", tid));
			PyTuple_SetItem(pArgs, 1, pRegNames);
			//copy reg names into list
			for (int i = 0; i < regnum; i++)
			{
				PyList_SetItem(pRegNames, i, PyString_FromString(registers[i].name));
			}
			PyObject* pResult = PyObject_CallObject(pFunc, pArgs);
			if (PyList_Check(pResult))
			{
				for (int i = 0; i < PyList_Size(pResult) && i < regnum; i++)
				{
					PyObject* regval = PyList_GetItem(pResult, i);
					if (PyInt_Check(regval))
					{
						//deal with int only for now
						values[i].ival = PyInt_AsLong(regval);
					}
				}
				retval = 1;
			}
		}
		PyGILState_Release(gstate);
	}

	return retval;
}

/// Write one thread register.
/// This function is called from debthread.
/// \param tid     thread id
/// \param regidx  register index
/// \param regval  new value of the register
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi proxy_write_register(thid_t tid, int regidx, const regval_t *value)
{
	MSG(__FUNCTION__"\n");
	int retval = 0;
	if (regidx > getnumber(registers))
		return 0;

	if (DEBUG)
	{
		retval = 1;
	}
	else
	{
		PyGILState_STATE gstate = PyGILState_Ensure();
		if (pFuncs[__FUNCTION__] != 0)
		{
			PyObject* pFunc = pFuncs[__FUNCTION__];
			PyObject* pArgs = PyTuple_New(3);
			PyTuple_SetItem(pArgs, 0, Py_BuildValue("i", tid));
			PyTuple_SetItem(pArgs, 1, Py_BuildValue("s", registers[regidx]));
			PyTuple_SetItem(pArgs, 2, Py_BuildValue("i", value->ival));
			PyObject* pResult = PyObject_CallObject(pFunc, pArgs);
			if (PyObject_IsTrue(pResult))
				retval = 1;
		}
		PyGILState_Release(gstate);
	}

	return retval;
}

/// Get information about the base of a segment register.
/// Currently used by the IBM PC module to resolve references like fs:0.
/// This function is called from debthread.
/// \param tid         thread id
/// \param sreg_value  value of the segment register (returned by get_reg_val())
/// \param answer      pointer to the answer. can't be NULL.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi proxy_thread_get_sreg_base(thid_t tid, int sreg_value, ea_t *answer)
{
	MSG(__FUNCTION__"\n");
	return 1;
}

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_DBG | PLUGIN_HIDE,   // plugin flags
	plugin_init,                 // initialize
	plugin_term,                 // terminate. this pointer may be NULL.
	plugin_run,                  // invoke plugin
	PLUGIN_NAME,                   // long comment about the plugin
								   // it could appear in the status line
								   // or as a hint
								   PLUGIN_NAME,                   // multiline help about the plugin
								   PLUGIN_NAME,            // the preferred short name of the plugin
								   ""                    // the preferred hotkey to run the plugin
};

