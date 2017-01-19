

#ifndef __PROXYDBG_H
#define __PROXYDBG_H

#ifdef PACKED
#undef PACKED
#endif

#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS

#ifdef __NT__
#include <windows.h>
#include <winnt.h>
#else
//#ifndef __NT__
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#endif


#include <pro.h>
#include <ida.hpp>
#include <idd.hpp>
#include <kernwin.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <srarea.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <entry.hpp>
#include <dbg.hpp>
#include <ua.hpp>

#include <Python.h>

bool idaapi proxy_init_debugger(const char * /*hostname*/, int /*portnum*/, const char * /*password*/);
bool idaapi proxy_term_debugger(void);
int idaapi proxy_process_get_info(int n, process_info_t *info);
int idaapi proxy_start_process(const char * /*path*/,
	const char *args,
	const char * /*startdir*/,
	int /*dbg_proc_flags*/,
	const char *input_path,
	uint32 /*input_file_crc32*/);
int idaapi proxy_attach_process(pid_t /*pid*/, int /*event_id*/);
int idaapi proxy_detach_process(void);
void idaapi proxy_rebase_if_required_to(ea_t /*new_base*/);
int idaapi proxy_prepare_to_pause_process(void);
int idaapi proxy_exit_process(void);
gdecode_t idaapi proxy_get_debug_event(debug_event_t *event, int /*timeout_ms*/);
int idaapi proxy_continue_after_event(const debug_event_t *event);
void idaapi proxy_set_exception_info(const exception_info_t *info, int qty);
void idaapi proxy_stopped_at_debug_event(bool /*dlls_added*/);
int idaapi proxy_thread_suspend(thid_t /*tid*/);
int idaapi proxy_thread_continue(thid_t /*tid*/);
int idaapi proxy_set_resume_mode(thid_t /*tid*/, resume_mode_t resmod);
int idaapi proxy_read_registers(thid_t /*tid*/, int clsmask, regval_t *values);
int idaapi proxy_write_register(thid_t /*tid*/, int regidx, const regval_t *value);
int idaapi proxy_thread_get_sreg_base(thid_t /*tid*/, int /*sreg_value*/, ea_t *answer);
int idaapi proxy_get_memory_info(meminfo_vec_t &areas);
ssize_t idaapi proxy_read_memory(ea_t ea, void *buffer, size_t size);
ssize_t idaapi proxy_write_memory(ea_t ea, const void *buffer, size_t size);
int idaapi proxy_is_ok_bpt(bpttype_t type, ea_t ea, int /*len*/);
int idaapi proxy_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel);
int idaapi proxy_update_lowcnds(const lowcnd_t * /*lowcnds*/, int nlowcnds);
int idaapi proxy_open_file(const char *file, uint32 * /*fsize*/, bool /*readonly*/);
void idaapi proxy_close_file(int /*fn*/);
ssize_t idaapi proxy_read_file(int /*fn*/, uint32 /*off*/, void * /*buf*/, size_t /*size*/);
ea_t idaapi proxy_map_address(ea_t off, const regval_t * /*regs*/, int /*regnum*/);
const char *idaapi proxy_set_dbg_options(const char *keyword, int /*pri*/,
	int value_type, const void *value);
const void *idaapi proxy_get_debmod_extensions(void);
bool idaapi proxy_update_call_stack(thid_t /*tid*/, call_stack_t * /*trace*/);
ea_t idaapi proxy_appcall(
	ea_t /*func_ea*/,
	thid_t /*tid*/,
	const struct func_type_data_t * /*fti*/,
	int /*nargs*/,
	const struct regobjs_t * /*regargs*/,
	struct relobj_t * /*stkargs*/,
	struct regobjs_t * /*retregs*/,
	qstring * /*errbuf*/,
	debug_event_t * /*event*/,
	int /*options*/);
int idaapi proxy_cleanup_appcall(thid_t /*tid*/);
int idaapi proxy_eval_lowcnd(thid_t /*tid*/, ea_t ea);
ssize_t idaapi proxy_write_file(int /*fn*/, uint32 /*off*/, const void * /*buf*/, size_t /*size*/);
int idaapi proxy_send_ioctl(int /*fn*/, const void * /*buf*/, size_t /*size*/, void ** /*poutbuf*/, ssize_t * /*poutsize*/);
bool idaapi proxy_dbg_enable_trace(thid_t /*tid*/, bool /*enable*/, int /*trace_flags*/);
bool idaapi proxy_is_tracing_enabled(thid_t /*tid*/, int /*tracebit*/);
int idaapi proxy_rexec(const char *cmdline);
void idaapi proxy_get_debapp_attrs(debapp_attrs_t *out_pattrs);



/*
	Interface
*/
debugger_t *get_dbg();//idd.hpp
text_options_t get_dto();//ida.hpp
processor_t get_ph();//idp.hpp
asm_t get_ash();//idp.hpp
idainfo get_inf();//ida.hpp

#endif
