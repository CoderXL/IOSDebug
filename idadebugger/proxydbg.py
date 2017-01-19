import socket
import thread
#import threading
import re
from xml.dom.minidom import parse
import xml.dom.minidom
import binascii
import struct
import Queue
import time
import pydevd

DEBUG = 1

DEFAULT_TIMEOUT = 0.05  # in the future this should be self dynamicly adapted denpend on network
DEFAULT_RETRYTIME = 3
HANDSHAKE_RETRYTIME = 5

DBG_FLAG_REMOTE = 1
DBG_FLAG_NOHOST = 2
DBG_FLAG_FAKE_ATTACH = 4
DBG_FLAG_HWDATBPT_ONE = 8
DBG_FLAG_CAN_CONT_BPT = 0x10
DBG_FLAG_NEEDPORT = 0x20
DBG_FLAG_DONT_DISTURB = 0x40
DBG_FLAG_SAFE = 0x80
DBG_FLAG_CLEAN_EXIT = 0x100
DBG_FLAG_USE_SREGS = 0x200
DBG_FLAG_NOSTARTDIR = 0x400
DBG_FLAG_NOPARAMETERS = 0x800
DBG_FLAG_NOPASSWORD = 0x1000
DBG_FLAG_CONNSTRING = 0x2000
DBG_FLAG_SMALLBLKS = 0x4000
DBG_FLAG_MANMEMINFO = 0x8000
DBG_FLAG_EXITSHOTOK = 0x10000
DBG_FLAG_VIRTHREADS = 0x20000
DBG_FLAG_LOWCNDS = 0x40000
DBG_FLAG_DEBTHREAD = 0x80000
DBG_FLAG_DEBUG_DLL = 0x100000
DBG_FLAG_FAKE_MEMORY = 0x200000
DBG_FLAG_ANYSIZE_HWBPT = 0x400000
DBG_FLAG_TRACER_MODULE = 0x800000
DBG_FLAG_PREFER_SWBPTS = 0x1000000

REGISTER_READONLY = 0x0001
REGISTER_IP = 0x0002
REGISTER_SP = 0x0004
REGISTER_FP = 0x0008
REGISTER_ADDRESS = 0x0010
REGISTER_CS = 0x0020
REGISTER_SS = 0x0040
REGISTER_NOLF = 0x0080
REGISTER_CUSTFMT = 0x010

dt_byte = 0
dt_word = 1
dt_dword = 2
dt_float = 3
dt_double = 4
dt_tbyte = 5
dt_packreal = 6
dt_qword = 7
dt_byte16 = 8
dt_code = 9
dt_void = 10
dt_fword = 11
dt_bitfild = 12
dt_string = 13
dt_unicode = 14
dt_3byte = 15
dt_ldbl = 16
dt_byte32 = 17
dt_byte64 = 18

NO_EVENT = 0x00000000
PROCESS_START = 0x00000001
PROCESS_EXIT = 0x00000002
THREAD_START = 0x00000004
THREAD_EXIT = 0x00000008
BREAKPOINT = 0x00000010
STEP = 0x00000020
EXCEPTION = 0x00000040
LIBRARY_LOAD = 0x00000080
LIBRARY_UNLOAD = 0x00000100
INFORMATION = 0x00000200
SYSCALL = 0x00000400
WINMESSAGE = 0x00000800
PROCESS_ATTACH = 0x00001000
PROCESS_DETACH = 0x00002000
PROCESS_SUSPEND = 0x00004000
TRACE_FULL = 0x00008000

# these magic for macho
IOS_MH_MAGIC = 0xfeedface
IOS_MH_CIGAM = 0xcefaedfe
IOS_MH_MAGIC_64 = 0xfeedfacf
IOS_MH_CIGAM_64 = 0xcffaedfe
#MH_OBJECT	= 0x1
IOS_MH_EXECUTE	= 0x2
IOS_MH_DYLIB	= 0x6
IOS_MH_DYLINKER	= 0x7
LC_SEGMENT = 0x1
# these magic for android-linux
ANDROID_DEX = 0x0A786564
ANDROID_ODEX = 0x0A786565
ANDROID_ELF = 0x464C457F
ANDROID_APK = 0x04034B50
# others todo


# every packet should retry 3 times to retrieve the real response
def printdata(tag, data):
    print("%s0x%lx" % (tag, len(data)))
    align = 32
    linenum = len(data) / align + 1
    emptynum = linenum * align - len(data)
    for i in range(0, emptynum):
        if type(data) == str:
            data = data + "\0"
        elif type(data) == list:
            data.append(0)
    title = ""
    for i in range(0, align):
        title = title + "%02X " % i
    print(title)
    if type(data) == str:
        for i in range(0, linenum):
            left = ""
            right = ""
            for j in range(0, align):
                left = left + "%02X " % ord(data[i * align + j])
                right = right + data[i * align + j]
            print(left + " " + right.replace("\n", "").replace("\r", ""))
    elif type(data) == list:
        for i in range(0, linenum):
            left = ""
            right = ""
            for j in range(0, align):
                left = left + "%02X " % data[i * align + j]
                right = right + chr(data[i * align + j])
            print(left + " " + right.replace("\n", "").replace("\r", ""))


class GDBRemoteCommunicationClient(object):
    # constants
    bufsize = 65536
    DEBUGGER_TYPE_LLDB = 1
    DEBUGGER_TYPE_GDB = 2

    use_sync = True  # default setting
    socket = None
    connected = True
    inited = False
    debugger_type = -1
    cpu_arch = -1
    os_type = -1  # currently unused
    istarget_little_endian = True

    general_info = {}
    qsupport_feature = []

    packet_queue = Queue.Queue()    #packet queue
    packet_lock = thread.allocate_lock()

    # runtime info
    module_info = []
    thread_info = []
    register_info = []
    mainname = ""
    mainbase = 0
    mainsize = 0

    # cpu register info [name offset size],[name offset size]
    # lldb:readfrom qRegisterInfo?   gdb:readfrom qXfer:features:read:arm-core.xml:0,fff
    reg_layout = []

    msgQueue = Queue.Queue()
    msg_lock = thread.allocate_lock()
    readthread = None

    m_supports_vCont_c = False
    m_supports_vCont_C = False
    m_supports_vCont_s = False
    m_supports_vCont_S = False
    m_supports_vCont_all = False
    m_supports_vCont_any = False
    m_supports_detach_stay_stopped = None
    m_supports_qXfer_auxv_read = False
    m_supports_qXfer_libraries_svr4_read = False
    m_supports_qXfer_libraries_read = False
    m_supports_augmented_libraries_svr4_read = False
    m_supports_threads_read = False
    m_supports_qXfer_features_read = False
    m_supports_qEcho = False
    m_max_packet_size = 0

    eUnsupported = -2
    eError = -1
    eOK = 0
    eAck = 1
    eNack = 2
    eResponse = 3

    vcont_continue = 0
    vcont_continue_sig = 1
    vcont_step = 2
    vcont_step_sig = 3
    vcont_t = 4

    # cputype defines
    CPU_ARCH_ABI64 = 0x01000000
    CPU_TYPE_VAX = 1
    CPU_TYPE_MC680x0 = 6
    CPU_TYPE_I386 = 7
    CPU_TYPE_X86_64 = CPU_TYPE_I386 | CPU_ARCH_ABI64
    CPU_TYPE_MIPS = 8
    CPU_TYPE_MC98000 = 10
    CPU_TYPE_HPPA = 11
    CPU_TYPE_ARM = 12
    CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64
    CPU_TYPE_MC88000 = 13
    CPU_TYPE_SPARC = 14
    CPU_TYPE_I860 = 15
    CPU_TYPE_ALPHA = 16
    CPU_TYPE_POWERPC = 18
    CPU_TYPE_POWERPC64 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64

    # breakpoint type
    eStoppointInvalid = -1
    eBreakpointSoftware = 0
    eBreakpointHardware = 1
    eWatchpointWrite = 2
    eWatchpointRead = 3
    eWatchpointReadWrite = 4

    def ReadPacketThread(self):
        End = False
        try:
            while self.connected:
                response = self.socket.recv(self.bufsize)
                print "recv:", response
                if type(response) == str:
                    # this packet is valid except empty
                    response = self.CheckForPacket(response)
                    self.packet_lock.acquire()
                    self.packet_queue.put_nowait(response)
                    self.packet_lock.release()
        except Exception as e:
            self.connected = False
            self.socket.close()
            print e
        print "ReadPacketThread exit"

    def ReadPacketAsync(self, timeout=DEFAULT_TIMEOUT):
        result = None
        self.packet_lock.acquire()
        #for debug
        print "msg%d\n" % self.packet_queue.qsize()

        if self.connected:
            if not self.packet_queue.empty():
                result = self.packet_queue.get_nowait()
            else:
                time.sleep(timeout)
                if self.packet_queue.empty():
                    result =  ""
                else:
                    result = self.packet_queue.get_nowait()
        self.packet_lock.release()
        return result

    def ReadPacketSync(self, timeout=DEFAULT_TIMEOUT):
        if not self.connected:
            return None
        response = None
        self.socket.settimeout(timeout)
        try:
            response = self.socket.recv(self.bufsize)
            print "recv:", response
            if type(response) == str:
                # this packet is valid except empty
                response = self.CheckForPacket(response)
        except Exception as e:
            if type(e) == socket.timeout:
                return ""
            self.connected = False
            print e
        return response

    def ReadPacket(self, timeout=DEFAULT_TIMEOUT):
        if self.use_sync:
            return self.ReadPacketSync(timeout)
        else:
            return self.ReadPacketAsync(timeout)

    def InsertMsg(self, msg):
        self.msg_lock.acquire()
        self.msgQueue.put_nowait(msg)
        self.msg_lock.release()
        print "insert:", msg

    def GetCurrentIns(self):
        if "EIP" in self.register_info:
            insoff = self.register_info["EIP"]
        elif "PC" in self.register_info:
            insoff = self.register_info["PC"]
        return insoff

    def init(self):
        # determine debugger_type and cpu_type
        if self.GetQXferFeaturesReadSupported():
            # see if debugger is gdb
            xmldata = self.ReadExtFeature("features", "target.xml")
            if type(xmldata) == str:
                # in case of undefined namespace
                dom = xml.dom.minidom.parseString(xmldata)
                node_target = dom.getElementsByTagName("target")[0]
                node_architecture = node_target.getElementsByTagName("architecture")
                if len(node_architecture) > 0 and len(node_architecture[0].childNodes) > 0:
                    self.general_info["arch"] = node_architecture[0].childNodes[0].nodeValue
                node_osabi = node_target.getElementsByTagName("osabi")
                if len(node_osabi) > 0 and len(node_osabi[0].childNodes) > 0:
                    self.general_info["osabi"] = node_osabi[0].childNodes[0].nodeValue
                regsinfo = []
                for include in node_target.getElementsByTagName("xi_include"):
                    xmldata = self.ReadExtFeature("features", include.getAttribute("href"))
                    subdom = xml.dom.minidom.parseString(xmldata)
                    regsinfo = regsinfo + subdom.getElementsByTagName("reg")
                self.GetGDBServerRegisterInfo(regsinfo)
                self.debugger_type = self.DEBUGGER_TYPE_GDB
                if "arch" in self.general_info:
                    if self.general_info["arch"] == 'i386':
                        self.cpu_arch = self.CPU_TYPE_I386
                    else:  # unimplemented yet
                        print "unhandled arch", self.general_info["arch"]
                        pass
            else:
                # unimplemented yet!
                pass
        if self.debugger_type == -1 and self.GetGDBServerVersion():
            ## use GetGDBServerVersion to detect lldb server
            self.debugger_type = self.DEBUGGER_TYPE_LLDB
            self.GetHostInfo()
            if "cputype" in self.general_info:
                self.cpu_arch = self.general_info["cputype"]
            self.BuildDynamicRegisterInfo()
        if self.debugger_type == -1:
            raise  # we cannot handle this yet

        # fake moduleload event
        maintid = self.GetDefaultThreadID()
        self.register_info = self.ReadAllRegisters(maintid)
        self.module_info = self.GetLoadedModuleList()
        self.thread_info = self.GetCurrentThreadIDs()
        insoff = self.GetCurrentIns()

        msg = {"eid": PROCESS_START, "tid": maintid, "name": self.mainname, "base": self.mainbase,
               "size": self.mainsize, "rebase_to": self.mainbase, "ea": insoff}
        self.InsertMsg(msg)

        msg = {"eid": EXCEPTION, "tid": maintid, "ea": insoff, "code": 0xAA55,
               "info": "initial break", "handled": False}
        self.InsertMsg(msg)
        #
        # for mod in self.module_info:
        #     base = mod["begin"]
        #     name = mod["name"]
        #     size = mod["size"]
        #     if base != self.mainbase:
        #         msg = {"eid": LIBRARY_LOAD, "tid": maintid, "ea": base, "name": name, "base": base,
        #                "size": size, "rebase_to": base}
        #         print "insert:", msg
        #         self.msgQueue.put_nowait(msg)
        #     else:
        #         msg = {"eid": LIBRARY_LOAD, "tid": maintid, "ea": base, "name": name, "base": base,
        #                "size": size, "ismain": True}
        #         #               print "insert:", msg
        #         #                self.msgQueue.put_nowait(msg)
        #
        # # fake threadstart event
        # for thread in self.thread_info:
        #     msg = {"eid": THREAD_START, "tid": self.thread_info[thread]["id"], "ea": 0}
        #     #           print "insert:", msg
        #     #           self.msgQueue.put_nowait(msg)  #need ea?
        # msg = {"eid": PROCESS_SUSPEND, "tid": self.GetDefaultThreadID(), "ea": 0x400000}
        # self.msgQueue.put_nowait(msg)

        self.inited = True
        print "init ok"

    def __del__(self):
        self.socket.close()
        self.connected = False
        self.readthread = None
        print "end connection"

    def __init__(self, socket):
        #pydevd.settrace('localhost', port=1111, stdoutToServer = True, stderrToServer = True)
        self.socket = socket
        self.socket.settimeout(1)

        if not self.use_sync:
            self.readthread = threading.Thread(target = self.ReadPacketThread)
            self.readthread.start()
            self.connected = False
        else:
            self.connected = True

        if not self.HandshakeWithServer():
            raise ValueError("handshake failed")  # cannot establish connection
        self.socket.settimeout(None)
        self.GetRemoteQSupported()
        self.SetCurrentThread(0)
        # put other things in init() in case block ida
        self.init()

        return

    def calcsign(self, input):
        sum = 0
        for ch in input:
            sum = sum + ord(ch)
        return (sum & 0xff)

    def make_general_packet(self, input, align=False):
        packet = "$%s#%02x" % (input, self.calcsign(input))
        if align:
            pl = len(packet)
            if (pl % 32) != 0:  # align 32 bytes
                pla = 32 - pl % 32
                for i in range(0, pla):
                    packet = packet + "\0"
        return packet

    def CheckForPacket(self, packet):
        # GDBRemoteCommunication::CheckForPacket
        if packet is None:
            return None
        rebuild = ""
        i = 0
        last = '\0'
        vbegin = 0x20  # ord(' ')
        vend = 0x7f  # ord('~')
        # without csum calc!
        while i < len(packet):
            ch = ord(packet[i])
            if i == 0 and packet[i] in ['+', '-']:
                pass
            elif packet[i] == '$':
                pass
            elif packet[i] == '#':
                break
            elif packet[i] == '*':
                # handle 'run length encoding'
                i = i + 1
                c = packet[i]
                repeat = ord(c) - ord(' ') + 3
                for j in range(0, repeat):
                    rebuild = rebuild + last
            # filter out visible char
            elif ch in range(vbegin, vend):
                # just handle above yet
                rebuild = rebuild + packet[i]
                last = packet[i]
            i = i + 1
        return rebuild

    def SendAck(self):
        # send '#' package to get synchronized
        end = False
        try:
            while not end:
                self.socket.send("+")
                print "send:+"
                if self.ReadPacket() == "":
                    end = True
                    break
        except Exception as e:
            end = False
        return end

    def HandshakeWithServer(self):
        # for lldb / gdb
        if self.SendAck():
            retry = 0
            while retry < HANDSHAKE_RETRYTIME:
                if self.QueryNoAckModeSupported():
                    self.connected = True
                    return True
                retry = retry + 1
                time.sleep(0.5)
        return False

    def SendPacketAndWaitForResponse(self, request, raw = False):
        self.SendAck()
        if not raw:
            packet = self.make_general_packet(request)
        else:
            packet = request
        self.socket.send(packet)
        print "send:", packet
        for i in range(0, DEFAULT_RETRYTIME):
            try:
                response = self.ReadPacket()
                if response.find("$E") == -1 and response not in ["", "+","-", None]:
                    return response
            except Exception as e:
                return None
        return packet

    def GetResponseType(self, input):
        if type(input) != str or len(input) == 0:
            return self.eUnsupported
        elif input[0] == 'E':
            return self.eError
        elif input[0] == 'O':
            return self.eOK
        elif input[0] == '+':
            return self.eAck
        elif input[0] == '-':
            return self.eNack
        else:
            return self.eResponse

    def GetEchoSupported(self):
        return self.m_supports_qEcho

    def GetAugmentedLibrariesSVR4ReadSupported(self):
        return self.m_supports_augmented_libraries_svr4_read

    def GetQXferLibrariesSVR4ReadSupported(self):
        return self.m_supports_qXfer_libraries_svr4_read

    def GetQXferLibrariesReadSupported(self):
        return self.m_supports_qXfer_libraries_read

    def GetQXferAuxvReadSupported(self):
        return self.m_supports_qXfer_auxv_read

    def GetQXferFeaturesReadSupported(self):
        return self.m_supports_qXfer_features_read

    def GetRemoteMaxPacketSize(self):
        return self.m_max_packet_size

    def IsResultOk(self, req, raw = False):
        return self.GetResponseType(self.SendPacketAndWaitForResponse(req, raw)) == self.eOK

    def IsResulteError(self, req, raw = False):
        return self.GetResponseType(self.SendPacketAndWaitForResponse(req, raw)) == self.eError

    def IsResulteResponse(self, req, raw = False):
        return self.GetResponseType(self.SendPacketAndWaitForResponse(req, raw)) == self.eResponse

    def QueryNoAckModeSupported(self):
        # for lldb / gdb
        response = ""
        retry = 0
        success = False
        self.socket.send(self.make_general_packet("QStartNoAckMode"))
        while retry < HANDSHAKE_RETRYTIME:
            response = self.ReadPacket(1)
            print "handshakeresponse:%d"%(len(response))
            if self.GetResponseType(response) == self.eOK:
                success = True
                break
            self.SendAck()
            retry = retry + 1
        return success

    def GetListThreadsInStopReplySupported(self):
        # for lldb / gdb
        return self.IsResultOk("QListThreadsInStopReply")

    def GetVAttachOrWaitSupported(self):
        # for lldb / gdb
        return self.IsResultOk("qVAttachOrWaitSupported")

    def GetSyncThreadStateSupported(self):
        # for lldb / gdb
        return self.IsResultOk("qSyncThreadStateSupported")

    def ResetDiscoverableSettings(self):
        general_info = {}
        qsupport_feature = []
        reg_layout = []  # [name offset size],[name offset size]

        m_supports_vCont_c = False
        m_supports_vCont_C = False
        m_supports_vCont_s = False
        m_supports_vCont_S = False
        m_supports_vCont_all = False
        m_supports_vCont_any = False
        m_supports_detach_stay_stopped = None
        m_supports_qXfer_auxv_read = False
        m_supports_qXfer_libraries_svr4_read = False
        m_supports_qXfer_libraries_read = False
        m_supports_augmented_libraries_svr4_read = False
        m_supports_threads_read = False
        m_supports_qXfer_features_read = False
        m_supports_qEcho = False
        m_max_packet_size = 0

    def GetRemoteQSupported(self):
        # for lldb / gdb
        response = self.SendPacketAndWaitForResponse("qSupported:xmlRegisters=i386,arm")
        if self.GetResponseType(response) != self.eResponse:
            return False
        if response.find("qXfer:auxv:read+") != -1:
            self.m_supports_qXfer_auxv_read = True
        if response.find("qXfer:libraries-svr4:read+") != -1:
            self.m_supports_qXfer_libraries_svr4_read = True
        if response.find("augmented-libraries-svr4-read") != -1:
            self.m_supports_qXfer_libraries_svr4_read = True
            self.m_supports_augmented_libraries_svr4_read = True
        if response.find("qXfer:libraries:read+") != -1:
            self.m_supports_qXfer_libraries_read = True
        if response.find("qXfer:features:read+") != -1:
            self.m_supports_qXfer_features_read = True
        if response.find("qEcho") != -1:
            self.m_supports_qEcho = True
        if response.find("qXfer:threads:read+") != -1:
            self.m_supports_threads_read = True
        if response.find("PacketSize=") != -1:
            try:
                pos1 = response.find("PacketSize=") + 11
                pos2 = response.find(";", pos1)
                if pos2 == -1:
                    pos2 = response.find("#", pos1)
                self.m_max_packet_size = int(response[pos1:pos2], 16)
            except:
                pass
        for item in response.split(";"):
            self.qsupport_feature.append(item)

    def GetThreadSuffixSupported(self):
        # for lldb / gdb
        return self.IsResultOk("QThreadSuffixSupported")

    def GetVContSupported(self):
        # for lldb / gdb
        response = self.SendPacketAndWaitForResponse("vCont?")
        if response != None:
            if response.find(";c") != -1:
                self.m_supports_vCont_c = True
            if response.find(";C") != -1:
                self.m_supports_vCont_C = True
            if response.find(";s") != -1:
                self.m_supports_vCont_s = True
            if response.find(";S") != -1:
                self.m_supports_vCont_S = True
            if self.m_supports_vCont_c and self.m_supports_vCont_C and self.m_supports_vCont_s \
                    and self.m_supports_vCont_S:
                self.m_supports_vCont_all = True
            if self.m_supports_vCont_c or self.m_supports_vCont_C or self.m_supports_vCont_s \
                    or self.m_supports_vCont_S:
                self.m_supports_vCont_any = True

    def GetpPacketSupported(self, tid):
        # for lldb / gdb
        if self.GetThreadSuffixSupported():
            response = self.SendPacketAndWaitForResponse("p0;thread:%lx;" % tid)
        else:
            response = self.SendPacketAndWaitForResponse("p0")
        if self.GetResponseType(response) in [self.eOK, self.eResponse]:
            return True
        return False  # not support

    def GetThreadsInfo(self):
        # for lldb
        response = self.SendPacketAndWaitForResponse("jThreadsInfo")
        if self.GetResponseType(response) != self.eResponse:
            # not support
            return None
        return response

    def GetThreadExtendedInfoSupported(self):
        # for lldb
        return self.IsResultOk("jThreadExtendedInfo:")

    def GetLoadedDynamicLibrariesInfosSupported(self):
        # for lldb
        return self.IsResultOk("jGetLoadedDynamicLibrariesInfos:")

    def GetxPacketSupported(self):
        # for lldb / gdb
        return self.IsResultOk("x0,0")

    def SendvCont(self, action, threadid=-1, sig=-1):
        # for lldb / gdb
        packet = "vCont"
        if action == self.vcont_continue:
            packet = "vCont;c"
        elif action == self.vcont_continue_sig:
            packet = "vCont;C%02x" % sig
        elif action == self.vcont_step:
            packet = "vCont;s"
        elif action == self.vcont_step_sig:
            packet = "vCont;S%02x" % sig
        elif action == self.vcont_t:
            packet = "vCont;t"
        if threadid != -1:
            packet = packet + ":%lx" % threadid
        return self.IsResultOk(packet)

    def SendInterrupt(self):
        # for lldb / gdb
        # is 'vCtrlC' equals to '\x03'?
        #return self.IsResultOk("vCtrlC")
        return self.IsResultOk("\x03")
        #todo  handle result

    def GetCurrentProcessID(self):
        pass

    def SendArgumentsPacket(self, args):
        # todo........
        pass

    def SendEnvironmentPacket(self):
        # todo............
        pass

    def SendLaunchArchPacket(self, arch):
        # for lldb
        return self.IsResultOk("QLaunchArch:" + arch)

    def SendLaunchEventDataPacket(self):
        # todo.................
        pass

    def GetGDBServerVersion(self):
        """
        update debugger info
        for lldb
        :return:if can get
        """
        response = self.SendPacketAndWaitForResponse("qGDBServerVersion")
        if type(response) == str and len(response) > 0:
            for item in response.split(";"):
                if item.find("name:") != -1:
                    self.general_info["debuggername"] = item.replace("name:", "")
                elif item.find("version:") != -1:
                    index = item.find("debugserver-")
                    self.general_info["debuggerversion"] = item[index + 12:]
            return True
        return False

    def GetDefaultThreadID(self):
        """
        get current thread id
        for lldb / gdb
        :return: thread id, -1 for error
        """
        retry = 0
        response = self.SendPacketAndWaitForResponse("qC")
        success = False
        while not success:
            if type(response) != str or len(response) <= 2:
                response = self.SendPacketAndWaitForResponse("qC")
            if response[0] == 'Q' and response[1] == 'C':
                try:
                    return int(response[2:], 16)
                except:
                    pass
        return -1

    def GetHostInfo(self):
        """
        update system info
        for lldb
        :return:
        """
        response = self.SendPacketAndWaitForResponse("qHostInfo")
        if self.GetResponseType(response) == self.eResponse:
            if type(response) == str and len(response) > 0:
                for item in response.split(";"):
                    if len(item.split(":")) != 2:
                        continue
                    (name, value) = item.split(":")
                    try:
                        value = int(value)  # notice: here number not hex but decimal
                    except:
                        pass
                    self.general_info[name] = value
            return True
        return False

    def SendAttach(self, sig):
        pass

    def SendStdinNotification(self):
        pass

    def AllocateMemory(self, size, permission):
        # for lldb
        # permission: "r"|"w"|"x"
        response = self.SendPacketAndWaitForResponse("_M%lx,%s" % (size, permission))
        try:
            addr = int(response, 16)
            return addr
        except:
            return 0

    def DeallocateMemory(self, addr):
        # for lldb
        return self.IsResultOk("_m%lx" % addr)

    def Detach(self, keep_stopped):
        # for lldb / gdb
        if keep_stopped:
            if self.m_supports_detach_stay_stopped is None:
                if self.IsResultOk("qSupportsDetachAndStayStopped:"):
                    self.m_supports_detach_stay_stopped = True
                else:
                    self.m_supports_detach_stay_stopped = False
            if self.m_supports_detach_stay_stopped:
                if self.SendPacketAndWaitForResponse("D1") == "":
                    return True
        else:
            if self.SendPacketAndWaitForResponse("D") == "":
                return True
        return False

    def GetMemoryRegionInfo(self, addr):
        # for lldb
        response = self.SendPacketAndWaitForResponse("qMemoryRegionInfo:%lx" % addr)
        regioninfo = {}
        if type(response) == str and len(response) > 0:
            for item in response.split(";"):
                if len(item.split(":")) != 2:
                    continue
                (name, value) = item.split(":")
                if name in ["start", "size"]:
                    regioninfo[name] = int(value, 16)
                elif name == "permissions":
                    regioninfo[name] = value
                else:
                    regioninfo[name] = value
        return regioninfo

    def GetWatchpointSupportInfo(self):
        return self.IsResultOk("qWatchpointSupportInfo:")

    def SetDisableASLR(self, enable):
        return self.IsResultOk("QSetDisableASLR:%d" % enable)

    def SetDetachOnError(self, enable):
        return self.IsResultOk("QSetDetachOnError:%d" % enable)

    def GetProcessInfo(self, pid):
        pass  # for lldb only return current pid, don't use this

    def GetCurrentProcessInfo(self):
        # for lldb
        response = self.SendPacketAndWaitForResponse("qProcessInfo")
        processinfo = {}
        if type(response) == str and len(response) > 0:
            for item in response.split(";"):
                if len(item.split(":")) != 2:
                    continue
                (name, value) = item.split(":")
                if name in ["pid", "parent-pid", "real-uid", "real-gid", ";effective-uid",
                            "effective-gid", "cputype", "cpusubtype", "ptrsize"]:
                    processinfo[name] = int(value, 16)
                elif name in ["ostype", "vendor", "endian"]:
                    processinfo[name] = int(value, 16)
                else:
                    processinfo[name] = value
        return processinfo

    def GetUserName(self):
        # for lldb
        pass

    def GetGroupName(self):
        # for lldb
        pass

    def SetNonStopMode(self, enable):
        # for lldb / gdb
        return self.IsResultOk("QNonStop:%d" % enable)

    def LaunchGDBServer(self):
        # for lldb
        pass

    def QueryGDBServer(self):
        # for lldb
        pass

    def KillSpawnedProcess(self):
        # for lldb
        pass

    def SetCurrentThread(self, tid):
        # for lldb / gdb
        if tid == -1:
            packet = "Hg-1"
        else:
            packet = "Hg%lx" % tid
        return self.IsResultOk(packet)

    def SetCurrentThreadForRun(self, tid):
        # for lldb / gdb
        if tid == -1:
            packet = "Hc-1"
        else:
            packet = "Hc%lx" % tid
        return self.IsResultOk(packet)

    def GetStopReply(self):
        # for lldb / gdb
        response = self.SendPacketAndWaitForResponse("?")
        stopinfo = {}
        if type(response) == str and len(response) > 0 and response[0] == "T":
            stopinfo["signal"] = response[1:3]
            for item in response.split(";"):
                if len(item.split(":")) != 2:
                    continue
                (name, value) = item.split(":")
                if name in ["thread", "core", "qaddr", "metype", "mecount", "medata"]:
                    stopinfo[name] = int(value, 16)
                else:
                    if re.match(r"[0-9a-f]+", name) != None:  # reigsters
                        stopinfo[int(name, 16)] = int(value, 16)
                    else:
                        stopinfo[name] = value
        return stopinfo

    def GetThreadStopInfo(self, tid):
        # for lldb
        response = self.SendPacketAndWaitForResponse("qThreadStopInfo%lx" % tid)
        stopinfo = {}
        if type(response) == str and len(response) > 0 and response[0] == "T":
            stopinfo["signal"] = int(response[1:3], 16)
            for item in response.split(";"):
                if len(item.split(":")) != 2:
                    continue
                (name, value) = item.split(":")
                if name in ["thread", "core", "qaddr", "metype", "mecount", "medata"]:
                    stopinfo[name] = int(value, 16)
                else:
                    if re.match(r"[0-9a-f]+", name) != None:  # reigsters
                        stopinfo[int(name, 16)] = int(value, 16)
                    else:
                        stopinfo[name] = value
        return stopinfo

    def SendGDBStoppointTypePacket(self, type, insert, addr, length):
        # for lldb / gdb
        # set break point
        if insert:
            packet = "Z"
        else:
            packet = "z"
        packet = packet + "%d,%lx,%x" % (type, addr, length)
        # to do...........

    def GetCurrentThreadIDs(self):
        # for lldb / gdb
        threadids = {}
        success = False
        # first test if we cant get thread info from xml
        if self.m_supports_threads_read:
            response = self.ReadExtFeature("threads", "")
            if self.GetResponseType(response) == self.eResponse:
                success = True
                try:
                    dom = xml.dom.minidom.parseString(response)
                    threads = dom.getElementsByTagName("threads")
                    if len(threads) > 0:
                        for node in threads[0].getElementsByTagName("thread"):
                            try:
                                tid = int(node.getAttribute("id"), 16)
                                core = int(node.getAttribute("core"), 16)
                                name = node.getAttribute("name")
                                threadids[tid] = {"id": tid, "core": core, "name": name}
                            except:
                                pass
                except Exception as e:
                    print e
        if not success:
            # for gdb / lldb
            response = self.SendPacketAndWaitForResponse("qfThreadInfo")
            while self.GetResponseType(response) == self.eResponse:
                if response[0] == 'l':
                    for item in response[1:].split(","):
                        if len(item) > 0:
                            try:
                                tid = int(item, 16)
                                threadids[tid] = {"id": tid, "core": 0, "name": "unknown"}
                            except:
                                pass
                    break
                elif response[0] == 'm':
                    for item in response[1:].split(","):
                        if len(item) > 0:
                            try:
                                tid = int(item, 16)
                                threadids[tid] = {"id": tid, "core": 0, "name": "unknown"}
                            except:
                                pass
                response = self.SendPacketAndWaitForResponse("qsThreadInfo")
        return threadids

    def GetShlibInfoAddr(self):
        # for lldb to get _dyld_all_image_infos base
        basestr = self.SendPacketAndWaitForResponse("qShlibInfoAddr")
        try:
            return int(basestr, 16)
        except:
            pass
        return None

    def AnalysisModuleAndGetSize(self, modbegin, modname):
        type = 0 # 1 -> macho  2 -> dex  3 -> elf 4 -> apk
        try:
            magic = self.ReadRemoteInt(modbegin, 4)
            modsize = 0
            if magic in [IOS_MH_MAGIC, IOS_MH_CIGAM, IOS_MH_MAGIC_64, IOS_MH_CIGAM_64]:
                type = 1
                if magic == IOS_MH_MAGIC:
                    file_type = self.ReadRemoteInt(modbegin + 0xC, 4)
                    size_of_load_commands = self.ReadRemoteInt(modbegin + 0x14, 4)
                    command_data = binascii.unhexlify(self.DoReadMemory(modbegin + 0x1C, size_of_load_commands))
                    off = 0
                    if file_type == IOS_MH_EXECUTE:
                        while off < size_of_load_commands:
                            command, commandsize = struct.unpack("2I", command_data[off: off + 8])
                            if command == LC_SEGMENT:
                                segment_name, vm_address, vm_size = struct.unpack("16s2I", command_data[off + 8: off + 32])
                                if vm_address + vm_size > modsize:
                                    modsize = vm_address + vm_size
                                if modsize > 0x4000000:
                                    return 0x1C + size_of_load_commands  # contain mach-o header
                            off = off + commandsize
                    else:
                        return -1
                    if file_type == IOS_MH_EXECUTE:
                        self.mainbase = modbegin
                        self.mainsize = modsize
                        self.mainname = modname
                else:
                    pass  # todo
            elif magic in [ANDROID_DEX, ANDROID_ODEX]:
                type = 2 # todo
            elif magic in [ANDROID_ELF]:
                type = 3 # todo
            elif magic in [ANDROID_APK]:
                type = 4 # todo
        except:
            pass
        return modsize

    def ReadRemoteInt(self, addr, size):
        # for lldb
        result = self.DoReadMemory(addr, size)
        if result == None or len(result) == 0:
            return None
        ch = ["B", "B", "H", "H", "I", "I", "I", "I", "Q"][size]
        try:
            value, = struct.unpack(ch, binascii.unhexlify(result))
            return value
        except:
            return None

    def ReadRemoteString(self, addr, type=1):
        # for lldb
        # type=1:ascii   type=2:unicode ...
        if type == 1:
            BUFSIZE = 32
            End = False
            outstr = ""
            i = 0
            while not End:
                result = self.DoReadMemory(addr + BUFSIZE * i, BUFSIZE)
                if result == None or len(result) == 0:
                    continue
                k = result.find('00')
                if k != -1:
                    if (k & 1) != 0:
                        k = k + 1
                    result = result[:k]
                outstr = outstr + result
                if k != -1:
                    break
                i = i + 1
            try:
                return binascii.unhexlify(outstr)
            except:
                print "parse string error:", outstr
        else:
            pass
        return None

    def GetLoadedModuleList(self):
        # for lldb / gdb
        # for linux-gdb, use /proc/[pid]/maps seems better
        module_info = []
        if self.debugger_type == self.DEBUGGER_TYPE_GDB:
            # todo  get self exe base
            if self.GetQXferLibrariesSVR4ReadSupported():
                xmldata = self.ReadExtFeature("libraries-svr4", "")
                # parse xml
            elif self.GetQXferLibrariesReadSupported():
                xmldata = self.ReadExtFeature("libraries", "")
                # parse xml
            else:  # cannot get info
                return None
            dom = xml.dom.minidom.parseString(xmldata)
            for library in dom.getElementsByTagName("library"):
                try:
                    modname = library.getAttribute("name")
                    modbegin = int(library.getAttribute("l_addr"), 16)
                    modsize = self.AnalysisModuleAndGetSize(modbegin, modname)
                    if modsize != -1:
                        module_info.append({"name": modname, "begin": modbegin, "size": modsize})
                except:
                    pass
        elif self.debugger_type == self.DEBUGGER_TYPE_LLDB:
            dyld_all_image_infos = self.GetShlibInfoAddr()
            Is_target_64bit = False
            if (self.cpu_arch & self.CPU_ARCH_ABI64) != 0:
                Is_target_64bit = True
            if dyld_all_image_infos is None:  # valid
                return None  # error happen
            # struct dyld_all_image_infos {
            #   uint32_t						version;
            #   uint32_t						infoArrayCount;
            #   const struct dyld_image_info*	infoArray;
            #   ...}
            # struct dyld_image_info {
            #   const struct mach_header*	imageLoadAddress;
            #   const char*					imageFilePath;
            #   uintptr_t					imageFileModDate;
            #   }
            if Is_target_64bit:
                infoArray = self.ReadRemoteInt(dyld_all_image_infos + 8, 8)
                infoArrayCount = self.ReadRemoteInt(dyld_all_image_infos + 4, 4)
                if infoArray is None or infoArrayCount is None:
                    return None
                for i in range(0, infoArrayCount):
                    imageLoadAddress = self.ReadRemoteInt(infoArray + i * 24, 8)
                    imageFilePathPtr = self.ReadRemoteInt(infoArray + i * 24 + 8, 8)
                    imageFilePath = self.ReadRemoteString(imageFilePathPtr)
                    imageSize = self.AnalysisModuleAndGetSize(imageLoadAddress, imageFilePath)
                    if imageSize != -1:
                        module_info.append({"name": imageFilePath, "begin": imageLoadAddress, "size": imageSize})
                        break # for test
            else:
                infoArray = self.ReadRemoteInt(dyld_all_image_infos + 8, 4)
                infoArrayCount = self.ReadRemoteInt(dyld_all_image_infos + 4, 4)
                if infoArray is None or infoArrayCount is None:
                    return None
                for i in range(0, infoArrayCount):
                    imageLoadAddress = self.ReadRemoteInt(infoArray + i * 12, 4)
                    imageFilePathPtr = self.ReadRemoteInt(infoArray + i * 12 + 4, 4)
                    imageFilePath = self.ReadRemoteString(imageFilePathPtr)
                    if imageLoadAddress is None or imageFilePathPtr is None or imageFilePath is None:
                        break
                    imageSize = self.AnalysisModuleAndGetSize(imageLoadAddress, imageFilePath)
                    if imageSize != -1:
                        module_info.append({"name": imageFilePath, "begin": imageLoadAddress, "size": imageSize})
                        break #for test
        return module_info

    def RunShellCommand(self, cmd):
        # for lldb
        pass

    def MakeDirectory(self):
        pass

    def SetFilePermissions(self):
        pass

    def OpenFile(self):
        pass

    def CloseFile(self):
        pass

    def GetFileSize(self):
        pass

    def GetFilePermissions(self):
        pass

    def ReadFile(self):
        pass

    def WriteFile(self):
        pass

    def CreateSymlink(self):
        pass

    def Unlink(self):
        pass

    def GetFileExists(self):
        pass

    def CalculateMD5(self):
        pass

    def tohex(self, nib):
        if nib < 10:
            return chr(ord('0') + nib)
        else:
            return chr(ord('a') + nib - 10)

    def fromhex(self, ch):
        return [][ord(ch)]
        a = ord(ch)
        if a >= ord('0') and a <= ord('9'):
            return a - ord('0')
        elif a >= ord('a') and a <= ord("f"):
            return a - ord('a') + 10
        else:
            # error
            return 0

    def convert_int_to_ascii(self, fromint):
        # fromint should be [0x??,0x??,]
        tostr = ""
        n = len(fromint)
        for i in range(0, n):
            ch = fromint[i]
            nib = ((ch & 0xf0) >> 4) & 0x0f
            tostr = tostr + self.tohex(nib)
            nib = ch & 0x0f
            tostr = tostr + self.tohex(nib)
        return tostr

    def convert_ascii_to_int(self, fromstr):
        toint = []
        n = len(fromstr) / 2
        for i in range(0, n):
            nib1 = self.fromhex(fromstr[i * 2])
            nib2 = self.fromhex(fromstr[i * 2 + 1])
            toint.append((((nib1 & 0x0f) << 4) & 0xf0) | (nib2 & 0x0f))
        return toint

    def ReadAllRegisters(self, tid):
        # for gdb / lldb     for 'read/write register' action we only supply 'g' packet other than 'p'
        print "ReadAllRegisters"
        regs = {}
        thread_suffix_supported = self.GetThreadSuffixSupported()
        response = None
        success = False
        while not success:
            try:
                #if thread_suffix_supported:
                response = self.SendPacketAndWaitForResponse("g;thread:%4.4lx;" % tid)
                #elif self.SetCurrentThread(tid):
                #    response = self.SendPacketAndWaitForResponse("g")
            # handle run-length read_frame remote.c
            # fcf*"b0e7e3bf10*"01c0*"0ce7e3bfa8e8e3bf*%5c6ecdb7177656b786020* 730*"7b0*"7b0*"7b0**330*}000800140*+800140*+80ff3f0* 5c8f42d7a3b0ff3f7f030* 20010* f*0* 730*"e2b95ab67b0*"940b1ba0*Mff00f* 00f*"00f*"0*}0010*"010*"010*"010*"ff00ff00ff00ff00ff00ff00ff00ff0*<a01f0*"010*
            # init data structure from reg_layout

                reg_data = {}
                for reg in self.reg_layout:
                    regname = reg["name"]
                    off = reg["offset"] * 2
                    size = reg["bitsize"] / 4
                    if off + size >= len(response):
                        continue
                    if size == 8:
                        ch2 = "I"
                    elif size == 16:
                        ch2 = "Q"
                    elif size == 4:
                        ch2 = "H"
                    elif size == 2:
                        ch2 = "B"
                    else:
                        break  # no support for float now
                    if self.istarget_little_endian:
                        ch1 = "<"
                    else:
                        ch1 = ">"
                    value, = struct.unpack(ch1 + ch2, binascii.unhexlify(response[off: off + size]))
                    reg_data[regname] = value
                    success = True
            except:
                pass
        return reg_data

    def WriteAllRegisters(self, tid, reg_data):
        # for gdb / lldb     for 'read/write register' action we only supply 'g' packet other than 'p'
        # query register and modify data in response
        regs = {}
        thread_suffix_supported = self.GetThreadSuffixSupported()
        response = None
        if thread_suffix_supported:
            response = self.SendPacketAndWaitForResponse("g;thread:%4.4lx;" % tid)
        elif self.SetCurrentThread(tid):
            response = self.SendPacketAndWaitForResponse("g")
        for reg in self.reg_layout:
            regname = reg["name"]
            if regname not in reg_data:
                # only deal with pre-registered name
                continue
            off = reg["offset"] * 2
            size = reg["bitsize"] / 4
            if off + size >= len(response):
                continue
            if size == 8:
                ch2 = "I"
            elif size == 16:
                ch2 = "Q"
            elif size == 4:
                ch2 = "H"
            elif size == 2:
                ch2 = "B"
            else:
                continue  # no support for float now
            if self.istarget_little_endian:
                ch1 = "<"
            else:
                ch1 = ">"
            value = binascii.hexlify(struct.pack("<I", reg_data[regname]))
            rebuild = response[0: off] + value + response[off + size:]
        return self.IsResultOk("G" + rebuild)

    def SaveRegisterState(self):
        # used to execute shellcode
        pass

    def RestoreRegisterState(self):
        # used to execute shellcode
        pass

    def GetModuleInfo(self):
        # for lldb
        pass

    def ServeSymbolLookups(self):
        pass

    def RawCallFunction(self):
        pass

    # GDBRemoteCommunicationClient.cpp

    def SendRawPacket(self, packet):
        try:
            sock.send(packet)
            return self.ReadPacket()
        except Exception as e:
            return None

    # ProcessGDBRemote.cpp

    def GetGDBServerRegisterInfo(self, regxml):
        # for gdb
        # first sort xml
        i = 0
        index = 0
        regxml_fix = regxml
        for i in range(0, len(regxml)):
            regnumstr = regxml[i].getAttribute("regnum")
            if regnumstr != "":
                index = int(regnumstr, 10)
            regxml_fix[index] = regxml[i]
            index = index + 1
        try:
            offset = 0
            index = 0
            for node_target in regxml_fix:
                name = node_target.getAttribute("name")
                name = name.upper()
                bitsize = int(node_target.getAttribute("bitsize"), 10)  # contain bytes
                type = node_target.getAttribute("type")
                group = node_target.getAttribute("group")
                self.reg_layout.append({"name": name, "bitsize": bitsize, "offset": offset,
                                        "type": type, "group": group, "regnum": index})
                offset = offset + bitsize / 8
                index = index + 1
            return True
        except Exception as e:
            print e
        return False

    def ReadExtFeature(self, object, annex):
        # for gdb
        size = self.GetRemoteMaxPacketSize()
        if size == 0:
            size = 0x1000
        size = size - 1  # leave space for 'm' or 'l' character in the response
        offset = 0
        active = True
        xmldata = ""
        while active:
            packet = "qXfer:%s:read:%s:%x,%x" % (object, annex, offset, size)
            response = self.SendPacketAndWaitForResponse(packet)
            if self.GetResponseType(response) != self.eResponse:
                return None
            if response[0] == 'l':
                # last thunk
                active = False
                xmldata = xmldata + response[1:]
                offset = offset + size
            elif response[0] == 'm':
                # more thunks
                xmldata = xmldata + response[1:]
                offset = offset + size
            else:
                return False
        # remove invalid characters
        if type(xmldata) == str:
            xmldata = xmldata.replace(":", "_")
        return xmldata

    def BuildDynamicRegisterInfo(self, maxregnum=32):
        if not self.IsResulteResponse("qRegisterInfo"):
            return False
        End = False
        rindex = 0
        while not End:
            response = self.SendPacketAndWaitForResponse("qRegisterInfo%x" % rindex)
            if self.GetResponseType(response) != self.eResponse:
                End = True
                break
            while response.find("name") == -1: # until corrent response
                response = self.SendPacketAndWaitForResponse("qRegisterInfo%x" % rindex)
            # result like: name:r0;alt-name:arg1....
            single_reg_info = {}
            for item in response.split(";"):
                index = item.find(":")
                if index == -1:
                    continue
                name = item[0:index]
                value = item[index + 1:]
                if name in ["gcc", "bitsize", "offset"]:
                    try:
                        value = int(value, 10)  # notice: here encoding with decimal
                    except:
                        pass
                if name in ["name"]:
                    value = value.upper()
                single_reg_info[name] = value
            self.reg_layout.append(single_reg_info)
            rindex = rindex + 1
            if rindex > maxregnum:
                # a lot of register we don't need and it's a waste of time to do send and recv job
                break

    def HandleStopReplySequence(self):
        pass

    def DoDestroy(self):
        pass

    def DoReadMemory(self, addr, size):
        # binary_memory_read = self.GetxPacketSupported()
        # if binary_memory_read:
        #    packet = "x%lx,%lx" % (addr, size)
        # else:
        #   packet = "m%lx,%lx" % (addr, size)
        packet = "m%lx,%lx" % (addr, size)
        response = self.SendPacketAndWaitForResponse(packet)
        if self.GetResponseType(response) != self.eResponse:
            return None
        # if binary_memory_read:
        #    return response
        # else:
        return response

    def DoWriteMemory(self, addr, dataasarr):
        # buf should be [0x??,0x??,...]
        hexstr = ""  # transform from buf to hex
        for x in dataasarr:
            hexstr += "%02x" % x
        return self.IsResultOk("M%lx,%lx:%s" % (addr, len(dataasarr), hexstr))

    def GetExtendedInfoForThread(self):
        pass

    def GetLoadedDynamicLibrariesInfos(self):
        pass

    def GetSharedCacheInfo(self):
        pass

    def GetFileLoadAddress(self):
        pass

    def DoExecute(self):
        pass

client = None
def proxy_init_debugger(hostname, portnum, password):
    global client, sock
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname, portnum))
        client = GDBRemoteCommunicationClient(sock)
    except Exception as e:
        print e
        client = None
    success = client != None
    print "proxy_init_debugger:", success
    if not success and client is not None and client.sock is not None:
        client.socket.close()
    return success

def proxy_get_register_layout():
    print "proxy_get_register_layout"
    global client
    if client is None or not client.connected:
        return None
    if not client.inited:
        return None
    processorstr = "UNK"  # unknown
    register_list = []
    if client.cpu_arch == client.CPU_TYPE_ARM:
        if client.istarget_little_endian:
            processorstr = "ARM"
            for item in client.reg_layout:  # name offset bitsize
                name = item["name"]
                bitsize = item["bitsize"]
                dtyp = dt_dword
                flags = REGISTER_ADDRESS
                if name == "SP":
                    flags = flags | REGISTER_SP
                elif name == "PC":
                    flags = flags | REGISTER_IP
                if bitsize == 64:
                    dtyp = dt_qword
                # todo
                register_list.append({"name": name, "flags": flags, "dtyp": dtyp})
        else:
            processorstr = "ARMB"
    elif client.cpu_arch == client.CPU_TYPE_I386:
        processorstr = "X86"
        # todo

    # {"processor": processorstr, "flags": DBG_FLAG_REMOTE, }
    return {"registers": register_list}

def proxy_term_debugger():
    global client
    client = None
    return

def proxy_process_get_info(n):
    global client
    if client is None or not client.connected:
        return
    return {"name": "Remote Process", "pid": 123}

def proxy_start_process(path, args, startdir, dbg_proc_flags, input_path, input_file_crc32):
    # we have already attached
    return 1

def proxy_attach_process(pid, event_id):
    # we have already attached
    return 1

def proxy_detach_process():
    global client
    if client is None or not client.connected:
        return
    client.msg_lock.acquire()
    client.msgQueue.put_nowait({"eid": PROCESS_DETACH, "tid": client.GetDefaultThreadID(), "ea": 0x400000})
    client.msg_lock.release()
    return 1

def proxy_rebase_if_required_to():
    global client
    if client is None or not client.connected:
        return
    # todo
    return

def proxy_prepare_to_pause_process():
    global client
    if client is None or not client.connected:
        return 0
    client.SendInterrupt()
    tid = client.GetDefaultThreadID()
    client.register_info = client.ReadAllRegisters(tid)
    client.msg_lock.acquire()
    client.msgQueue.put_nowait({"eid": PROCESS_SUSPEND, "tid": client.GetDefaultThreadID(),
                                "ea": client.register_info["PC"]})
    client.msg_lock.release()
    return 1

def proxy_exit_process():
    global client
    if client is None or not client.connected:
        return
    # todo
    client.msg_lock.acquire()
    client.msgQueue.put_nowait({"eid": PROCESS_EXIT})
    client.msg_lock.release()

def proxy_get_debug_event():
    global client
    event = None
    if client is None or not client.connected:
        return None
    if not client.inited:
        return None   # wen won't handle event util the initialize success
    client.msg_lock.acquire()
    if not client.msgQueue.empty():
        event = client.msgQueue.get()
    client.msg_lock.release()
    return event

def proxy_continue_after_event():
    return 1

def proxy_set_exception_info():
    pass

def proxy_stopped_at_debug_event():
    pass

def proxy_thread_suspend():
    msg = PROCESS_SUSPEND
    pass

def proxy_thread_continue():
    pass

def proxy_set_resume_mode():
    pass

def proxy_read_registers(tid):
    global client
    if client is None or not client.connected:
        return None
    client.register_info = client.ReadAllRegisters(tid)
    regvals = []
    for reg in client.reg_layout:
        regvals.append(client.register_info[reg["name"]])
    return regvals

def proxy_write_register(tid, regidx, value):
    global client
    if client is None or not client.connected:
        return None
    reg_data = {}
    reg_data[client.reg_layout[regidx]] = value
    return client.WriteAllRegisters(tid, reg_data)

def proxy_thread_get_sreg_base():
    pass

def proxy_get_memory_info():
    pass

def proxy_read_memory(ea, size):
    global client
    if client is None or not client.connected:
        return None
    buffer = client.DoReadMemory(ea, size)
    if buffer is None:
        return None
    return binascii.unhexlify(buffer)

def proxy_write_memory(ea, buffer):
    global client
    if client is None or not client.connected:
        return None
    return client.DoWriteMemory(ea, binascii.hexlify(buffer))

def proxy_is_ok_bpt():
    pass

def proxy_update_bpts():
    pass

def proxy_update_lowcnds():
    pass

def proxy_open_file():
    pass

def proxy_close_file():
    pass

def proxy_read_file():
    pass

def proxy_map_address():
    pass

def proxy_set_dbg_options():
    pass

def proxy_get_debmod_extensions():
    pass

def proxy_update_call_stack():
    pass

def proxy_appcall():
    pass

def proxy_cleanup_appcall():
    pass

def proxy_eval_lowcnd():
    pass

def proxy_write_file():
    pass

def proxy_send_ioctl():
    pass

def proxy_dbg_enable_trace():
    pass

def proxy_is_tracing_enabled():
    pass

def proxy_rexec():
    pass

def proxy_get_debapp_attrs():
    pass

# for ida command
def proxy_raw(packet):
    global client
    if client is None or not client.connected:
        return None
    if packet.find("raw:") == 0:
        response = client.SendPacketAndWaitForResponse(packet[4:], True)
        print response
    elif packet.find("msg:") == 0:
        print "msg"
        try:
            eidstr = packet[4:6]
            eidmap = {"NE":NO_EVENT,"PS":PROCESS_START,"PE":PROCESS_EXIT,"TS":THREAD_START,"TE":THREAD_EXIT,
                "BP":BREAKPOINT,"ST":STEP,"ET":EXCEPTION,"LL":LIBRARY_LOAD,"LU":LIBRARY_UNLOAD,"IN":INFORMATION,
                "SC":SYSCALL,"WM":WINMESSAGE,"PA":PROCESS_ATTACH,"PD":PROCESS_DETACH,"PU":PROCESS_SUSPEND,
                "TF":TRACE_FULL}
            eid = eidmap[eidstr]
            tid = 0
            ea = 0
            for item in packet.split(","):
                if item.find("tid") != -1:
                    tid = int(item[4:],16)
                elif item.find("ea") != -1:
                    ea = int(item[3:],16)
            if eid in [PROCESS_START,PROCESS_ATTACH,LIBRARY_LOAD]:
                name = ""
                base = 0
                size = 0
                rebase_to = 0
                for item in packet.split(","):
                    if item.find("name") != -1:
                        name = item[5:]
                    elif item.find("base") != -1:
                        base = int(item[5:], 16)
                    elif item.find("size") != -1:
                        size = int(item[5:], 16)
                    elif item.find("rebase_to") != -1:
                        rebase_to = int(item[10:], 16)
                msg = {"eid":eid,"tid":tid,"ea":ea,"name":name,"base":base,"size":size,"rebase_to":rebase_to}
            elif eid in [PROCESS_EXIT,THREAD_EXIT]:
                exit_code = 0
                for item in packet.split(","):
                    if item.find("exit_code") != -1:
                        exit_code = int(item[10:], 16)
                msg = {"eid": eid, "tid": tid, "ea": ea, "exit_code":exit_code}
            elif eid in [LIBRARY_UNLOAD,INFORMATION]:
                info = ""
                for item in packet.split(","):
                    if item.find("info") != -1:
                        info = item[5:]
                msg = {"eid": eid, "tid": tid, "ea": ea, "info": info}
            elif eid in [BREAKPOINT]:
                hea = 0
                kea = 0
                for item in packet.split(","):
                    if item.find("hea") != -1:
                        hea = int(item[4:], 16)
                    elif item.find("kea") != -1:
                        kea = int(item[4:], 16)
                msg = {"eid": eid, "tid": tid, "ea": ea, "hea": hea, "kea": kea}
            elif eid in [EXCEPTION]:
                code = 0
                info = ""
                for item in packet.split(","):
                    if item.find("code") != -1:
                        code = int(item[5:], 16)
                    elif item.find("info") != -1:
                        info = item[5:]
                msg = {"eid": eid, "tid": tid, "ea": ea, "code": code, "info": info}
            client.InsertMsg(msg)
        except Exception as e:
            print e.message
    else:
        response = client.SendPacketAndWaitForResponse(packet)
        printdata("recv:", response)


'''
def calcsign(input):
    sum = 0
    for ch in input:
        sum = sum + ord(ch)
    return "%02x" % (sum & 0xff)

def get_server_data(sock):
    global isconnect
    #    sock.settimeout(2)
    while True:
        try:
            data = sock.recv(65536)
            if len(data) <= 0:
                isconnect = False
                break
            printdata("recv", data)
        except Exception as e:
            pass

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 1111))
threading.Thread(target=get_server_data, args=(sock,)).start()
isconnect = True

# test case
try:
    client = GDBRemoteCommunicationClient(sock)
    client.SetCurrentThread(0)
    #####test get thread info                       lldb:ok gdb:ok
    threadsset = client.GetCurrentThreadIDs()
    tid = client.GetDefaultThreadID()
    #####test register read / write                 lldb:?  gdb:ok
    #regs = client.ReadAllRegisters(tid)
    #print regs["eax"]
    #print client.WriteAllRegisters(thread, {"eax":0})
    #regs = client.ReadAllRegisters(thread)
    #print regs["eax"]

    #####test memory read / write                   lldb:ok  gdb:ok
    #regs = client.ReadAllRegisters(tid)
    #print regs["esp"]
    #out = client.DoReadMemory(0x98d67000, 8)
    #printdata("readed:", out)
    #client.DoWriteMemory(0x98d67000, [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90])
    #out = client.DoReadMemory(0x98d67000, 8)
    #printdata("readed:", out)

    #####test get load library info                 lldb:ok  gdb:ok
    client.GetLoadedModuleList()
    #test run
    #test intterupt
    #test step
    #test exit
    #test software breakpoint
    #get call stack?(future)
    #test call api?(future)

except Exception as e:
    print "cannot establish connection!", e

while True:
    print "input:"
    input = raw_input()
    try:
        if input == 'q' or not isconnect:
            sock.close()
            break
        elif input.find("raw:") != -1:
            input = input[4:]
            sock.send(input)
            print "send", input
        else:
            input = "$" + input + "#" + calcsign(input)
            sock.send(input)
            print "send", input
    except Exception as e:
        print e
'''
#if DEBUG:
#    proxy_init_debugger("localhost", 111, "")
#    print proxy_get_debug_event()
#    print proxy_get_debug_event()