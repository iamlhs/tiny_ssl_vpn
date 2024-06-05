#ifndef TUN_HPP
#define TUN_HPP

#include <spdlog/spdlog.h>
#include <asio.hpp>

using asio::awaitable;
using asio::co_spawn;
using asio::redirect_error;
using asio::ip::tcp;
using asio::use_awaitable;
using asio::detached;

#ifdef _MSC_VER
#include <winsock2.h>
#include <Windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <ip2string.h>
#include <winternl.h>
#include <cstdarg>
#include <cstring>
#include <string>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Ntdll.lib")

#include "../wintun/include/wintun.h" // Include the header file that defines the missing identifier

const char ip[4] = { 10, 6, 7, 7 }; // ip address of the tun device

static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

static HMODULE
InitializeWintun(void)
{
    HMODULE Wintun =
        LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Wintun)
        return NULL;
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
        X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
        X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(Wintun);
        SetLastError(LastError);
        return NULL;
    }
    return Wintun;
}

static void CALLBACK
ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_ DWORD64 Timestamp, _In_z_ const WCHAR *LogLine)
{
    SYSTEMTIME SystemTime;
    FileTimeToSystemTime((FILETIME *)&Timestamp, &SystemTime);
    std::wstring ws(LogLine); std::string str(ws.begin(), ws.end()); // FIX: convert wstring to string
    switch (Level)
    {
    case WINTUN_LOG_INFO: spdlog::info("Log from WinTun: {}", str); break;
    case WINTUN_LOG_WARN: spdlog::warn("Log from WinTun: {}", str); break;
    case WINTUN_LOG_ERR: spdlog::error("Log from WinTun: {}", str); break;
    default:
        return;
    }
}

static HMODULE Wintun;
static WINTUN_ADAPTER_HANDLE Adapter;
static WINTUN_SESSION_HANDLE Session;

#else
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

static int tunfd;
int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);       

   return tunfd;
}
#endif

void tun_stop() {
#ifdef _MSC_VER
    if (Adapter) WintunCloseAdapter(Adapter);
    FreeLibrary(Wintun);
#else
    close(tunfd);
#endif
}

//在Windows和Linux平台上初始化TUN虚拟网络设备。TUN（Tunnel Interface）是一种虚拟网络设备，通常用于创建虚拟专用网络（VPN）。以下是代码的逐行解释：
void tun_init() {
#ifdef _MSC_VER
    Wintun = InitializeWintun();//调用wintun初始化函数
    if (!Wintun) {
        spdlog::error("Failed to load wintun.dll");
        return;
    }
    WintunSetLogger(ConsoleLogger);//设置Wintun的日志记录器，这里使用控制台日志记录器。
    //定义了一个全局唯一标识符（GUID），用于标识TUN适配器。
    GUID AGuid = { 0xdeadbabe, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    //调用WintunCreateAdapter函数，创建一个TUN适配器，适配器的名称和GUID用于标识。
    Adapter = WintunCreateAdapter(L"Tiny SSL", L"VPN TUN", &AGuid);
    if (!Adapter) {//如果创建适配器失败，则打印错误信息并调用tun_stop函数后退出。
        spdlog::error("Failed to create Wintun adapter");
        tun_stop();
        return;
    }
    DWORD Version = WintunGetRunningDriverVersion();//获取当前运行的Wintun驱动程序版本
    spdlog::info("Wintun driver version: {}.{}", (Version >> 16) & 0xff, (Version >> 0) & 0xff);

    MIB_UNICASTIPADDRESS_ROW AddressRow;//声明一个结构体变量，用于存储IP地址信息。
    InitializeUnicastIpAddressEntry(&AddressRow);//初始化IP地址结构体。
    WintunGetAdapterLUID(Adapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    //设置IPv4地址和子网掩码。这里ip为4个字节数组，表示IP地址的每个字节。
    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl((ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | (ip[3] << 0)); /* 10.6.7.7 */
    AddressRow.OnLinkPrefixLength = 24; /* This is a /24 network *///设置此网络的子网掩码前缀长度（即，255.255.255.0）。
    AddressRow.DadState = IpDadStatePreferred;//设置DAD（Duplicate Address Detection）状态为首选。

    DWORD LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        spdlog::error("Failed to set IP address on Wintun adapter: {}", LastError);
        tun_stop();
        return;
    }

    Session = WintunStartSession(Adapter, 0x400000);
    if (!Session)
    {
        spdlog::error("Failed to start Wintun session");
        tun_stop();
        return;
    }
#else
    tunfd = createTunDevice();
    if (tunfd < 0) {
        spdlog::error("Failed to create TUN device");
        return;
    }
#endif
    spdlog::info("TUN device created");
}

bool is_tun_has_data() {
#ifdef _MSC_VER
    //调用window平台函数获取TUN接口的读等待事件句柄（WaitEvent）
    HANDLE WaitEvent = WintunGetReadWaitEvent(Session);
    if (!WaitEvent) {//检查WaitEvent是否为NULL。如果是，表示获取读等待事件失败，记录错误日志，并返回false。
        spdlog::error("Failed to get Wintun read wait event");
        return false;
    }
    //等待WaitEvent。参数0表示无限期等待。
    DWORD WaitResult = WaitForSingleObject(WaitEvent, 0);
    //WaitEvent已经触发，即TUN接口有数据可读，返回true。
    if (WaitResult == WAIT_OBJECT_0) {
        return true;
    }
    else if (WaitResult == WAIT_TIMEOUT) {//超时，无数据可读
        return false;
    }
    else {//两者都不是，则出现error
        spdlog::error("Failed to wait for Wintun read wait event: {}", GetLastError());
        return false;
    }
#else//linux平台执行
    static fd_set readFDSet;//描述一组文件描述符的集合
    FD_ZERO(&readFDSet);//将readFDSet清空，准备重新设置。
    //将TUN接口的文件描述符（tunfd）添加到readFDSet集合中，监视这个文件描述符是否有数据可读。
    FD_SET(tunfd, &readFDSet);//
    //等待readFDSet集合中的文件描述符有数据可读。
    //FD_SETSIZE是系统中最大的文件描述符加一。
    int ret = select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
    if (ret < 0) {//出现error
        spdlog::error("Failed to wait for TUN device: {}", strerror(errno));
        return false;
    }
    return FD_ISSET(tunfd, &readFDSet);
#endif
}
//定义了一个函数tun_read，它接受一个指向unsigned char类型的指针buffer和一个size_t类型的buffer_size作为参数。这个函数用于从TUN接口读取数据，并返回读取的字节数。
size_t tun_read(unsigned char *buffer, size_t buffer_size) {
    size_t size;//size存储读取的数据字节数。
#ifdef _MSC_VER//条件编译指令，仅在编译器为Microsoft Visual C++ (_MSC_VER)时执行下面的代码。
//从Wintun会话（Session）中接收一个数据包
//DWORD *类型的指针&size用于存储接收数据包的长度
    buffer = WintunReceivePacket(Session, (DWORD *) &size);
    if (!buffer) {
        //若buffer为null,表示从Wintun会话中接收数据包失败，记录错误日志
        spdlog::error("Failed to receive packet from Wintun session");
        return 0;
    }WintunReleaseReceivePacket(Session, buffer);//释放从Wintun会话接收到的数据包。
#else
    size = read(tunfd, buffer, buffer_size);
#endif
    return size;
}

void tun_write(const unsigned char *buffer, size_t buffer_size) {
#ifdef _MSC_VER
//使用WintunAllocateSendPacket函数分配一个用于发送的数据包。
//Session是Wintun会话句柄，buffer_size是要发送的数据字节大小。
//函数返回一个指向分配的数据包的BYTE *指针
    BYTE *Packet = WintunAllocateSendPacket(Session, (DWORD)buffer_size);
    if (!Packet) {//若数据包空则分配失败，记录错误日志，并返回。
        spdlog::error("Failed to allocate send packet");
        return;
    }
    memcpy(Packet, buffer, buffer_size);//将buffer数据复制入数据包
    WintunSendPacket(Session, Packet);//发送数据包
    switch (WaitForSingleObject(WintunGetReadWaitEvent(Session), 1000))
    {//等待Wintun会话的读等待事件
    case WAIT_OBJECT_0:
        break;//事件在1000毫秒内发生，则执行break语句
    case WAIT_TIMEOUT://超时错误
        spdlog::error("Timeout waiting for Wintun read wait event");
        break;
    }
#else
    write(tunfd, buffer, buffer_size);
#endif
}

#endif