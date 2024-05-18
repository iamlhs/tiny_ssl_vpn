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

void tun_init() {
#ifdef _MSC_VER
    Wintun = InitializeWintun();
    if (!Wintun) {
        spdlog::error("Failed to load wintun.dll");
        return;
    }
    WintunSetLogger(ConsoleLogger);

    GUID AGuid = { 0xdeadbabe, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    Adapter = WintunCreateAdapter(L"Tiny SSL", L"VPN TUN", &AGuid);

    if (!Adapter) {
        spdlog::error("Failed to create Wintun adapter");
        tun_stop();
        return;
    }

    DWORD Version = WintunGetRunningDriverVersion();
    spdlog::info("Wintun driver version: {}.{}", (Version >> 16) & 0xff, (Version >> 0) & 0xff);

    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(Adapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl((ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | (ip[3] << 0)); /* 10.6.7.7 */
    AddressRow.OnLinkPrefixLength = 24; /* This is a /24 network */
    AddressRow.DadState = IpDadStatePreferred;

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
    HANDLE WaitEvent = WintunGetReadWaitEvent(Session);
    if (!WaitEvent) {
        spdlog::error("Failed to get Wintun read wait event");
        return false;
    }

    DWORD WaitResult = WaitForSingleObject(WaitEvent, 0);
    if (WaitResult == WAIT_OBJECT_0) {
        return true;
    }
    else if (WaitResult == WAIT_TIMEOUT) {
        return false;
    }
    else {
        spdlog::error("Failed to wait for Wintun read wait event: {}", GetLastError());
        return false;
    }
#else
    static fd_set readFDSet;
    FD_ZERO(&readFDSet);
    FD_SET(tunfd, &readFDSet);
    int ret = select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
    if (ret < 0) {
        spdlog::error("Failed to wait for TUN device: {}", strerror(errno));
        return false;
    }
    return FD_ISSET(tunfd, &readFDSet);
#endif
}

size_t tun_read(unsigned char *buffer, size_t buffer_size) {
    size_t size;
#ifdef _MSC_VER
    buffer = WintunReceivePacket(Session, (DWORD *) &size);
    if (!buffer) {
        spdlog::error("Failed to receive packet from Wintun session");
        return 0;
    }
    WintunReleaseReceivePacket(Session, buffer);
#else
    size = read(tunfd, buffer, buffer_size);
#endif
    return size;
}

void tun_write(const unsigned char *buffer, size_t buffer_size) {
#ifdef _MSC_VER
    BYTE *Packet = WintunAllocateSendPacket(Session, (DWORD)buffer_size);
    if (!Packet) {
        spdlog::error("Failed to allocate send packet");
        return;
    }
    memcpy(Packet, buffer, buffer_size);
    WintunSendPacket(Session, Packet);

    switch (WaitForSingleObject(WintunGetReadWaitEvent(Session), 1000))
    {
    case WAIT_OBJECT_0:
        break;
    case WAIT_TIMEOUT:
        spdlog::error("Timeout waiting for Wintun read wait event");
        break;
    }
#else
    write(tunfd, buffer, buffer_size);
#endif
}

#endif