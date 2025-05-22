#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <iomanip>
#include <filesystem>

#ifdef _WIN32
#include <comdef.h>
#include <WbemIdl.h>
#include <windows.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "pdh.lib")
#else
#include <sys/sysinfo.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <cstring>
#endif

using namespace std;
namespace fs = std::filesystem;

const char *ASCII_CHARS = "$@B%8&WM#*ZO0QLCJUYXzcvunxrjft1-_+~i!lI;:,. ";
#pragma pack(push, 1)
struct BMPHeader
{
    uint16_t bfType;
    uint32_t bfSize;
    uint16_t bfReserved1;
    uint16_t bfReserved2;
    uint32_t bfOffBits;
};

struct BMPInfoHeader
{
    uint32_t biSize;
    int32_t biWidth;
    int32_t biHeight;
    uint16_t biPlanes;
    uint16_t biBitCount;
    uint32_t biCompression;
    uint32_t biSizeImage;
    int32_t biXPelsPerMeter;
    int32_t biYPelsPerMeter;
    uint32_t biClrUsed;
    uint32_t biClrImportant;
};
#pragma pack(pop)

struct RGB
{
    unsigned char r, g, b;
};
#ifdef _WIN32
typedef LONG(WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
std::string getWindowsVersion()
{
    HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
    if (!hMod)
        return "Unknown Windows version";

    RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)::GetProcAddress(hMod, "RtlGetVersion");
    if (!fxPtr)
        return "Unknown Windows version";

    RTL_OSVERSIONINFOW rovi = {0};
    rovi.dwOSVersionInfoSize = sizeof(rovi);
    if (fxPtr(&rovi) != 0)
        return "Unknown Windows version";

    int major = rovi.dwMajorVersion;
    int minor = rovi.dwMinorVersion;
    int build = rovi.dwBuildNumber;

    if (major == 10 && build >= 22000)
        return "Windows 11";
    else if (major == 10)
        return "Windows 10";
    else if (major == 6 && minor == 3)
        return "Windows 8.1";
    else if (major == 6 && minor == 2)
        return "Windows 8";
    else if (major == 6 && minor == 1)
        return "Windows 7";
    else if (major == 6 && minor == 0)
        return "Windows Vista";
    else if (major == 5 && minor == 1)
        return "Windows XP";

    return "Unknown Windows version";
}

DWORD GetParentProcessId(DWORD pid)
{
    DWORD ppid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe))
        {
            do
            {
                if (pe.th32ProcessID == pid)
                {
                    ppid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return ppid;
}

std::string GetProcessName(DWORD pid)
{
    std::string result = "Unknown";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess)
    {
        char exeName[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, NULL, exeName, MAX_PATH))
            result = exeName;
        CloseHandle(hProcess);
    }
    return result;
}

string getPdhErrorMessage(DWORD status)
{
    static char buffer[256];
    FormatMessageA(
        FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
        GetModuleHandleA("pdh.dll"),
        status,
        0,
        buffer,
        sizeof(buffer),
        nullptr);
    return string(buffer);
}

string wstring_to_utf8(const wstring &wstr)
{
    if (wstr.empty())
        return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &strTo[0], size_needed, nullptr, nullptr);
    return strTo;
}

int getCPUUsagePercent()
{
    static PDH_HQUERY cpuQuery;
    static PDH_HCOUNTER cpuTotal;
    static bool initialized = false;

    if (!initialized)
    {
        if (PdhOpenQuery(nullptr, 0, &cpuQuery) != ERROR_SUCCESS)
        {
            std::cerr << "Failed to open PDH query.\n";
            return -1;
        }
        if (PdhAddEnglishCounterW(cpuQuery, L"\\Processor(_Total)\\% Processor Time", 0, &cpuTotal) != ERROR_SUCCESS)
        {
            std::cerr << "Failed to add PDH counter.\n";
            return -1;
        }
        if (PdhCollectQueryData(cpuQuery) != ERROR_SUCCESS)
        {
            std::cerr << "Failed to collect initial PDH data.\n";
            return -1;
        }
        initialized = true;
        Sleep(400);
    }
    if (PdhCollectQueryData(cpuQuery) != ERROR_SUCCESS)
    {
        std::cerr << "Failed to collect PDH data.\n";
        return -1;
    }
    PDH_FMT_COUNTERVALUE counterVal;
    if (PdhGetFormattedCounterValue(cpuTotal, PDH_FMT_DOUBLE, nullptr, &counterVal) != ERROR_SUCCESS)
    {
        std::cerr << "Failed to format counter value.\n";
        return -1;
    }

    return static_cast<int>(std::round(counterVal.doubleValue));
}
#endif

vector<string> getSystemInfoLines()
{
    vector<string> info;

#ifdef _WIN32

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    info.push_back("OS: " + getWindowsVersion());
    info.push_back("CPU cores: " + to_string(sysinfo.dwNumberOfProcessors));

    HKEY hKey;
    char cpuName[256];
    DWORD size = sizeof(cpuName);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr, (LPBYTE)cpuName, &size);
        RegCloseKey(hKey);
        info.push_back(string("CPU: ") + cpuName);
    }

    int usage = getCPUUsagePercent();
    if (usage >= 0)
    {
        info.push_back("CPU Usage: " + to_string(usage) + " %");
    }
    else
    {
        info.push_back("CPU Usage: Unknown");
    }

    {
        HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (SUCCEEDED(hres))
        {
            hres = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                                        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                                        nullptr, EOAC_NONE, nullptr);
            if (SUCCEEDED(hres))
            {
                IWbemLocator *pLocator = nullptr;
                if (CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                     IID_IWbemLocator, (LPVOID *)&pLocator) == S_OK)
                {
                    IWbemServices *pServices = nullptr;
                    if (pLocator->ConnectServer(
                            _bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0, 0, 0, 0, &pServices) == S_OK)
                    {
                        if (CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                                              nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                                              nullptr, EOAC_NONE) == S_OK)
                        {
                            IEnumWbemClassObject *pEnumerator = nullptr;
                            if (pServices->ExecQuery(bstr_t("WQL"),
                                                     bstr_t("SELECT Name FROM Win32_VideoController"),
                                                     WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                                     nullptr, &pEnumerator) == S_OK)
                            {
                                IWbemClassObject *pObj = nullptr;
                                ULONG ret = 0;
                                int gpuIndex = 0;
                                while (pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &ret) == S_OK)
                                {
                                    VARIANT vtProp;
                                    if (pObj->Get(L"Name", 0, &vtProp, 0, 0) == S_OK)
                                    {
                                        info.push_back("GPU " + to_string(gpuIndex++) + ": " + wstring_to_utf8(vtProp.bstrVal));
                                        VariantClear(&vtProp);
                                    }
                                    pObj->Release();
                                }
                                pEnumerator->Release();
                            }
                        }
                        pServices->Release();
                    }
                    pLocator->Release();
                }
            }
            CoUninitialize();
        }
    }

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    uint64_t totalRamMB = memStatus.ullTotalPhys / (1024 * 1024);
    uint64_t availRamMB = memStatus.ullAvailPhys / (1024 * 1024);
    info.push_back("Total/Free/Used RAM: " + to_string(totalRamMB) + " MB total/ " + to_string(availRamMB) + " MB avail. / " + to_string(totalRamMB - availRamMB) + " MB used");

    {
        DWORD currentPID = GetCurrentProcessId();
        DWORD parentPID = GetParentProcessId(currentPID);
        std::string parentName = GetProcessName(parentPID);
        info.push_back("Shell: " + parentName);
    }

#else

    struct utsname unameData;
    if (uname(&unameData) == 0)
    {
        info.push_back(string("OS: ") + unameData.sysname + " " + unameData.release);
    }
    else
    {
        info.push_back("OS: Unknown");
    }

    unsigned int cores = thread::hardware_concurrency();
    if (cores == 0)
        cores = 1;
    info.push_back("CPU cores: " + to_string(cores));

    ifstream cpuinfo("/proc/cpuinfo");
    string line;
    while (getline(cpuinfo, line))
    {
        if (line.find("model name") != string::npos)
        {
            auto pos = line.find(':');
            if (pos != string::npos)
            {
                string model = line.substr(pos + 2);
                info.push_back("CPU: " + model);
            }
            break;
        }
    }

    struct sysinfo memInfo;
    if (sysinfo(&memInfo) == 0)
    {
        uint64_t totalRamMB = memInfo.totalram * memInfo.mem_unit / (1024 * 1024);
        uint64_t freeRamMB = memInfo.freeram * memInfo.mem_unit / (1024 * 1024);
        uint64_t usedRamMB = totalRamMB - freeRamMB;
        info.push_back("Total/Free/Used RAM: " + to_string(totalRamMB) + " MB / " + to_string(freeRamMB) + " MB avail. / " + to_string(freeRamMB) + " MB used");
    }

    {
        FILE *pipe = popen("lspci | grep -i 'vga\\|3d\\|2d'", "r");
        if (pipe)
        {
            char buffer[256];
            vector<string> gpus;
            while (fgets(buffer, sizeof(buffer), pipe))
            {
                gpus.emplace_back(buffer);
            }
            pclose(pipe);
            if (!gpus.empty())
            {
                for (size_t i = 0; i < gpus.size(); ++i)
                {

                    size_t pos = gpus[i].find('\n');
                    if (pos != string::npos)
                        gpus[i] = gpus[i].substr(0, pos);
                    info.push_back("GPU " + to_string(i) + ": " + gpus[i]);
                }
            }
            else
            {
                info.push_back("GPU: Unknown");
            }
        }
        else
        {
            info.push_back("GPU: Unknown");
        }
    }

    static unsigned long long lastTotal = 0, lastIdle = 0;
    ifstream statFile("/proc/stat");
    if (statFile)
    {
        string cpuLine;
        getline(statFile, cpuLine);
        istringstream ss(cpuLine);
        string cpu;
        unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
        ss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;

        unsigned long long idleTime = idle + iowait;
        unsigned long long nonIdle = user + nice + system + irq + softirq + steal;
        unsigned long long total = idleTime + nonIdle;

        unsigned long long totald = total - lastTotal;
        unsigned long long idled = idleTime - lastIdle;

        int cpuPercent = 0;
        if (totald != 0)
            cpuPercent = (int)(100 * (totald - idled) / totald);

        lastTotal = total;
        lastIdle = idleTime;

        info.push_back("CPU Usage: " + to_string(cpuPercent) + " %");
    }

    struct statvfs stat;
    if (statvfs("/", &stat) == 0)
    {
        uint64_t total = stat.f_blocks * stat.f_frsize / (1024 * 1024);
        uint64_t free = stat.f_bfree * stat.f_frsize / (1024 * 1024);
        uint64_t used = total - free;
        info.push_back("Disk (/): Total " + to_string(total) + " MB");
        info.push_back("Disk (/): Used " + to_string(used) + " MB");
        info.push_back("Disk (/): Free " + to_string(free) + " MB");
    }
    else
    {
        info.push_back("Disk (/): Unknown");
    }

    {
        const char *shellEnv = getenv("SHELL");
        if (shellEnv)
        {
            info.push_back(string("Shell: ") + shellEnv);
        }
        else
        {
            info.push_back("Shell: Unknown");
        }
    }

#endif

    return info;
}

int main(int argc, char *argv[])
{

    string osName;

#if defined(_WIN32)
    osName = "windows";
#elif defined(__APPLE__)
    osName = "macos";
#elif defined(__linux__)
    osName = "linux";
#else
    cerr << "Unsupported OS." << endl;
    return 1;
#endif

    fs::path exePath = fs::absolute(argv[0]).parent_path();

    fs::path bmpFilePath = exePath / "icons" / (osName + ".bmp");

    ifstream file(bmpFilePath, ios::binary);
    if (!file)
    {
        cerr << "Cannot open BMP file: " << bmpFilePath << endl;
        return 1;
    }

    BMPHeader header;
    BMPInfoHeader info;

    file.read(reinterpret_cast<char *>(&header), sizeof(header));
    if (header.bfType != 0x4D42)
    {
        cerr << "Not a valid BMP file." << endl;
        return 1;
    }

    file.read(reinterpret_cast<char *>(&info), sizeof(info));
    if (info.biBitCount != 24)
    {
        cerr << "Only 24-bit BMP supported." << endl;
        return 1;
    }

    bool topDown = info.biHeight < 0;
    int width = info.biWidth;
    int height = abs(info.biHeight);

    int padding = (4 - (width * 3) % 4) % 4;

    file.seekg(header.bfOffBits, ios::beg);

    vector<vector<RGB>> pixels(height, vector<RGB>(width));

    for (int y = 0; y < height; y++)
    {
        int row = topDown ? y : (height - 1 - y);
        for (int x = 0; x < width; x++)
        {
            unsigned char b, g, r;
            if (!file.read(reinterpret_cast<char *>(&b), 1) ||
                !file.read(reinterpret_cast<char *>(&g), 1) ||
                !file.read(reinterpret_cast<char *>(&r), 1))
            {
                cerr << "Unexpected end of file." << endl;
                return 1;
            }
            pixels[row][x] = {r, g, b};
        }
        file.ignore(padding);
    }

    const int maxWidth = 20;
    const int maxHeight = 20;

    double scaleX = static_cast<double>(width) / maxWidth;
    double scaleY = static_cast<double>(height) / maxHeight;
    double scale = max(scaleX, scaleY);
    if (scale < 1.0)
        scale = 1.0;

    int outWidth = static_cast<int>(width / scale);
    int outHeight = static_cast<int>(height / scale);

    vector<string> iconLines;

    for (int y = 0; y < outHeight; y++)
    {
        stringstream line;

        for (int x = 0; x < outWidth; x++)
        {
            int startX = static_cast<int>(x * scale);
            int startY = static_cast<int>(y * scale);
            int endX = static_cast<int>((x + 1) * scale);
            int endY = static_cast<int>((y + 1) * scale);

            if (endX > width)
                endX = width;
            if (endY > height)
                endY = height;

            int rSum = 0, gSum = 0, bSum = 0, count = 0;
            for (int yy = startY; yy < endY; yy++)
            {
                for (int xx = startX; xx < endX; xx++)
                {
                    rSum += pixels[yy][xx].r;
                    gSum += pixels[yy][xx].g;
                    bSum += pixels[yy][xx].b;
                    count++;
                }
            }
            if (count == 0)
                count = 1;

            int rAvg = rSum / count;
            int gAvg = gSum / count;
            int bAvg = bSum / count;

            int gray = (rAvg + gAvg + bAvg) / 3;
            int index = gray * 9 / 255;
            char c = ASCII_CHARS[index];

            line << " " << "\x1b[38;2;" << rAvg << ";" << gAvg << ";" << bAvg << "m" << c;
        }
        line << "\x1b[0m";
        iconLines.push_back(line.str());
    }

    vector<string> sysInfoLines = getSystemInfoLines();

    const int iconWidthChars = maxWidth * 2;

    int contentHeight = max((int)iconLines.size(), (int)sysInfoLines.size());
    int iconPaddingTop = (contentHeight - (int)iconLines.size()) / 2;
    int sysInfoPaddingTop = (contentHeight - (int)sysInfoLines.size()) / 2;

#if defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    int totalWidth = csbi.srWindow.Right - csbi.srWindow.Left - 4;
#else
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    int totalWidth = w.ws_col - 4;
#endif

    int sysInfoWidth = totalWidth - iconWidthChars;

    int spaceBetween = (totalWidth - sysInfoWidth) - iconWidthChars;
    if (spaceBetween < 1)
        spaceBetween = 1;

    for (int i = 0; i < contentHeight; i++)
    {
        string iconLine, infoLine;

        if (i < iconPaddingTop || i >= iconPaddingTop + (int)iconLines.size())
        {
            iconLine = string(iconWidthChars, ' ');
        }
        else
        {
            iconLine = iconLines[i - iconPaddingTop];
        }

        if (i < sysInfoPaddingTop || i >= sysInfoPaddingTop + (int)sysInfoLines.size())
        {
            infoLine = "";
        }
        else
        {
            infoLine = sysInfoLines[i - sysInfoPaddingTop];
        }

        int realIconLen = 0;
        for (size_t pos = 0; pos < iconLine.size();)
        {
            if (iconLine[pos] == '\x1b' && pos + 1 < iconLine.size() && iconLine[pos + 1] == '[')
            {
                pos += 2;
                while (pos < iconLine.size() && iconLine[pos] != 'm')
                    pos++;
                if (pos < iconLine.size())
                    pos++;
            }
            else
            {
                realIconLen++;
                pos++;
            }
        }
        if (realIconLen < iconWidthChars)
        {
            iconLine += string(iconWidthChars - realIconLen, ' ');
        }

        cout << iconLine;

        cout << string(spaceBetween, ' ');

        cout << setw(sysInfoWidth) << right << infoLine << "\n";
    }

    return 0;
}
