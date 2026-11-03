#include "firewall.hpp"

#include <windows.h>
#include <shellapi.h>

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <stdexcept>

#pragma comment(lib, "shell32.lib")

namespace {

std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                   nullptr, 0, nullptr, nullptr);
    std::string out(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                        out.data(), size, nullptr, nullptr);
    return out;
}

std::wstring ToWide(const std::string& s) {
    if (s.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), size);
    return out;
}

std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

void PrintUsage() {
    std::cout <<
R"(winwall - firewall based on Windows Firewall Api

Usage:
  winwall <command> [options] [positional...]

Commands:
  block-all                          Block all outbound traffic
  allow-program  <exe-path>          Allow an application (outbound)
  allow-ip       <ips>               Allow remote IPs (outbound)
  allow-port     <port>              Allow a remote TCP/UDP port (outbound)
  allow-in       <port>              Allow an inbound local port
  restore                            Remove all rules with the prefix and
                                     restore the original outbound action
  list                               List rules created by this CLI
  help                               Show this help

Options:
  --proto=tcp|udp|any                Protocol (default: tcp; allow-program: any)
  --profiles=domain,private,public   Profiles (default: all)
  --remote=<addr[,addr...]>          Remote addresses
  --remote-ports=<ports>             Remote ports
  --local-ports=<ports>              Local ports
  --prefix=<name>                    Rule name prefix (default: AppFW_v1)

NOTE: administrator privileges are required to modify firewall rules.
)";
}

struct Options {
    std::wstring prefix = L"AppFW_v1";
    Protocol proto = Protocol::Any;
    NET_FW_PROFILE_TYPE2 profiles = static_cast<NET_FW_PROFILE_TYPE2>(
        NET_FW_PROFILE2_DOMAIN | NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_PUBLIC);
    std::wstring remote;
    std::wstring remotePorts;
    std::wstring localPorts;
    bool protoSet = false;
    bool profilesSet = false;
};

Protocol ParseProto(const std::string& s) {
    const auto v = Lower(s);
    if (v == "tcp") return Protocol::Tcp;
    if (v == "udp") return Protocol::Udp;
    if (v == "any") return Protocol::Any;
    throw std::invalid_argument("Unknown protocol: " + s);
}

NET_FW_PROFILE_TYPE2 ParseProfiles(const std::string& s) {
    std::stringstream ss(s);
    std::string tok;
    NET_FW_PROFILE_TYPE2 result = static_cast<NET_FW_PROFILE_TYPE2>(0);
    while (std::getline(ss, tok, ',')) {
        tok = Lower(tok);
        while (!tok.empty() && std::isspace((unsigned char)tok.front())) tok.erase(tok.begin());
        while (!tok.empty() && std::isspace((unsigned char)tok.back())) tok.pop_back();
        if (tok.empty() || tok == "all") {
            return static_cast<NET_FW_PROFILE_TYPE2>(
                NET_FW_PROFILE2_DOMAIN | NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_PUBLIC);
        }
        if (tok == "domain")       result = (NET_FW_PROFILE_TYPE2)(result | NET_FW_PROFILE2_DOMAIN);
        else if (tok == "private") result = (NET_FW_PROFILE_TYPE2)(result | NET_FW_PROFILE2_PRIVATE);
        else if (tok == "public")  result = (NET_FW_PROFILE_TYPE2)(result | NET_FW_PROFILE2_PUBLIC);
        else throw std::invalid_argument("Unknown profile: " + tok);
    }
    if (result == 0) throw std::invalid_argument("Empty profile list");
    return result;
}

bool ParseOption(const std::string& arg, Options& opt) {
    auto startsWith = [&](const char* p) { return arg.rfind(p, 0) == 0; };
    if (startsWith("--proto=")) {
        opt.proto = ParseProto(arg.substr(8));
        opt.protoSet = true;
        return true;
    }
    if (startsWith("--profiles=")) {
        opt.profiles = ParseProfiles(arg.substr(11));
        opt.profilesSet = true;
        return true;
    }
    if (startsWith("--remote=")) {
        opt.remote = ToWide(arg.substr(9));
        return true;
    }
    if (startsWith("--remote-ports=")) {
        opt.remotePorts = ToWide(arg.substr(15));
        return true;
    }
    if (startsWith("--local-ports=")) {
        opt.localPorts = ToWide(arg.substr(14));
        return true;
    }
    if (startsWith("--prefix=")) {
        opt.prefix = ToWide(arg.substr(9));
        return true;
    }
    return false;
}

bool IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

int ParsePort(const std::wstring& s) {
    try {
        const int p = std::stoi(ToUtf8(s));
        if (p < 1 || p > 65535) throw std::out_of_range("port");
        return p;
    } catch (...) {
        throw std::invalid_argument("Invalid port number: " + ToUtf8(s));
    }
}

int Run(int argc, wchar_t** argv) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    const std::string cmd = Lower(ToUtf8(argv[1]));

    if (cmd == "help" || cmd == "-h" || cmd == "--help") {
        PrintUsage();
        return 0;
    }

    Options opt;
    std::vector<std::wstring> positional;

    for (int i = 2; i < argc; ++i) {
        std::string a = ToUtf8(argv[i]);
        if (a.rfind("--", 0) == 0) {
            if (!ParseOption(a, opt)) {
                std::cerr << "Unknown option: " << a << "\n";
                return 2;
            }
        } else {
            positional.push_back(argv[i]);
        }
    }

    if (!IsAdmin()) {
        std::cerr << "Administrator privileges required.\n";
        return 3;
    }

    try {
        if (cmd == "restore") {
            Firewall fw(opt.prefix);
            fw.Disable();
            fw.Commit();
            std::cout << "OK: rules removed, default outbound action restored.\n";
            return 0;
        }

        if (cmd == "list") {
            Firewall fw(opt.prefix);
            const auto names = fw.ListRules();
            fw.Commit();
            std::wcout << L"Rules with prefix \"" << opt.prefix << L"\": "
                       << names.size() << L"\n";
            for (const auto& n : names) {
                std::wcout << L"  " << n << L"\n";
            }
            return 0;
        }

        Firewall fw(opt.prefix);

        if (cmd == "block-all") {
            fw.BlockAllOutbound();
            fw.Commit();
            std::cout << "OK: all outbound traffic blocked (persistent).\n"
                         "Undo with: firewall-cli restore\n";
            return 0;
        }

        if (cmd == "allow-program") {
            if (positional.empty()) {
                std::cerr << "allow-program: <exe-path> is required\n";
                return 2;
            }
            const Protocol proto = opt.protoSet ? opt.proto : Protocol::Any;
            fw.AllowProgram(positional[0], proto, opt.profiles);
            fw.Commit();
            std::wcout << L"OK: allowed: " << positional[0] << L"\n";
            return 0;
        }

        if (cmd == "allow-ip") {
            if (positional.empty()) {
                std::cerr << "allow-ip: <ips> is required\n";
                return 2;
            }
            const Protocol proto = opt.protoSet ? opt.proto : Protocol::Tcp;
            const std::wstring ports = opt.remotePorts.empty() ? L"*" : opt.remotePorts;
            fw.AllowIP(positional[0], proto, ports, opt.profiles);
            fw.Commit();
            std::wcout << L"OK: allowed addresses: " << positional[0] << L"\n";
            return 0;
        }

        if (cmd == "allow-port") {
            if (positional.empty()) {
                std::cerr << "allow-port: <port> is required\n";
                return 2;
            }
            const int port = ParsePort(positional[0]);
            const Protocol proto = opt.protoSet ? opt.proto : Protocol::Tcp;
            const std::wstring remote = opt.remote.empty() ? L"*" : opt.remote;
            fw.AllowRemotePort(port, proto, remote, opt.profiles);
            fw.Commit();
            std::wcout << L"OK: outbound port " << port << L" allowed\n";
            return 0;
        }

        if (cmd == "allow-in") {
            if (positional.empty()) {
                std::cerr << "allow-in: <port> is required\n";
                return 2;
            }
            const int port = ParsePort(positional[0]);
            const Protocol proto = opt.protoSet ? opt.proto : Protocol::Tcp;
            fw.AllowLocalPortIn(port, proto, opt.profiles);
            fw.Commit();
            std::wcout << L"OK: inbound port " << port << L" allowed\n";
            return 0;
        }

        std::cerr << "Unknown command: " << cmd << "\n";
        PrintUsage();
        return 2;
    }
    catch (const std::system_error& e) {
        std::cerr << "WinAPI error: " << e.what()
                  << " (HRESULT=0x" << std::hex << (unsigned long)e.code().value()
                  << std::dec << ")\n";
        return 4;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 4;
    }
}

}

int wmain(int argc, wchar_t** argv) {
    return Run(argc, argv);
}