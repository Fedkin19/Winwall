#pragma once

#include <windows.h>
#include <netfw.h>

#ifdef _MSC_VER
#include <atlbase.h>
using CComPtr = ATL::CComPtr;
#else
#include <wrl/client.h>
using Microsoft::WRL::ComPtr;
#define CComPtr ComPtr
#endif

#include <string>
#include <vector>
#include <stdexcept>
#include <system_error>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "netfw.lib")

inline void ThrowIfFailed(HRESULT hr, const char* what) {
    if (FAILED(hr)) {
        throw std::system_error(
            std::error_code(hr, std::system_category()),
            what);
    }
}

enum class Protocol {
    Tcp = NET_FW_IP_PROTOCOL_TCP,
    Udp = NET_FW_IP_PROTOCOL_UDP,
    Any = NET_FW_IP_PROTOCOL_ANY,
};

enum class RuleDirection {
    In  = NET_FW_RULE_DIR_IN,
    Out = NET_FW_RULE_DIR_OUT,
};

class Firewall {
public:
    explicit Firewall(const std::wstring& rulePrefix = L"AppFW_v1")
        : prefix_(rulePrefix)
    {
        ThrowIfFailed(
            policy_.CoCreateInstance(__uuidof(NetFwPolicy2)),
            "CoCreateInstance(NetFwPolicy2)");

        ThrowIfFailed(policy_->get_Rules(&rules_), "get_Rules");

        NET_FW_PROFILE_TYPE2 profile = AllProfiles();
        ThrowIfFailed(
            policy_->get_DefaultOutboundAction(profile, &originalOutboundAction_),
            "get_DefaultOutboundAction");
    }

    ~Firewall() noexcept {
        if (committed_) return;
        try {
            Disable();
        } catch (...) {
        }
    }

    Firewall(const Firewall&) = delete;
    Firewall& operator=(const Firewall&) = delete;
    Firewall(Firewall&&) = delete;
    Firewall& operator=(Firewall&&) = delete;

    void Commit() noexcept {
        committed_ = true;
    }

    void BlockAllOutbound() {
        NET_FW_PROFILE_TYPE2 profile = AllProfiles();
        ThrowIfFailed(
            policy_->put_DefaultOutboundAction(profile, NET_FW_ACTION_BLOCK),
            "put_DefaultOutboundAction(BLOCK)");
        blockAllActive_ = true;
    }

    void AllowProgram(const std::wstring& exePath,
                      Protocol proto = Protocol::Any,
                      NET_FW_PROFILE_TYPE2 profiles = AllProfiles()) {
        AddRule(exePath, proto, RuleDirection::Out,
                exePath.c_str(), {}, {}, profiles, {});
    }

    void AllowIP(const std::wstring& addresses,
                 Protocol proto = Protocol::Tcp,
                 const std::wstring& remotePorts = L"*",
                 NET_FW_PROFILE_TYPE2 profiles = AllProfiles()) {
        AddRule(addresses, proto, RuleDirection::Out,
                nullptr, addresses, remotePorts, profiles, {});
    }

    void AllowRemotePort(int port,
                         Protocol proto = Protocol::Tcp,
                         const std::wstring& remoteAddresses = L"*",
                         NET_FW_PROFILE_TYPE2 profiles = AllProfiles()) {
        AddRule(L"port_" + std::to_wstring(port), proto, RuleDirection::Out,
                nullptr, remoteAddresses, std::to_wstring(port), profiles, {});
    }

    void AllowLocalPortIn(int port,
                          Protocol proto = Protocol::Tcp,
                          NET_FW_PROFILE_TYPE2 profiles = AllProfiles()) {
        AddRule(L"local_port_" + std::to_wstring(port), proto, RuleDirection::In,
                nullptr, {}, {}, profiles, std::to_wstring(port));
    }

    std::vector<std::wstring> ListRules() const {
        std::vector<std::wstring> result;
        if (!rules_) return result;

        CComPtr<IUnknown> enumeratorUnk;
        if (SUCCEEDED(rules_->get__NewEnum(&enumeratorUnk)) && enumeratorUnk) {
            CComPtr<IEnumVARIANT> enumer;
            if (SUCCEEDED(enumeratorUnk->QueryInterface(IID_PPV_ARGS(&enumer))) && enumer) {
                VARIANT v;
                VariantInit(&v);
                ULONG fetched = 0;
                while (enumer->Next(1, &v, &fetched) == S_OK && fetched == 1) {
                    if (v.vt == VT_DISPATCH && v.pdispVal) {
                        CComPtr<INetFwRule> rule;
                        if (SUCCEEDED(v.pdispVal->QueryInterface(IID_PPV_ARGS(&rule))) && rule) {
                            BSTR name = nullptr;
                            if (SUCCEEDED(rule->get_Name(&name)) && name) {
                                std::wstring n(name, SysStringLen(name));
                                SysFreeString(name);
                                if (n.rfind(prefix_ + L"_", 0) == 0) {
                                    result.push_back(n);
                                }
                            }
                        }
                    }
                    VariantClear(&v);
                    fetched = 0;
                }
            }
        }
        return result;
    }

    void Disable() {
        if (!rules_) return;

        HRESULT lastHr = S_OK;

        for (auto it = addedRules_.rbegin(); it != addedRules_.rend(); ++it) {
            HRESULT hr = rules_->Remove(it->c_str());
            if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
                lastHr = hr;
            }
        }
        addedRules_.clear();

        std::vector<std::wstring> stale;
        CComPtr<IUnknown> enumeratorUnk;
        if (SUCCEEDED(rules_->get__NewEnum(&enumeratorUnk)) && enumeratorUnk) {
            CComPtr<IEnumVARIANT> enumer;
            if (SUCCEEDED(enumeratorUnk->QueryInterface(IID_PPV_ARGS(&enumer))) && enumer) {
                VARIANT v;
                VariantInit(&v);
                ULONG fetched = 0;
                while (enumer->Next(1, &v, &fetched) == S_OK && fetched == 1) {
                    if (v.vt == VT_DISPATCH && v.pdispVal) {
                        CComPtr<INetFwRule> rule;
                        if (SUCCEEDED(v.pdispVal->QueryInterface(IID_PPV_ARGS(&rule))) && rule) {
                            BSTR name = nullptr;
                            if (SUCCEEDED(rule->get_Name(&name)) && name) {
                                std::wstring n(name, SysStringLen(name));
                                SysFreeString(name);
                                if (n.rfind(prefix_ + L"_", 0) == 0) {
                                    stale.push_back(n);
                                }
                            }
                        }
                    }
                    VariantClear(&v);
                    fetched = 0;
                }
            }
        }
        for (auto& n : stale) {
            HRESULT hr = rules_->Remove(n.c_str());
            if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
                lastHr = hr;
            }
        }

        if (blockAllActive_) {
            NET_FW_PROFILE_TYPE2 profile = AllProfiles();
            HRESULT hr = policy_->put_DefaultOutboundAction(profile, originalOutboundAction_);
            if (FAILED(hr) && SUCCEEDED(lastHr)) lastHr = hr;
            blockAllActive_ = false;
        }

        ThrowIfFailed(lastHr, "Disable");
    }

private:
    static constexpr NET_FW_PROFILE_TYPE2 AllProfiles() {
        return static_cast<NET_FW_PROFILE_TYPE2>(
            NET_FW_PROFILE2_DOMAIN | NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_PUBLIC);
    }

    void AddRule(const std::wstring& nameSuffix,
                 Protocol proto,
                 RuleDirection direction,
                 const wchar_t* appPath,
                 const std::wstring& remoteAddresses,
                 const std::wstring& remotePorts,
                 NET_FW_PROFILE_TYPE2 profiles,
                 const std::wstring& localPorts)
    {
        if (!rules_) throw std::runtime_error("Firewall: rules collection is null");

        if ((!remotePorts.empty() || !localPorts.empty()) && proto == Protocol::Any) {
            throw std::invalid_argument("Firewall: ports require Tcp or Udp protocol");
        }

        CComPtr<INetFwRule> rule;
        ThrowIfFailed(rule.CoCreateInstance(__uuidof(NetFwRule)),
                      "CoCreateInstance(NetFwRule)");

        std::wstring fullName = prefix_ + L"_" + nameSuffix;
        ThrowIfFailed(rule->put_Name(fullName.c_str()), "put_Name");
        ThrowIfFailed(rule->put_Direction(static_cast<NET_FW_RULE_DIRECTION>(direction)),
                      "put_Direction");
        ThrowIfFailed(rule->put_Protocol(static_cast<LONG>(proto)), "put_Protocol");
        ThrowIfFailed(rule->put_Action(NET_FW_ACTION_ALLOW), "put_Action");
        ThrowIfFailed(rule->put_Enabled(VARIANT_TRUE), "put_Enabled");
        ThrowIfFailed(rule->put_Profiles(profiles), "put_Profiles");

        if (appPath && *appPath) {
            ThrowIfFailed(rule->put_ApplicationName(appPath), "put_ApplicationName");
        }
        if (!remoteAddresses.empty()) {
            ThrowIfFailed(rule->put_RemoteAddresses(remoteAddresses.c_str()),
                          "put_RemoteAddresses");
        }
        if (!remotePorts.empty()) {
            ThrowIfFailed(rule->put_RemotePorts(remotePorts.c_str()), "put_RemotePorts");
        }
        if (!localPorts.empty()) {
            ThrowIfFailed(rule->put_LocalPorts(localPorts.c_str()), "put_LocalPorts");
        }

        rules_->Remove(fullName.c_str());

        ThrowIfFailed(rules_->Add(rule), "INetFwRules::Add");
        addedRules_.push_back(std::move(fullName));
    }

    CComPtr<INetFwPolicy2> policy_;
    CComPtr<INetFwRules>   rules_;
    std::wstring           prefix_;
    std::vector<std::wstring> addedRules_;
    NET_FW_ACTION          originalOutboundAction_ = NET_FW_ACTION_ALLOW;
    bool                   blockAllActive_ = false;
    bool                   committed_ = false;
};