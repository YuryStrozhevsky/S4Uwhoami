#include "./XSEC/index.h"

#include <iostream>
#include <format>
#include <regex>
#include <string>

#include <NTSecAPI.h>
//***************************************************************************************
std::string status_to_string(std::string_view function, NTSTATUS status)
{
    std::ostringstream stream;
    stream << function << " error #" << LsaNtStatusToWinError(status);

    return stream.str();
}
//***************************************************************************************
void whoami(std::wstring_view TargetName)
{
    #pragma region Initial variables
    HANDLE LogonHandle;
    ULONG PackageId;

    LUID LogonId = {};

    HANDLE Token = nullptr;

    QUOTA_LIMITS QuotaLimits = {};

    NTSTATUS SubStatus = 0;

    TOKEN_SOURCE TokenSource = {};
    std::string source_name = "Somethin"; // Need to be only 8 chars length
    memcpy(TokenSource.SourceName, source_name.data(), 8);
    AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

    PVOID ProfileBuffer = nullptr;
    ULONG ProfileBufferLength = 0;

    std::string package_name = "Kerberos";
    LSA_STRING PackageName = { package_name.size(), package_name.size(), package_name.data() };
    std::string origin_name = "Something";
    LSA_STRING OriginName = { origin_name.size(), origin_name.size(), origin_name.data() };

    auto TargetNameByteLength = TargetName.size() * sizeof(wchar_t);
    #pragma endregion

    #pragma region Request using user name only (without a password)
    std::unique_ptr<unsigned char[]> RawCacheRequest{ new unsigned char[TargetNameByteLength + sizeof(KERB_S4U_LOGON)]() };
    if(!RawCacheRequest)
        throw std::exception("Out of memory");

    PKERB_S4U_LOGON CacheRequest = reinterpret_cast<PKERB_S4U_LOGON>(RawCacheRequest.get());

    CacheRequest->MessageType = KerbS4ULogon;
    CacheRequest->Flags = 0;
    CacheRequest->ClientUpn.Length = TargetNameByteLength;
    CacheRequest->ClientUpn.MaximumLength = TargetNameByteLength;
    CacheRequest->ClientUpn.Buffer = (PWSTR)(CacheRequest + 1);

    std::copy((byte*)TargetName.data(), (byte*)TargetName.data() + TargetNameByteLength, (byte*)CacheRequest->ClientUpn.Buffer);
    #pragma endregion

    #pragma region Send the request to LSA and get access token
    NTSTATUS Status = LsaConnectUntrusted(&LogonHandle);
    std::unique_ptr<void, decltype([](void const* value){ LsaDeregisterLogonProcess((PVOID)value); }) > handle_guard{ LogonHandle };

    Status = LsaLookupAuthenticationPackage(LogonHandle, &PackageName, &PackageId);
    if(Status < 0)
        throw std::exception(status_to_string("LsaLookupAuthenticationPackage", Status).c_str());

    Status = LsaLogonUser(
        LogonHandle,
        &OriginName,
        Network,
        PackageId,
        CacheRequest,
        TargetNameByteLength + sizeof(KERB_S4U_LOGON),
        nullptr,
        &TokenSource,
        &ProfileBuffer,
        &ProfileBufferLength,
        &LogonId,
        &Token,
        &QuotaLimits,
        &SubStatus
    );
    std::unique_ptr<void, decltype([](void const* value){ LsaFreeReturnBuffer((PVOID)value); }) > profilebuffer_guard{ ProfileBuffer };
    std::unique_ptr<void, decltype([](void const* value){ CloseHandle((PVOID)value); }) > token_guard{ Token };

    if(Status < 0)
        throw std::exception(status_to_string("LsaLogonUser", Status).c_str());

    if(SubStatus < 0)
        throw std::exception(status_to_string("LsaLogonUser SubStatus", SubStatus).c_str());

    XSEC::XTOKEN token{ Token };
    #pragma endregion

    #pragma region Information about user
    std::wcout << L"User:" << std::endl;
    std::wcout << L"=====" << std::endl;
    std::wcout << token.User->Sid->commonName() << L"\t" << token.User->Sid->stringRepresentation() << std::endl;
    #pragma endregion

    #pragma region Information about groups
    if(!token.Groups.empty())
    {
        std::wcout << std::endl << L"Groups:" << std::endl;
        std::wcout << L"=======" << std::endl;

        std::vector<std::wstring> first;
        std::vector<std::wstring> second;

        size_t first_max = 0;

        for(auto&& group : token.Groups)
        {
            auto first_str = group.Sid->commonName();
            auto first_size = first_str.size();
            first_max = (first_size > first_max) ? first_size : first_max;

            first.push_back(first_str);
            second.push_back(group.Sid->stringRepresentation());
        }

        for(size_t i = 0; i < first.size(); i++)
            std::wcout << std::format(L"{:{}}", first[i], first_max + 1) << second[i] << std::endl;
    }
    #pragma endregion

    #pragma region Information about privileges
    if(!token.Privileges.empty())
    {
        std::wcout << std::endl << L"Privileges:" << std::endl;
        std::wcout << L"===========" << std::endl;

        std::vector<std::wstring> first;
        std::vector<std::wstring> second;

        size_t first_max = 0;

        for(auto&& privilege : token.Privileges)
        {
            auto names = privilege.Luid->privilegeNames();

            first_max = (names.first.size() > first_max) ? names.first.size() : first_max;

            first.push_back(names.first);
            second.push_back(names.second);
        }

        for(size_t i = 0; i < first.size(); i++)
            std::wcout << std::format(L"{:{}}", first[i], first_max + 1) << second[i] << std::endl;
    }
    #pragma endregion

    #pragma region Information about user claims
    if(nullptr != token.UserClaimAttributes)
    {
        if(!token.UserClaimAttributes->Attributes.empty())
        {
            std::wcout << std::endl << "User claims information:" << std::endl;
            std::wcout << L"========================" << std::endl;

            std::vector<std::wstring> first;
            std::vector<std::wstring> second;

            size_t first_max = 0;

            for(auto&& attribute : token.UserClaimAttributes->Attributes)
            {
                std::wstringstream stream;

                for(auto&& value : attribute->values_to_string())
                {
                    if(stream.tellp())
                        stream << L", ";

                    stream << value;
                }

                first_max = (attribute->Name.size() > first_max) ? attribute->Name.size() : first_max;

                first.push_back(attribute->Name);
                second.push_back(stream.str());
            }

            for(size_t i = 0; i < first.size(); i++)
                std::wcout << std::format(L"{:{}}", first[i], first_max + 1) << second[i] << std::endl;
        }
    }
    #pragma endregion

    #pragma region Information about device claims
    if(nullptr != token.DeviceClaimAttributes)
    {
        if(!token.DeviceClaimAttributes->Attributes.empty())
        {
            std::wcout << std::endl << "Device claims information:" << std::endl;
            std::wcout << L"==========================" << std::endl;

            std::vector<std::wstring> first;
            std::vector<std::wstring> second;

            size_t first_max = 0;

            for(auto&& attribute : token.DeviceClaimAttributes->Attributes)
            {
                std::wstringstream stream;

                for(auto&& value : attribute->values_to_string())
                {
                    if(stream.tellp())
                        stream << L", ";

                    stream << value;
                }

                first_max = (attribute->Name.size() > first_max) ? attribute->Name.size() : first_max;

                first.push_back(attribute->Name);
                second.push_back(stream.str());
            }

            for(size_t i = 0; i < first.size(); i++)
                std::wcout << std::format(L"{:{}}", first[i], first_max + 1) << second[i] << std::endl;
        }
    }
    #pragma endregion

    #pragma region Store full information about the token into XML
    std::wstring strTargetName = TargetName.data();
    std::replace(strTargetName.begin(), strTargetName.end(), L'\\', L'_');
    std::replace(strTargetName.begin(), strTargetName.end(), L'/', L'_');

    XSEC::XSave(token, std::format(L"{}_token.xml", strTargetName));
    #pragma endregion
}
//***************************************************************************************
int wmain(int argc, wchar_t* argv[])
{
    if(S_OK != CoInitialize(NULL))
        return 0;

    std::unique_ptr<void, decltype([](void* value){ delete[] value; CoUninitialize(); }) > com_guard{ reinterpret_cast<void*>(new char[1]{}) };

    if(argc == 2)
    {
        try
        {
            whoami(argv[1]);
        }
        catch(std::exception ex)
        {
            std::cout << ex.what() << std::endl;
        }
        catch(...)
        {
            std::cout << "UNKNOWN ERROR DURING EXECUTION" << std::endl;
        }
    }
    else
        std::cout << "Please provide name for user/device in domain";

    return 0;
}
//***************************************************************************************