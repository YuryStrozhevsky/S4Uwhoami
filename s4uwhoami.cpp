#include "./XSEC/index.h"
#include "./XKERB/index.h"

#include <iostream>
#include <format>
#include <regex>
#include <string>
#include <filesystem>

#include <NTSecAPI.h>

#pragma comment(lib, "Crypt32.lib")
//***************************************************************************************
std::string status_to_string(std::string_view function, NTSTATUS status)
{
    std::ostringstream stream;
    stream << function << " error #" << LsaNtStatusToWinError(status);

    return stream.str();
}
//***************************************************************************************
struct parameters {
    std::optional<std::wstring> user_name = std::nullopt;
    std::optional<std::wstring> domain_name = std::nullopt;
    std::optional<std::wstring> file_name = std::nullopt;
};
//***************************************************************************************
void whoami_x509(parameters params)
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

    unsigned long long TargetNameByteLength = 0;
    unsigned long long DomainNameByteLength = 0;
    unsigned long long CertificateLength = 0;
    unsigned long long OverallLength = sizeof(KERB_CERTIFICATE_S4U_LOGON);
    unsigned long long CurrentLength = sizeof(KERB_CERTIFICATE_S4U_LOGON);

    std::vector<unsigned char> Certificate;
    #pragma endregion

    #pragma region Request input parameters
    if(params.user_name != std::nullopt)
    {
        TargetNameByteLength = params.user_name.value().size() * sizeof(wchar_t);
        OverallLength += TargetNameByteLength;
    }

    if(params.domain_name != std::nullopt)
    {
        DomainNameByteLength = params.domain_name.value().size() * sizeof(wchar_t);
        OverallLength += DomainNameByteLength;
    }

    if(params.file_name != std::nullopt)
    {
        std::ifstream stream(std::filesystem::path{ params.file_name.value() }, std::ios::in | std::ios::binary | std::ios::ate);
        if(stream.is_open() == false)
        {
            std::wcout << "Unable to open file: " << params.file_name.value() << std::endl;
            return;
        }

        auto size = stream.tellg();
        std::vector<unsigned char> data(size);

        Certificate.resize(size);

        stream.seekg(0);
        stream.read((char*)Certificate.data(), size);

        CertificateLength = size;
        OverallLength += CertificateLength;
    }

    std::unique_ptr<unsigned char[]> RawCacheRequest{ new unsigned char[OverallLength]() };
    if(!RawCacheRequest)
        throw std::exception("Out of memory");

    PKERB_CERTIFICATE_S4U_LOGON CacheRequest = reinterpret_cast<PKERB_CERTIFICATE_S4U_LOGON>(RawCacheRequest.get());

    CacheRequest->MessageType = KerbCertificateS4ULogon;
    CacheRequest->Flags = 0;

    if(params.user_name != std::nullopt)
    {
        CacheRequest->UserPrincipalName.Length = TargetNameByteLength;
        CacheRequest->UserPrincipalName.MaximumLength = TargetNameByteLength;
        CacheRequest->UserPrincipalName.Buffer = (PWSTR)((byte*)CacheRequest + CurrentLength);

        std::copy((byte*)params.user_name.value().data(), (byte*)params.user_name.value().data() + TargetNameByteLength, (byte*)CacheRequest->UserPrincipalName.Buffer);

        CurrentLength += TargetNameByteLength;
    }

    if(params.domain_name != std::nullopt)
    {
        CacheRequest->DomainName.Length = DomainNameByteLength;
        CacheRequest->DomainName.MaximumLength = DomainNameByteLength;
        CacheRequest->DomainName.Buffer = (PWSTR)((byte*)CacheRequest + CurrentLength);

        std::copy((byte*)params.domain_name.value().data(), (byte*)params.domain_name.value().data() + DomainNameByteLength, (byte*)CacheRequest->DomainName.Buffer);

        CurrentLength += DomainNameByteLength;
    }

    if(params.file_name != std::nullopt)
    {
        CacheRequest->CertificateLength = CertificateLength;
        CacheRequest->Certificate = (PUCHAR)((byte*)CacheRequest + CurrentLength);

        std::copy(Certificate.begin(), Certificate.end(), (byte*)CacheRequest->Certificate);
    }
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
        OverallLength,
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
    std::wstring strTargetName;
    if(params.user_name != std::nullopt)
        strTargetName = params.user_name.value().data();
    else
        strTargetName = std::filesystem::path{ params.file_name.value() }.filename().wstring().data();

    std::replace(strTargetName.begin(), strTargetName.end(), L'\\', L'_');
    std::replace(strTargetName.begin(), strTargetName.end(), L'/', L'_');

    XSEC::XSave(token, std::format(L"{}_token.xml", strTargetName));
    #pragma endregion
}
//***************************************************************************************
void usage()
{
    std::cout << "S4UWhoami (c) 2024-2025, Yury Strozhevsky" << std::endl << std::endl;
    std::cout << "Example: " << std::endl;
    std::cout << "\tS4UWhoami [-s <kdc_address>] [-u <user_name>] [-d <user_domain>] [-c <file_with_user_cert>]" << std::endl << std::endl;
    std::cout << "kdc_address: IP address or DNS for Kerberos KDC for send requests to" << std::endl;
}
//***************************************************************************************
int wmain(int argc, wchar_t* argv[])
{
    if(S_OK != CoInitialize(NULL))
        return 0;

    std::unique_ptr<void, decltype([](void* value){ delete[] value; CoUninitialize(); }) > com_guard{ reinterpret_cast<void*>(new char[1]{}) };

    if(argc == 1)
    {
        usage();
        return 0;
    }

    int count = 1;

    std::optional<std::wstring> server_name = std::nullopt;
    parameters params;

    do
    {
        std::wstring param = argv[count];

        if(param == L"-u")
        {
            count++;
            if(count > argc)
            {
                usage();
                return 0;
            }

            params.user_name = argv[count];
        }
        else
        {
            if(param == L"-d")
            {
                count++;
                if(count > argc)
                {
                    usage();
                    return 0;
                }

                params.domain_name = argv[count];
            }
            else
            {
                if(param == L"-c")
                {
                    count++;
                    if(count > argc)
                    {
                        usage();
                        return 0;
                    }

                    params.file_name = argv[count];
                }
                else
                {
                    if(param == L"-s")
                    {
                        count++;
                        if(count > argc)
                        {
                            usage();
                            return 0;
                        }

                        server_name = argv[count];
                    }
                    else
                    {
                        usage();
                        return 0;
                    }
                }
            }
        }
    } while(++count < argc);

    try
    {
        if(server_name != std::nullopt)
        {
            if(params.domain_name == std::nullopt)
            {
                std::cout << "You need to provide domain name (-d) if you would like to pin Kerberos KDC" << std::endl;
                return 0;
            }

            XKERB::XCallAuthenticationPackage<KerbPinKdcMessage>({
                .Realm = params.domain_name.value(),
                .KdcAddress = server_name.value()
            });
        }

        if((params.user_name == std::nullopt) && (params.file_name == std::nullopt))
        {
            std::cout << "You need to provie either <user_name> or <file_name>" << std::endl;
            return 0;
        }

        whoami_x509(params);
    }
    catch(std::exception ex)
    {
        std::cout << ex.what() << std::endl;
    }
    catch(...)
    {
        std::cout << "UNKNOWN ERROR DURING EXECUTION" << std::endl;
    }

    if(server_name != std::nullopt)
        XKERB::XCallAuthenticationPackage<KerbUnpinAllKdcsMessage>({});

    return 0;
}
//***************************************************************************************