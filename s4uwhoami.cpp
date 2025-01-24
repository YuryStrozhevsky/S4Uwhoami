#include "./XSEC/index.h"
#include "./XKERB/index.h"

#include <iostream>
#include <format>
#include <string>
#include <filesystem>
#include <map>

#include <NTSecAPI.h>

#pragma comment(lib, "Crypt32.lib")
//***************************************************************************************
using parameters = std::map<std::wstring, std::wstring>;
//***************************************************************************************
std::string status_to_string(std::string_view function, NTSTATUS status)
{
    if(status >= 0)
        return "";

    std::ostringstream stream;
    stream << function << " error#" << std::hex << std::uppercase << " 0x" << status << std::dec << " (";

    // https://learn.microsoft.com/en-us/windows/win32/com/com-error-codes-4
    switch(status)
    {
        case SEC_E_INSUFFICIENT_MEMORY:
            stream << "Not enough memory is available to complete this request";
            break;
        case SEC_E_INVALID_HANDLE:
            stream << "The handle specified is invalid";
            break;
        case SEC_E_UNSUPPORTED_FUNCTION:
            stream << "The function requested is not supported";
            break;
        case SEC_E_TARGET_UNKNOWN:
            stream << "The specified target is unknown or unreachable";
            break;
        case SEC_E_INTERNAL_ERROR:
            stream << "The Local Security Authority cannot be contacted";
            break;
        case SEC_E_SECPKG_NOT_FOUND:
            stream << "The requested security package does not exist";
            break;
        case SEC_E_NOT_OWNER:
            stream << "The caller is not the owner of the desired credentials";
            break;
        case SEC_E_CANNOT_INSTALL:
            stream << "The security package failed to initialize, and cannot be installed";
            break;
        case SEC_E_INVALID_TOKEN:
            stream << "The token supplied to the function is invalid";
            break;
        case SEC_E_CANNOT_PACK:
            stream << "The security package is not able to marshal the logon buffer, so the logon attempt has failed";
            break;
        case SEC_E_QOP_NOT_SUPPORTED:
            stream << "The per-message Quality of Protection is not supported by the security package";
            break;
        case SEC_E_NO_IMPERSONATION:
            stream << "The security context does not allow impersonation of the client";
            break;
        case SEC_E_LOGON_DENIED:
            stream << "The logon attempt failed";
            break;
        case SEC_E_UNKNOWN_CREDENTIALS:
            stream << "The credentials supplied to the package were not recognized";
            break;
        case SEC_E_NO_CREDENTIALS:
            stream << "No credentials are available in the security package";
            break;
        case SEC_E_MESSAGE_ALTERED:
            stream << "The message or signature supplied for verification has been altered";
            break;
        case SEC_E_OUT_OF_SEQUENCE:
            stream << "The message supplied for verification is out of sequence";
            break;
        case SEC_E_NO_AUTHENTICATING_AUTHORITY:
            stream << "No authority could be contacted for authentication";
            break;
        case SEC_E_BAD_PKGID:
            stream << "The requested security package does not exist";
            break;
        case SEC_E_CONTEXT_EXPIRED:
            stream << "The context has expired and can no longer be used";
            break;
        case SEC_E_INCOMPLETE_MESSAGE:
            stream << "The supplied message is incomplete. The signature was not verified.";
            break;
        case SEC_E_INCOMPLETE_CREDENTIALS:
            stream << "The credentials supplied were not complete, and could not be verified. The context could not be initialized.";
            break;
        case SEC_E_BUFFER_TOO_SMALL:
            stream << "The buffers supplied to a function was too small";
            break;
        case SEC_E_WRONG_PRINCIPAL:
            stream << "The target principal name is incorrect";
            break;
        case SEC_E_TIME_SKEW:
            stream << "The clocks on the client and server machines are skewed";
            break;
        case SEC_E_UNTRUSTED_ROOT:
            stream << "The certificate chain was issued by an authority that is not trusted";
            break;
        case SEC_E_ILLEGAL_MESSAGE:
            stream << "The message received was unexpected or badly formatted";
            break;
        case SEC_E_CERT_UNKNOWN:
            stream << "An unknown error occurred while processing the certificate";
            break;
        case SEC_E_CERT_EXPIRED:
            stream << "The received certificate has expired";
            break;
        case SEC_E_ENCRYPT_FAILURE:
            stream << "The specified data could not be encrypted";
            break;
        case SEC_E_DECRYPT_FAILURE:
            stream << "The specified data could not be decrypted";
            break;
        case SEC_E_ALGORITHM_MISMATCH:
            stream << "The client and server cannot communicate, because they do not possess a common algorithm";
            break;
        case SEC_E_SECURITY_QOS_FAILED:
            stream << "The security context could not be established due to a failure in the requested quality of service (e.g. mutual authentication or delegation)";
            break;
        case SEC_E_UNFINISHED_CONTEXT_DELETED:
            stream << "A security context was deleted before the context was completed. This is considered a logon failure.";
            break;
        case SEC_E_NO_TGT_REPLY:
            stream << "The client is trying to negotiate a context and the server requires user-to-user but didn't send a TGT reply";
            break;
        case SEC_E_NO_IP_ADDRESSES:
            stream << "Unable to accomplish the requested task because the local machine does not have any IP addresses";
            break;
        case SEC_E_WRONG_CREDENTIAL_HANDLE:
            stream << "The supplied credential handle does not match the credential associated with the security context";
            break;
        case SEC_E_CRYPTO_SYSTEM_INVALID:
            stream << "The crypto system or checksum function is invalid because a required function is unavailable";
            break;
        case SEC_E_MAX_REFERRALS_EXCEEDED:
            stream << "The number of maximum ticket referrals has been exceeded";
            break;
        case SEC_E_MUST_BE_KDC:
            stream << "The local machine must be a Kerberos KDC (domain controller) and it is not";
            break;
        case SEC_E_STRONG_CRYPTO_NOT_SUPPORTED:
            stream << "The other end of the security negotiation is requires strong crypto but it is not supported on the local machine";
            break;
        case SEC_E_TOO_MANY_PRINCIPALS:
            stream << "The KDC reply contained more than one principal name";
            break;
        case SEC_E_NO_PA_DATA:
            stream << "Expected to find PA data for a hint of what etype to use, but it was not found";
            break;
        case SEC_E_PKINIT_NAME_MISMATCH:
            stream << "The client certificate does not contain a valid UPN, or does not match the client name in the logon request. Please contact your administrator.";
            break;
        case SEC_E_SMARTCARD_LOGON_REQUIRED:
            stream << "Smartcard logon is required and was not used";
            break;
        case SEC_E_SHUTDOWN_IN_PROGRESS:
            stream << "A system shutdown is in progress";
            break;
        case SEC_E_KDC_INVALID_REQUEST:
            stream << "An invalid request was sent to the KDC";
            break;
        case SEC_E_KDC_UNABLE_TO_REFER:
            stream << "The KDC was unable to generate a referral for the service requested";
            break;
        case SEC_E_KDC_UNKNOWN_ETYPE:
            stream << "The encryption type requested is not supported by the KDC";
            break;
        case SEC_E_UNSUPPORTED_PREAUTH:
            stream << "An unsupported preauthentication mechanism was presented to the Kerberos package";
            break;
        case SEC_E_DELEGATION_REQUIRED:
            stream << "The requested operation cannot be completed. The computer must be trusted for delegation and the current user account must be configured to allow delegation.";
            break;
        case SEC_E_BAD_BINDINGS:
            stream << "Client`s supplied SSPI channel bindings were incorrect";
            break;
        case SEC_E_MULTIPLE_ACCOUNTS:
            stream << "The received certificate was mapped to multiple accounts";
            break;
        case SEC_E_NO_KERB_KEY:
            stream << "SEC_E_NO_KERB_KEY";
            break;
        case SEC_E_CERT_WRONG_USAGE:
            stream << "The certificate is not valid for the requested usage";
            break;
        case SEC_E_DOWNGRADE_DETECTED:
            stream << "The system cannot contact a domain controller to service the authentication request. Please try again later.";
            break;
        case SEC_E_SMARTCARD_CERT_REVOKED:
            stream << "The smartcard certificate used for authentication has been revoked. Please contact your system administrator. There may be additional information in the event log.";
            break;
        case SEC_E_ISSUING_CA_UNTRUSTED:
            stream << "An untrusted certificate authority was detected While processing the smartcard certificate used for authentication. Please contact your system administrator.";
            break;
        case SEC_E_REVOCATION_OFFLINE_C:
            stream << "The revocation status of the smartcard certificate used for authentication could not be determined. Please contact your system administrator.";
            break;
        case SEC_E_PKINIT_CLIENT_FAILURE:
            stream << "The smartcard certificate used for authentication was not trusted. Please contact your system administrator.";
            break;
        case SEC_E_SMARTCARD_CERT_EXPIRED:
            stream << "The smartcard certificate used for authentication has expired. Please contact your system administrator.";
            break;
        case SEC_E_NO_S4U_PROT_SUPPORT:
            stream << "The Kerberos subsystem encountered an error. A service for user protocol request was made against a domain controller which does not support service for user.";
            break;
        case SEC_E_CROSSREALM_DELEGATION_FAILURE:
            stream << "An attempt was made by this server to make a Kerberos constrained delegation request for a target outside of the server's realm. This is not supported, and indicates a misconfiguration on this server's allowed to delegate to list. Please contact your administrator.";
            break;
        case SEC_E_REVOCATION_OFFLINE_KDC:
            stream << "The revocation status of the domain controller certificate used for smartcard authentication could not be determined. There is additional information in the system event log. Please contact your system administrator.";
            break;
        case SEC_E_ISSUING_CA_UNTRUSTED_KDC:
            stream << "An untrusted certificate authority was detected while processing the domain controller certificate used for authentication. There is additional information in the system event log. Please contact your system administrator.";
            break;
        case SEC_E_KDC_CERT_EXPIRED:
            stream << "The domain controller certificate used for smartcard logon has expired. Please contact your system administrator with the contents of your system event log.";
            break;
        case SEC_E_KDC_CERT_REVOKED:
            stream << "The domain controller certificate used for smartcard logon has been revoked. Please contact your system administrator with the contents of your system event log.";
            break;
        case SEC_E_INVALID_PARAMETER:
            stream << "One or more of the parameters passed to the function was invalid";
            break;
        case SEC_E_DELEGATION_POLICY:
            stream << "Client policy does not allow credential delegation to target server";
            break;
        case SEC_E_POLICY_NLTM_ONLY:
            stream << "Client policy does not allow credential delegation to target server with NLTM only authentication";
            break;
        case SEC_E_NO_CONTEXT:
            stream << "The required security context does not exist";
            break;
        case SEC_E_PKU2U_CERT_FAILURE:
            stream << "The PKU2U protocol encountered an error while attempting to utilize the associated certificates";
            break;
        case SEC_E_MUTUAL_AUTH_FAILED:
            stream << "The identity of the server computer could not be verified";
            break;
        case SEC_E_ONLY_HTTPS_ALLOWED:
            stream << "Only https scheme is allowed";
            break;
        case 0xC000005E: // STATUS_NO_LOGON_SERVER
            stream << "No logon server found";
            break;
        case 0xC000006D: // STATUS_LOGON_FAILURE
            stream << "Logon failure (No such user)";
            break;
        default:
            stream << "Unknown error";
    }

    stream << ")" << std::endl;

    return stream.str();
}
//***************************************************************************************
void whoami_x509(parameters&& params)
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
    if(params.contains(L"-u"))
    {
        TargetNameByteLength = params[L"-u"].size() * sizeof(wchar_t);
        OverallLength += TargetNameByteLength;
    }

    if(params.contains(L"-d"))
    {
        DomainNameByteLength = params[L"-d"].size() * sizeof(wchar_t);
        OverallLength += DomainNameByteLength;
    }

    if(params.contains(L"-c"))
    {
        std::ifstream stream(std::filesystem::path{ params[L"-c"] }, std::ios::in | std::ios::binary | std::ios::ate);
        if(stream.is_open() == false)
        {
            std::wcout << "Unable to open file: " << params[L"-c"] << std::endl;
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

    if(params.contains(L"-u"))
    {
        CacheRequest->UserPrincipalName.Length = TargetNameByteLength;
        CacheRequest->UserPrincipalName.MaximumLength = TargetNameByteLength;
        CacheRequest->UserPrincipalName.Buffer = (PWSTR)((byte*)CacheRequest + CurrentLength);

        auto UserName = params[L"-u"];

        std::copy((byte*)UserName.data(), (byte*)UserName.data() + TargetNameByteLength, (byte*)CacheRequest->UserPrincipalName.Buffer);

        CurrentLength += TargetNameByteLength;
    }

    if(params.contains(L"-d"))
    {
        CacheRequest->DomainName.Length = DomainNameByteLength;
        CacheRequest->DomainName.MaximumLength = DomainNameByteLength;
        CacheRequest->DomainName.Buffer = (PWSTR)((byte*)CacheRequest + CurrentLength);

        auto DomainName = params[L"-d"];

        std::copy((byte*)DomainName.data(), (byte*)DomainName.data() + DomainNameByteLength, (byte*)CacheRequest->DomainName.Buffer);

        CurrentLength += DomainNameByteLength;
    }

    if(params.contains(L"-c"))
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
    if(params.contains(L"-u"))
        strTargetName = params[L"-u"].data();
    else
        strTargetName = std::filesystem::path{ params[L"-c"] }.filename().wstring().data();

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
    bool pinned = false;

    std::vector<std::wstring> valid{ L"-u", L"-d", L"-c", L"-s" };
    parameters params;

    do
    {
        if(std::find(valid.begin(), valid.end(), argv[count]) == valid.end())
        {
            usage();
            return 0;
        }

        count++;
        if(count > argc)
        {
            usage();
            return 0;
        }

        params[argv[count - 1]] = argv[count];

    } while(++count < argc);

    try
    {
        if(params.contains(L"-s"))
        {
            if(params.contains(L"-d") == false)
            {
                std::cout << "You need to provide domain name (-d) if you would like to pin Kerberos KDC" << std::endl;
                return 0;
            }

            pinned = true;

            XKERB::XCallAuthenticationPackage<KerbPinKdcMessage>({
                .Realm = params[L"-d"],
                .KdcAddress = params[L"-s"]
            });
        }

        if((params.contains(L"-u") == false) && (params.contains(L"-c") == false))
        {
            std::cout << "You need to provie either <user_name> or <file_name>" << std::endl;
            return 0;
        }

        whoami_x509(std::move(params));
    }
    catch(std::exception ex)
    {
        std::cout << ex.what() << std::endl;
    }
    catch(...)
    {
        std::cout << "UNKNOWN ERROR DURING EXECUTION" << std::endl;
    }

    if(pinned)
        XKERB::XCallAuthenticationPackage<KerbUnpinAllKdcsMessage>({});

    return 0;
}
//***************************************************************************************