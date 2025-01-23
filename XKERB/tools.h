#pragma once
//***********************************************************************************************************
#include <Windows.h>
#include <NTSecAPI.h>
#include <sspi.h>

#include <optional>
#include <string>
#include <memory>
#include <iomanip>
//***********************************************************************************************************
namespace XKERB
{
	//*******************************************************************************************************
    using _CloseHandle = decltype([](HANDLE value){ CloseHandle(value); });
    //*******************************************************************************************************
    struct CREDS_HANDLE_DATA
    {
        std::optional<std::wstring_view> User = std::nullopt;
        std::optional<std::wstring_view> Password = std::nullopt;
        ULONG CredentialsUse{ SECPKG_CRED_OUTBOUND };
        std::optional<std::wstring_view> Principal = std::nullopt;
        std::wstring_view Package{ L"Kerberos" };
        std::optional<LUID> LogonId = std::nullopt;
    };
    //***********************************************************************************************************
    using CredHandleReturnType = std::unique_ptr < CredHandle, decltype([](PCredHandle value){ FreeCredentialsHandle(value); }) > ;
    //***********************************************************************************************************
    CredHandleReturnType XAcquireCredentialsHandle(CREDS_HANDLE_DATA data)
    {
        #pragma region Initial variables
        TimeStamp Lifetime;

        std::unique_ptr<SEC_WINNT_AUTH_IDENTITY_W> identity;

        CredHandleReturnType result{ new CredHandle() };
        if(!result)
            throw std::exception("Out of memory");
        #pragma endregion

        if(data.User)
        {
            identity = std::unique_ptr<SEC_WINNT_AUTH_IDENTITY_W>{ new SEC_WINNT_AUTH_IDENTITY_W() };
            if(!identity)
                throw std::exception("Out of memory");

            identity->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

            identity->User = (unsigned short*)data.User.value().data();
            identity->UserLength = (unsigned long)data.User.value().size();

            if(data.Password)
            {
                identity->Password = (unsigned short*)data.Password.value().data();
                identity->PasswordLength = (unsigned long)data.Password.value().size();
            }
        }

        auto status = AcquireCredentialsHandleW(
            (data.Principal) ? (LPWSTR)data.Principal.value().data() : nullptr,
            (LPWSTR)data.Package.data(),
            data.CredentialsUse,
            (data.LogonId) ? &data.LogonId.value() : nullptr,
            identity.get(),
            nullptr,
            nullptr,
            result.get(),
            &Lifetime
        );
        if(status < 0)
            throw std::exception(secstatus_to_string("AcquireCredentialsHandle", status).data());

        return result;
    }
    //***********************************************************************************************************
    struct XLogonUserParameters
    {
        std::optional<std::wstring_view> User = std::nullopt;
        std::optional<std::wstring_view> Password = std::nullopt;
        std::optional<std::wstring_view> Domain = std::nullopt;
        SECURITY_LOGON_TYPE LogonType = SECURITY_LOGON_TYPE::Interactive;
        std::string_view PackageName = "Kerberos";
        bool S4U = false;
    };
    //***********************************************************************************************************
    using HandleReturnType = std::unique_ptr<void, _CloseHandle>;
    //***********************************************************************************************************
    HandleReturnType XLogonUser(XLogonUserParameters parameters)
    {
        #pragma region Initial variables
        HANDLE LogonHandle;
        ULONG PackageId;

        PVOID ProfileBuffer = nullptr;
        ULONG ProfileBufferLength = 0;

        LUID LogonId = {};

        HANDLE Token = nullptr;

        QUOTA_LIMITS QuotaLimits = {};

        NTSTATUS SubStatus = 0;

        TOKEN_SOURCE TokenSource = {};
        std::string source_name = "Somethin";
        memcpy(TokenSource.SourceName, source_name.data(), 8);
        AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

        LSA_STRING PackageName = { (USHORT)parameters.PackageName.size(), (USHORT)parameters.PackageName.size(), (PCHAR)parameters.PackageName.data() };
        std::string origin_name = "Something";
        LSA_STRING OriginName = { (USHORT)origin_name.size(), (USHORT)origin_name.size(), origin_name.data() };

        size_t UserLength = (parameters.User) ? (parameters.User.value().size() * size_wchar) : 0;
        size_t PasswordLength = (parameters.Password) ? (parameters.Password.value().size() * size_wchar) : 0;
        size_t DomainLength = (parameters.Domain) ? (parameters.Domain.value().size() * size_wchar) : 0;

        PVOID AuthenticationInformation = nullptr;
        raw_ptr AuthenticationInformationGuard;

        ULONG AuthenticationInformationLength = 0;
        #pragma endregion

        if(parameters.S4U)
        {
            #pragma region Check we do have user name provided
            if(!parameters.User)
                throw std::exception("For S4U logon at least user name is necessary");
            #pragma endregion

            #pragma region It is mandatory for S4U to have "logon type" as "Network"
            parameters.LogonType = Network;
            #pragma endregion

            #pragma region Fill KERB_CERTIFICATE_S4U_LOGON
            AuthenticationInformationLength = (ULONG)(sizeof(KERB_CERTIFICATE_S4U_LOGON) + UserLength + DomainLength);

            AuthenticationInformation = new unsigned char[AuthenticationInformationLength]();
            if(!AuthenticationInformation)
                throw std::exception("Out of memory");

            AuthenticationInformationGuard = raw_ptr{ reinterpret_cast<unsigned char*>(AuthenticationInformation) };

            PKERB_CERTIFICATE_S4U_LOGON LogonInfo = reinterpret_cast<PKERB_CERTIFICATE_S4U_LOGON>(AuthenticationInformation);

            LogonInfo->MessageType = KerbCertificateS4ULogon;
            LogonInfo->Flags = 0;

            string_to_unistring(&LogonInfo->UserPrincipalName, (byte*)AuthenticationInformation + sizeof(KERB_CERTIFICATE_S4U_LOGON), parameters.User.value());

            if(parameters.Domain)
                string_to_unistring(&LogonInfo->DomainName, (byte*)AuthenticationInformation + sizeof(KERB_CERTIFICATE_S4U_LOGON) + UserLength, parameters.Domain.value());
            #pragma endregion
        }
        else
        {
            #pragma region Fill KERB_INTERACTIVE_LOGON
            auto BaseSize = sizeof(KERB_INTERACTIVE_LOGON);

            AuthenticationInformationLength = (ULONG)(BaseSize + UserLength + PasswordLength + DomainLength);

            AuthenticationInformation = new unsigned char[AuthenticationInformationLength]();
            if(!AuthenticationInformation)
                throw std::exception("Out of memory");

            AuthenticationInformationGuard = raw_ptr{ reinterpret_cast<unsigned char*>(AuthenticationInformation) };

            PKERB_INTERACTIVE_LOGON LogonInfo = reinterpret_cast<PKERB_INTERACTIVE_LOGON>(AuthenticationInformation);

            LogonInfo->MessageType = KerbInteractiveLogon;

            auto address = (byte*)AuthenticationInformation + BaseSize;

            if(parameters.User)
            {
                string_to_unistring(&LogonInfo->UserName, address, parameters.User.value());
                address += UserLength;
            }

            if(parameters.Password)
            {
                string_to_unistring(&LogonInfo->Password, address, parameters.Password.value());
                address += PasswordLength;
            }

            if(parameters.Domain)
                string_to_unistring(&LogonInfo->LogonDomainName, address, parameters.Domain.value());
            #pragma endregion

            int iii = 0;
        }

        #pragma region Call LsaLogonUser
        NTSTATUS Status = LsaConnectUntrusted(&LogonHandle);
        std::unique_ptr<void, _LsaDeregisterLogonProcess> LogonHandleGuard{ LogonHandle };

        Status = LsaLookupAuthenticationPackage(LogonHandle, &PackageName, &PackageId);
        if(!NT_SUCCESS(Status))
            throw std::exception(status_to_string("LsaLookupAuthenticationPackage", Status).c_str());

        Status = LsaLogonUser(
            LogonHandle,
            &OriginName,
            parameters.LogonType,
            PackageId,
            AuthenticationInformation,
            AuthenticationInformationLength,
            nullptr,
            &TokenSource,
            &ProfileBuffer,
            &ProfileBufferLength,
            &LogonId,
            &Token,
            &QuotaLimits,
            &SubStatus
        );
        if(Status < 0)
            throw std::exception(status_to_string("LsaLogonUser", Status).c_str());

        LsaFreeReturnBuffer(ProfileBuffer);
        #pragma endregion

        return HandleReturnType{ Token };
    }
    //***********************************************************************************************************
    auto XImpersonateLoggedOnUser(HANDLE token)
    {
        if(!ImpersonateLoggedOnUser(token))
            throw std::exception("Cannot perform ImpersonateLoggedOnUser");

        auto result = std::unique_ptr<void, decltype([](void* value){ delete value;  RevertToSelf(); }) > { new char };
        if(!result)
            throw std::exception("Out of memory");

        return result;
    }
    //***********************************************************************************************************
    std::wstring_view XKList()
    {
        #pragma region Initial variables
        std::wstringstream stream;
        #pragma endregion

        #pragma region Aux lambdas
        auto FileTimeToString = [](FILETIME* ft) -> std::wstring
        {
            SYSTEMTIME st = { 0 };

            FileTimeToSystemTime(ft, &st);

            std::wstring dateBuf(128, L'\0');
            std::wstring timeBuf(128, L'\0');

            int size = GetDateFormatEx(LOCALE_NAME_SYSTEM_DEFAULT, DATE_SHORTDATE | LOCALE_USE_CP_ACP, &st, nullptr, dateBuf.data(), (int)dateBuf.size(), nullptr);
            if(size)
            {
                dateBuf.resize(--size);

                size = GetTimeFormatEx(LOCALE_NAME_SYSTEM_DEFAULT, LOCALE_USE_CP_ACP, &st, nullptr, timeBuf.data(), (int)timeBuf.size());
                if(size)
                {
                    timeBuf.resize(--size);

                    return std::wstring{ dateBuf + L" " + timeBuf };
                }
            }

            return L"";
        };

        auto EncryptionTypeToString = [](LONG type) -> std::wstring
        {
            switch(type)
            {
                case KERB_ETYPE_NULL:
                    return L"NULL";
                case KERB_ETYPE_DES_CBC_CRC:
                    return L"DES_CBC_CRC";
                case KERB_ETYPE_DES_CBC_MD4:
                    return L"DES_CBC_MD4";
                case KERB_ETYPE_DES_CBC_MD5:
                    return L"DES_CBC_MD5";
                case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:
                    return L"AES128_CTS_HMAC_SHA1_96";
                case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:
                    return L"AES256_CTS_HMAC_SHA1_96";
                case KERB_ETYPE_RC4_MD4:
                    return L"RC4_MD4";
                case KERB_ETYPE_RC4_PLAIN2:
                    return L"RC4_PLAIN2";
                case KERB_ETYPE_RC4_LM:
                    return L"RC4_LM";
                case KERB_ETYPE_RC4_SHA:
                    return L"RC4_SHA";
                case KERB_ETYPE_DES_PLAIN:
                    return L"DES_PLAIN";
                case KERB_ETYPE_RC4_HMAC_OLD:
                    return L"RC4_HMAC_OLD";
                case KERB_ETYPE_RC4_PLAIN_OLD:
                    return L"RC4_PLAIN_OLD";
                case KERB_ETYPE_RC4_HMAC_OLD_EXP:
                    return L"RC4_HMAC_OLD_EXP";
                case KERB_ETYPE_RC4_PLAIN_OLD_EXP:
                    return L"RC4_PLAIN_OLD_EXP";
                case KERB_ETYPE_RC4_PLAIN:
                    return L"RC4_PLAIN";
                case KERB_ETYPE_RC4_PLAIN_EXP:
                    return L"RC4_PLAIN_EXP";
                case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96_PLAIN:
                    return L"AES128_CTS_HMAC_SHA1_96_PLAIN";
                case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96_PLAIN:
                    return L"AES256_CTS_HMAC_SHA1_96_PLAIN";
                case KERB_ETYPE_DSA_SHA1_CMS:
                    return L"DSA_SHA1_CMS";
                case KERB_ETYPE_RSA_MD5_CMS:
                    return L"RSA_MD5_CMS";
                case KERB_ETYPE_RSA_SHA1_CMS:
                    return L"RSA_SHA1_CMS";
                case KERB_ETYPE_RC2_CBC_ENV:
                    return L"RC2_CBC_ENV";
                case KERB_ETYPE_RSA_ENV:
                    return L"RSA_ENV";
                case KERB_ETYPE_RSA_ES_OEAP_ENV:
                    return L"RSA_ES_OEAP_ENV";
                case KERB_ETYPE_DES_EDE3_CBC_ENV:
                    return L"DES_EDE3_CBC_ENV";
                case KERB_ETYPE_DES_CBC_MD5_NT:
                    return L"DES_CBC_MD5_NT";
                case KERB_ETYPE_RC4_HMAC_NT:
                    return L"RC4_HMAC_NT";
                case KERB_ETYPE_RC4_HMAC_NT_EXP:
                    return L"RC4_HMAC_NT_EXP";
                default:
                    return L"<UNKNOWN>";
            }

            return L"";
        };
        #pragma endregion

        auto Cache = XCallAuthenticationPackage<KerbQueryTicketCacheEx3Message>({});

        for(ULONG i = 0; i < Cache->CountOfTickets; i++)
        {
            auto Ticket = Cache->Tickets[i];

            std::wstring ClientName{ Ticket.ClientName.Buffer, Ticket.ClientName.Buffer + Ticket.ClientName.Length / size_wchar };
            std::wstring ClientRealm{ Ticket.ClientRealm.Buffer, Ticket.ClientRealm.Buffer + Ticket.ClientRealm.Length / size_wchar };
            std::wstring ServerName{ Ticket.ServerName.Buffer, Ticket.ServerName.Buffer + Ticket.ServerName.Length / size_wchar };
            std::wstring ServerRealm{ Ticket.ServerRealm.Buffer, Ticket.ServerRealm.Buffer + Ticket.ServerRealm.Length / size_wchar };

            stream << L"#" << i << L">" << L'\t' << L"Client: " << ClientName << L" @ " << ClientRealm << std::endl;
            stream << L'\t' << L"Server: " << ServerName << L" @ " << ServerRealm << std::endl;

            stream << L'\t' << L"KerbTicket Encryption Type: " << EncryptionTypeToString(Ticket.EncryptionType) << std::endl;

            #pragma region Ticket flags
            std::wstringstream TicketFlagsStream;

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_proxiable)
                TicketFlagsStream << L"proxiable ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_forwarded)
                TicketFlagsStream << L"forwarded ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_forwardable)
                TicketFlagsStream << L"forwardable ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_reserved)
                TicketFlagsStream << L"reserved ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_invalid)
                TicketFlagsStream << L"invalid ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_postdated)
                TicketFlagsStream << L"postdated ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_may_postdate)
                TicketFlagsStream << L"may_postdate ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_proxy)
                TicketFlagsStream << L"proxy ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_hw_authent)
                TicketFlagsStream << L"hw_authent ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_pre_authent)
                TicketFlagsStream << L"pre_authent ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_initial)
                TicketFlagsStream << L"initial ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_renewable)
                TicketFlagsStream << L"renewable ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_name_canonicalize)
                TicketFlagsStream << L"name_canonicalize ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_ok_as_delegate)
                TicketFlagsStream << L"ok_as_delegate ";

            if(Ticket.TicketFlags & KERB_TICKET_FLAGS_reserved1)
                TicketFlagsStream << L"reserved1 ";

            stream << L'\t' << L"Ticket Flags 0x" << std::setfill(L'0') << std::hex << Ticket.TicketFlags << std::dec << std::setfill(L' ') << L' ' << TicketFlagsStream.str();
            #pragma endregion

            stream << L'\t' << L"Start Time: " << FileTimeToString((FILETIME*)&Ticket.StartTime) << L" (local)" << std::endl;
            stream << L'\t' << L"End Time: " << FileTimeToString((FILETIME*)&Ticket.EndTime) << L" (local)" << std::endl;
            stream << L'\t' << L"Renew Time: " << FileTimeToString((FILETIME*)&Ticket.RenewTime) << L" (local)" << std::endl;
            stream << L'\t' << L"Session Key Type: " << EncryptionTypeToString(Ticket.SessionKeyType) << std::endl;

            stream << L'\t' << L"Cache Flags: ";
            if(Ticket.CacheFlags > 0)
                stream << L"0x" << std::setfill(L'0') << std::hex << Ticket.CacheFlags << std::dec << std::setfill(L' ') << L" -> PRIMARY" << std::endl;
            else
                stream << Ticket.CacheFlags << std::endl;

            std::wstring KdcCalled{ Ticket.KdcCalled.Buffer, Ticket.KdcCalled.Buffer + Ticket.KdcCalled.Length / size_wchar };

            stream << L'\t' << L"Kdc Called: " << KdcCalled << std::endl;

            stream << std::endl;
        }

        return stream.str();
    }
    //*******************************************************************************************************
}
//***********************************************************************************************************

