#pragma once
//***********************************************************************************************************
#include <Windows.h>
#include <NTSecAPI.h>

#include <memory>
#include <string>
#include <optional>
//***********************************************************************************************************
namespace XKERB
{
	//*******************************************************************************************************
	using _LsaFreeReturnBuffer = decltype([](void* value){ LsaFreeReturnBuffer(value); });
	using _LsaDeregisterLogonProcess = decltype([](void* value){ LsaDeregisterLogonProcess(value); });
	//*******************************************************************************************************
    template<typename T>
    std::unique_ptr<T, _LsaFreeReturnBuffer> XCallAuthenticationPackage(void* request, size_t requestSize, std::string_view package_name = "Kerberos")
    {
        #pragma region Initial variables
        HANDLE LogonHandle;
        ULONG PackageId;

        PVOID Response = nullptr;
        ULONG ResponseSize;

        NTSTATUS Status;
        NTSTATUS SubStatus;

        LSA_STRING PackageName = { (USHORT)package_name.size(), (USHORT)package_name.size(), const_cast<PCHAR>(package_name.data()) };
        #pragma endregion

        #pragma region Call SSP/AP package
        Status = LsaConnectUntrusted(&LogonHandle);
        std::unique_ptr<void, decltype([](void* value){ LsaDeregisterLogonProcess(value); })> handle_guard{ LogonHandle };

        Status = LsaLookupAuthenticationPackage(LogonHandle, &PackageName, &PackageId);
        if(!NT_SUCCESS(Status))
            throw std::exception(status_to_string("LsaLookupAuthenticationPackage", Status).c_str());

        Status = LsaCallAuthenticationPackage(
            LogonHandle,
            PackageId,
            request,
            (ULONG)requestSize,
            &Response,
            &ResponseSize,
            &SubStatus
        );
        if(!NT_SUCCESS(Status))
            throw std::exception(status_to_string("LsaCallAuthenticationPackage", Status).c_str());

        if(!NT_SUCCESS(SubStatus))
            throw std::exception(status_to_string("LsaCallAuthenticationPackage SubStatus", SubStatus).c_str());

        if(!ResponseSize)
            return nullptr;
        #pragma endregion

        return (std::unique_ptr<T, _LsaFreeReturnBuffer>{ reinterpret_cast<T*>(Response) });
    }
    //*******************************************************************************************************
    template<KERB_PROTOCOL_MESSAGE_TYPE> struct kerb_message_t;
    //*******************************************************************************************************
    struct kerb_struct
    {
        raw_ptr request;
        size_t size{};

        void allocate_request()
        {
            request = raw_ptr{ new unsigned char[size]() };
            if(!request)
                throw std::exception("Out of memory");
        }
    };
    //*******************************************************************************************************
    struct QUERY_TKT_CACHE_REQUEST : public kerb_struct
    {
        std::optional<LUID> LogonId{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            size = sizeof(KERB_QUERY_TKT_CACHE_REQUEST);

            allocate_request();

            auto target = reinterpret_cast<PKERB_QUERY_TKT_CACHE_REQUEST>(request.get());

            target->MessageType = type;
            if(LogonId)
                target->LogonId = LogonId.value();
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbQueryTicketCacheMessage>
    {
        using input = QUERY_TKT_CACHE_REQUEST;
        using output = KERB_QUERY_TKT_CACHE_RESPONSE;
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbQueryTicketCacheExMessage>
    {
        using input = QUERY_TKT_CACHE_REQUEST;
        using output = KERB_QUERY_TKT_CACHE_EX_RESPONSE;
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbQueryTicketCacheEx2Message>
    {
        using input = QUERY_TKT_CACHE_REQUEST;
        using output = KERB_QUERY_TKT_CACHE_EX2_RESPONSE;
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbQueryTicketCacheEx3Message>
    {
        using input = QUERY_TKT_CACHE_REQUEST;
        using output = KERB_QUERY_TKT_CACHE_EX3_RESPONSE;
    };
    //*******************************************************************************************************
    struct RETRIEVE_TKT_REQUEST : public kerb_struct
    {
        std::optional<LUID> LogonId{};
        std::optional<std::wstring_view> TargetName{};
        std::optional<ULONG> TicketFlags{};
        std::optional<ULONG> CacheOptions{};
        std::optional<LONG> EncryptionType{};
        std::optional<SecHandle> CredentialsHandle{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            auto TargetNameByteLength = (TargetName) ? TargetName.value().size() * size_wchar : 0;
            size = sizeof(KERB_RETRIEVE_TKT_REQUEST) + TargetNameByteLength;

            allocate_request();

            auto target = reinterpret_cast<PKERB_RETRIEVE_TKT_REQUEST>(request.get());

            target->MessageType = type;
            if(LogonId)
                target->LogonId = LogonId.value();
            if(TicketFlags)
                target->TicketFlags = TicketFlags.value();
            if(CacheOptions)
                target->CacheOptions = CacheOptions.value();
            if(EncryptionType)
                target->EncryptionType = EncryptionType.value();
            if(CredentialsHandle)
            {
                target->CacheOptions |= KERB_RETRIEVE_TICKET_USE_CREDHANDLE;
                target->CredentialsHandle = CredentialsHandle.value();
            }

            if(TargetNameByteLength)
                string_to_unistring(&target->TargetName, (byte*)request.get() + sizeof(KERB_RETRIEVE_TKT_REQUEST), TargetName.value());
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbRetrieveTicketMessage>
    {
        // TargetName does not matter, in all cases will get TGT
        // Unable to use KERB_RETRIEVE_TICKET_USE_CREDHANDLE - always get TGT for current session only
        // Seems that only LogonId parameter does matter, nothing else for this type of message

        using input = RETRIEVE_TKT_REQUEST;
        using output = KERB_RETRIEVE_TKT_RESPONSE;
    };
    //*******************************************************************************************************
    struct PURGE_TKT_CACHE_REQUEST : public kerb_struct
    {
        std::optional<LUID> LogonId{};
        std::optional<std::wstring_view> ServerName{};
        std::optional<std::wstring_view> RealmName{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            auto ServerNameByteLength = (ServerName) ? ServerName.value().size() * size_wchar : 0;
            auto RealmNameByteLength = (RealmName) ? RealmName.value().size() * size_wchar : 0;
            auto BaseSize = sizeof(KERB_PURGE_TKT_CACHE_REQUEST);

            size = BaseSize + ServerNameByteLength + RealmNameByteLength;

            allocate_request();

            auto target = reinterpret_cast<PKERB_PURGE_TKT_CACHE_REQUEST>(request.get());

            target->MessageType = type;
            if(LogonId)
                target->LogonId = LogonId.value();

            auto address = (byte*)request.get() + BaseSize;

            if(ServerNameByteLength)
            {
                string_to_unistring(&target->ServerName, address, ServerName.value());
                address += ServerNameByteLength;
            }

            if(RealmNameByteLength)
                string_to_unistring(&target->RealmName, address, RealmName.value());
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbPurgeTicketCacheMessage>
    {
        using input = PURGE_TKT_CACHE_REQUEST;
        using output = void;
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbRetrieveEncodedTicketMessage>
    {
        // TargetName matters. In case system has no ticket for the name it will request it.
        // In case if TargetName is not set call would fail with error 53.

        using input = RETRIEVE_TKT_REQUEST;
        using output = KERB_RETRIEVE_TKT_RESPONSE;
    };
    //*******************************************************************************************************
    struct SUBMIT_TKT_REQUEST : public kerb_struct
    {
        std::optional<LUID> LogonId{};
        std::optional<ULONG> Flags{};

        std::vector<byte> Ticket{};

        std::optional<std::vector<byte>> Key{};
        std::optional<LONG> KeyType{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            auto BaseSize = sizeof(KERB_SUBMIT_TKT_REQUEST);

            size = BaseSize + Ticket.size();
            if(Key)
                size += Key.value().size();

            allocate_request();

            auto target = reinterpret_cast<PKERB_SUBMIT_TKT_REQUEST>(request.get());

            target->MessageType = type;
            if(LogonId)
                target->LogonId = LogonId.value();
            if(Flags)
                target->Flags = Flags.value();

            auto address = BaseSize;

            if(!Ticket.empty())
            {
                target->KerbCredSize = (ULONG)Ticket.size();
                target->KerbCredOffset = (ULONG)address;

                std::copy(Ticket.begin(), Ticket.end(), (byte*)request.get() + address);

                address += Ticket.size();
            }

            if(Key)
            {
                target->Key.KeyType = KeyType.value_or(0);
                target->Key.Length = (ULONG)Key.value().size();
                target->Key.Offset = (ULONG)address;

                std::copy(Key.value().begin(), Key.value().end(), (byte*)request.get() + address);
            }
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbSubmitTicketMessage>
    {
        using input = SUBMIT_TKT_REQUEST;
        using output = void;
    };
    //*******************************************************************************************************
    struct QUERY_S4U2PROXY_CACHE_REQUEST : public kerb_struct
    {
        std::optional<ULONG> Flags{};
        std::optional<LUID> LogonId{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            size = sizeof(KERB_QUERY_S4U2PROXY_CACHE_REQUEST);

            allocate_request();

            auto target = reinterpret_cast<PKERB_QUERY_S4U2PROXY_CACHE_REQUEST>(request.get());

            target->MessageType = type;
            if(Flags)
                target->Flags = Flags.value();
            if(LogonId)
                target->LogonId = LogonId.value();
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbQueryS4U2ProxyCacheMessage>
    {
        using input = QUERY_S4U2PROXY_CACHE_REQUEST;
        using output = KERB_QUERY_S4U2PROXY_CACHE_RESPONSE;
    };
    //*******************************************************************************************************
    struct CHANGEPASSWORD_REQUEST : public kerb_struct
    {
        // All these are mandatory
        std::wstring DomainName{ L"" };
        PUNICODE_STRING DomainNameUni = nullptr;
        std::wstring AccountName{ L"" };
        PUNICODE_STRING AccountNameUni = nullptr;
        std::wstring OldPassword{ L"" };
        PUNICODE_STRING OldPasswordUni = nullptr;
        std::wstring NewPassword{ L"" };
        PUNICODE_STRING NewPasswordUni = nullptr;

        std::optional<bool> Impersonating{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            auto DomainNameLength = (DomainNameUni == nullptr) ? (DomainName.size() * size_wchar) : DomainNameUni->Length;
            auto AccountNameLength = (AccountNameUni == nullptr) ? (AccountName.size() * size_wchar) : AccountNameUni->Length;
            auto OldPasswordLength = (OldPasswordUni == nullptr) ? (OldPassword.size() * size_wchar) : OldPasswordUni->Length;
            auto NewPasswordLength = (NewPasswordUni == nullptr) ? (NewPassword.size() * size_wchar) : NewPasswordUni->Length;
            auto BaseSize = sizeof(KERB_CHANGEPASSWORD_REQUEST);

            size = BaseSize + DomainNameLength + AccountNameLength + OldPasswordLength + NewPasswordLength;

            allocate_request();

            auto target = reinterpret_cast<PKERB_CHANGEPASSWORD_REQUEST>(request.get());

            target->MessageType = type;

            auto address = (byte*)request.get() + BaseSize;

            if(DomainNameUni == nullptr)
                string_to_unistring(&target->DomainName, address, DomainName);
            else
                copy_unistring(&target->DomainName, address, DomainNameUni);
            address += DomainNameLength;
            if(AccountNameUni == nullptr)
                string_to_unistring(&target->AccountName, address, AccountName);
            else
                copy_unistring(&target->AccountName, address, AccountNameUni);
            address += AccountNameLength;
            if(OldPasswordUni == nullptr)
                string_to_unistring(&target->OldPassword, address, OldPassword);
            else
                copy_unistring(&target->OldPassword, address, OldPasswordUni);
            address += OldPasswordLength;
            if(NewPasswordUni == nullptr)
                string_to_unistring(&target->NewPassword, address, NewPassword);
            else
                copy_unistring(&target->NewPassword, address, NewPasswordUni);

            target->Impersonating = Impersonating.value_or(FALSE);
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbChangePasswordMessage>
    {
        using input = CHANGEPASSWORD_REQUEST;
        using output = void;
    };
    //*******************************************************************************************************
    struct SETPASSWORD_REQUEST : public kerb_struct
    {
        std::optional<LUID> LogonId{};
        std::optional<SecHandle> CredentialsHandle{};
        std::optional<ULONG> Flags{};

        std::wstring DomainName{ L"" };
        std::wstring AccountName{ L"" };
        std::wstring Password{ L"" };

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            auto DomainNameLength = DomainName.size() * size_wchar;
            auto AccountNameLength = AccountName.size() * size_wchar;
            auto PasswordLength = Password.size() * size_wchar;
            auto BaseSize = sizeof(KERB_SETPASSWORD_REQUEST);

            size = BaseSize + DomainNameLength + AccountNameLength + PasswordLength;

            allocate_request();

            auto target = reinterpret_cast<PKERB_SETPASSWORD_REQUEST>(request.get());

            target->MessageType = type;

            if(LogonId)
            {
                target->Flags |= KERB_SETPASS_USE_LOGONID;
                target->LogonId = LogonId.value();
            }
            if(CredentialsHandle)
            {
                target->Flags |= KERB_SETPASS_USE_CREDHANDLE;
                target->CredentialsHandle = CredentialsHandle.value();
            }

            auto address = (byte*)request.get() + BaseSize;

            string_to_unistring(&target->DomainName, address, DomainName);
            address += DomainNameLength;
            string_to_unistring(&target->AccountName, address, AccountName);
            address += AccountNameLength;
            string_to_unistring(&target->Password, address, Password);
        }
    };
    //*******************************************************************************************************
    //
    // The caller must have permission to set the password for the target account (mostly for domain admins).
    // Set domain password without any additional checks.
    //
    template<> struct kerb_message_t<KerbSetPasswordMessage>
    {
        using input = SETPASSWORD_REQUEST;
        using output = void;
    };
    //*******************************************************************************************************
    struct ADD_CREDENTIALS_REQUEST : public kerb_struct
    {
        std::wstring UserName{ L"" };
        std::wstring DomainName{ L"" };
        std::wstring Password{ L"" };

        std::optional<LUID> LogonId{};
        std::optional<ULONG> Flags{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            auto DomainNameLength = DomainName.size() * size_wchar;
            auto UserNameLength = UserName.size() * size_wchar;
            auto PasswordLength = Password.size() * size_wchar;
            auto BaseSize = sizeof(KERB_ADD_CREDENTIALS_REQUEST);

            size = BaseSize + DomainNameLength + UserNameLength + PasswordLength;

            allocate_request();

            auto target = reinterpret_cast<PKERB_ADD_CREDENTIALS_REQUEST>(request.get());

            target->MessageType = type;

            target->Flags = Flags.value_or(1); // KERB_REQUEST_ADD_CREDENTIAL
            if(LogonId)
                target->LogonId = LogonId.value();

            auto address = (byte*)request.get() + BaseSize;

            string_to_unistring(&target->UserName, address, UserName);
            address += UserNameLength;
            string_to_unistring(&target->DomainName, address, DomainName);
            address += DomainNameLength;
            string_to_unistring(&target->Password, address, Password);
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbAddExtraCredentialsMessage>
    {
        using input = ADD_CREDENTIALS_REQUEST;
        using output = void;
    };
    //*******************************************************************************************************
    struct ADD_CREDENTIALS_REQUEST_EX : public kerb_struct
    {
        std::wstring UserName{ L"" };
        std::wstring DomainName{ L"" };
        std::wstring Password{ L"" };

        std::optional<LUID> LogonId{};
        std::optional<ULONG> Flags{};

        std::optional<std::vector<std::wstring>> PrincipalNames{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            auto DomainNameLength = DomainName.size() * size_wchar;
            auto UserNameLength = UserName.size() * size_wchar;
            auto PasswordLength = Password.size() * size_wchar;

            auto BaseSize = sizeof(KERB_ADD_CREDENTIALS_REQUEST_EX);

            if(PrincipalNames)
            {
                auto PrincipalNamesLength = 0ULL;
                BaseSize = FIELD_OFFSET(KERB_ADD_CREDENTIALS_REQUEST_EX, PrincipalNames[PrincipalNames.value().size()]);

                for(auto&& element : PrincipalNames.value())
                    PrincipalNamesLength += (element.size() * size_wchar);

                size = BaseSize + DomainNameLength + UserNameLength + PasswordLength + PrincipalNamesLength;
            }
            else
                size = BaseSize + DomainNameLength + UserNameLength + PasswordLength;

            allocate_request();

            auto target = reinterpret_cast<PKERB_ADD_CREDENTIALS_REQUEST_EX>(request.get());

            target->Credentials.MessageType = type;

            target->Credentials.Flags = Flags.value_or(1); // KERB_REQUEST_ADD_CREDENTIAL
            if(LogonId)
                target->Credentials.LogonId = LogonId.value();

            auto address = (byte*)request.get() + BaseSize;

            string_to_unistring(&target->Credentials.UserName, address, UserName);
            address += UserNameLength;
            string_to_unistring(&target->Credentials.DomainName, address, DomainName);
            address += DomainNameLength;
            string_to_unistring(&target->Credentials.Password, address, Password);
            address += PasswordLength;

            if(PrincipalNames)
            {
                target->PrincipalNameCount = (ULONG)PrincipalNames.value().size();

                auto index = 0UL;

                for(auto&& element : PrincipalNames.value())
                {
                    string_to_unistring(&target->PrincipalNames[index++], address, element);
                    address += (element.size() * size_wchar);
                }
            }
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbAddExtraCredentialsExMessage>
    {
        using input = ADD_CREDENTIALS_REQUEST_EX;
        using output = void;
    };
    //*******************************************************************************************************
    struct RETRIEVE_KEY_TAB_REQUEST : public kerb_struct
    {

        std::wstring User{ L"" };
        std::wstring Password{ L"" };
        std::wstring Domain{ L"" };

        std::optional<ULONG> Flags{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            auto DomainLength = Domain.size() * size_wchar;
            auto UserLength = User.size() * size_wchar;
            auto PasswordLength = Password.size() * size_wchar;
            auto BaseSize = sizeof(KERB_RETRIEVE_KEY_TAB_REQUEST);

            size = BaseSize + DomainLength + UserLength + PasswordLength;

            allocate_request();

            auto target = reinterpret_cast<PKERB_RETRIEVE_KEY_TAB_REQUEST>(request.get());

            target->MessageType = type;
            target->Flags = Flags.value_or(0);

            auto address = (byte*)request.get() + BaseSize;

            string_to_unistring(&target->UserName, address, User);
            address += UserLength;
            string_to_unistring(&target->Password, address, Password);
            address += PasswordLength;
            string_to_unistring(&target->DomainName, address, Domain);
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbRetrieveKeyTabMessage>
    {
        using input = RETRIEVE_KEY_TAB_REQUEST;
        using output = KERB_RETRIEVE_KEY_TAB_RESPONSE;
    };
    //*******************************************************************************************************
    //
    // https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/blob/main/NtApiDotNet/Win32/Security/Native/KERB_PIN_KDC_REQUEST.cs
    //
    typedef struct _KERB_PIN_KDC_REQUEST
    {
        KERB_PROTOCOL_MESSAGE_TYPE  MessageType;
        ULONG                       Flags;
        UNICODE_STRING              Realm;
        UNICODE_STRING              KdcAddress;

        // Info about DcFlags can be found in information for "Flags" parameter for this function:
        // https://learn.microsoft.com/en-us/windows/win32/api/dsgetdc/nf-dsgetdc-dsgetdcnamea
        // Header file for these values: dsgetdc.h

        ULONG                       DcFlags;
    } KERB_PIN_KDC_REQUEST, * PKERB_PIN_KDC_REQUEST;
    //*******************************************************************************************************
    struct PIN_KDC_REQUEST : public kerb_struct
    {
        std::wstring Realm{ L"" };
        std::wstring KdcAddress{ L"" };

        std::optional<ULONG> Flags{};
        std::optional<ULONG> DcFlags{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            auto RealmLength = Realm.size() * size_wchar;
            auto KdcAddressLength = KdcAddress.size() * size_wchar;
            auto BaseSize = sizeof(KERB_PIN_KDC_REQUEST);

            size = BaseSize + RealmLength + KdcAddressLength;

            allocate_request();

            auto target = reinterpret_cast<PKERB_PIN_KDC_REQUEST>(request.get());

            target->MessageType = type;
            target->Flags = Flags.value_or(0);
            target->DcFlags = DcFlags.value_or(0);

            auto address = (byte*)request.get() + BaseSize;

            string_to_unistring(&target->Realm, address, Realm);
            address += RealmLength;
            string_to_unistring(&target->KdcAddress, address, KdcAddress);
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbPinKdcMessage>
    {
        using input = PIN_KDC_REQUEST;
        using output = void;
    };
    //*******************************************************************************************************
    //
    // https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/blob/main/NtApiDotNet/Win32/Security/Native/KERB_UNPIN_ALL_KDCS_REQUEST.cs
    //
    typedef struct _KERB_UNPIN_ALL_KDCS_REQUEST
    {
        KERB_PROTOCOL_MESSAGE_TYPE  MessageType;
        ULONG                       Flags;
    } KERB_UNPIN_ALL_KDCS_REQUEST, * PKERB_UNPIN_ALL_KDCS_REQUEST;
    //*******************************************************************************************************
    struct UNPIN_ALL_KDCS_REQUEST : public kerb_struct
    {
        std::optional<ULONG> Flags{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            size = sizeof(KERB_UNPIN_ALL_KDCS_REQUEST);

            allocate_request();

            auto target = reinterpret_cast<PKERB_UNPIN_ALL_KDCS_REQUEST>(request.get());

            target->MessageType = type;
            target->Flags = Flags.value_or(0);
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbUnpinAllKdcsMessage>
    {
        using input = UNPIN_ALL_KDCS_REQUEST;
        using output = void;
    };
    //*******************************************************************************************************
    struct QUERY_BINDING_CACHE_REQUEST : public kerb_struct
    {
        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            size = sizeof(KERB_QUERY_BINDING_CACHE_REQUEST);

            allocate_request();

            auto target = reinterpret_cast<PKERB_QUERY_BINDING_CACHE_REQUEST>(request.get());

            target->MessageType = type;
        }
    };
    //*******************************************************************************************************
    //
    // Requires TCB priviledge
    //
    template<> struct kerb_message_t<KerbQueryBindingCacheMessage>
    {
        using input = QUERY_BINDING_CACHE_REQUEST;
        using output = KERB_QUERY_BINDING_CACHE_RESPONSE;
    };
    //*******************************************************************************************************
    struct ADD_BINDING_CACHE_ENTRY_EX_REQUEST : public kerb_struct
    {
        std::wstring Realm{};
        std::wstring KdcAddress{};

        std::optional<ULONG> AddressType{};
        std::optional<ULONG> DcFlags{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            auto RealmLength = Realm.size() * size_wchar;
            auto KdcAddressLength = KdcAddress.size() * size_wchar;
            auto BaseSize = sizeof(KERB_ADD_BINDING_CACHE_ENTRY_EX_REQUEST);

            size = BaseSize + RealmLength + KdcAddressLength;

            allocate_request();

            auto target = reinterpret_cast<PKERB_ADD_BINDING_CACHE_ENTRY_EX_REQUEST>(request.get());

            target->MessageType = type;
            target->AddressType = AddressType.value_or(1); // DS_INET_ADDRESS
            target->DcFlags = DcFlags.value_or(0);

            auto address = (byte*)request.get() + BaseSize;

            string_to_unistring(&target->RealmName, address, Realm);
            address += RealmLength;
            string_to_unistring(&target->KdcAddress, address, KdcAddress);
        }
    };
    //*******************************************************************************************************
    //
    // Requires TCB priviledge
    //
    template<> struct kerb_message_t<KerbAddBindingCacheEntryExMessage>
    {
        using input = ADD_BINDING_CACHE_ENTRY_EX_REQUEST;
        using output = void;
    };
    //*******************************************************************************************************
    struct ADD_BINDING_CACHE_ENTRY_REQUEST : public kerb_struct
    {
        std::wstring Realm{};
        std::wstring KdcAddress{};

        std::optional<ULONG> AddressType{};
        std::optional<ULONG> DcFlags{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            auto RealmLength = Realm.size() * size_wchar;
            auto KdcAddressLength = KdcAddress.size() * size_wchar;
            auto BaseSize = sizeof(KERB_ADD_BINDING_CACHE_ENTRY_REQUEST);

            size = BaseSize + RealmLength + KdcAddressLength;

            allocate_request();

            auto target = reinterpret_cast<PKERB_ADD_BINDING_CACHE_ENTRY_REQUEST>(request.get());

            target->MessageType = type;
            target->AddressType = AddressType.value_or(1); // DS_INET_ADDRESS

            auto address = (byte*)request.get() + BaseSize;

            string_to_unistring(&target->RealmName, address, Realm);
            address += RealmLength;
            string_to_unistring(&target->KdcAddress, address, KdcAddress);
        }
    };
    //*******************************************************************************************************
    //
    // Requires TCB priviledge
    //
    template<> struct kerb_message_t<KerbAddBindingCacheEntryMessage>
    {
        using input = ADD_BINDING_CACHE_ENTRY_REQUEST;
        using output = void;
    };
    //*******************************************************************************************************
    struct PURGE_BINDING_CACHE_REQUEST : public kerb_struct
    {
        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            size = sizeof(KERB_PURGE_BINDING_CACHE_REQUEST);

            allocate_request();

            auto target = reinterpret_cast<PKERB_PURGE_BINDING_CACHE_REQUEST>(request.get());

            target->MessageType = type;
        }
    };
    //*******************************************************************************************************
    //
    // Requires TCB priviledge
    //
    template<> struct kerb_message_t<KerbPurgeBindingCacheMessage>
    {
        using input = PURGE_BINDING_CACHE_REQUEST;
        using output = void;
    };
    //*******************************************************************************************************
    struct QUERY_DOMAIN_EXTENDED_POLICIES_REQUEST : public kerb_struct
    {
        std::wstring Domain{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            auto DomainLength = Domain.size() * size_wchar;
            auto BaseSize = sizeof(KERB_QUERY_DOMAIN_EXTENDED_POLICIES_REQUEST);

            size = BaseSize + DomainLength;

            allocate_request();

            auto target = reinterpret_cast<PKERB_QUERY_DOMAIN_EXTENDED_POLICIES_REQUEST>(request.get());

            target->MessageType = type;
            target->Flags = 0; // MUST be 0

            string_to_unistring(&target->DomainName, (byte*)request.get() + BaseSize, Domain);
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbQueryDomainExtendedPoliciesMessage>
    {
        using input = QUERY_DOMAIN_EXTENDED_POLICIES_REQUEST;
        using output = KERB_QUERY_DOMAIN_EXTENDED_POLICIES_RESPONSE;
    };
    //*******************************************************************************************************
    struct QUERY_KDC_PROXY_CACHE_REQUEST : public kerb_struct
    {
        std::optional<LUID> LogonId{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            size = sizeof(KERB_QUERY_KDC_PROXY_CACHE_REQUEST);

            allocate_request();

            auto target = reinterpret_cast<PKERB_QUERY_KDC_PROXY_CACHE_REQUEST>(request.get());

            target->MessageType = type;
            target->Flags = 0; // MUST be 0
            if(LogonId)
                target->LogonId = LogonId.value();
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbQueryKdcProxyCacheMessage>
    {
        using input = QUERY_KDC_PROXY_CACHE_REQUEST;
        using output = KERB_QUERY_KDC_PROXY_CACHE_RESPONSE;
    };
    //*******************************************************************************************************
    struct PURGE_KDC_PROXY_CACHE_REQUEST : public kerb_struct
    {
        std::optional<LUID> LogonId{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            size = sizeof(KERB_PURGE_KDC_PROXY_CACHE_REQUEST);

            allocate_request();

            auto target = reinterpret_cast<PKERB_PURGE_KDC_PROXY_CACHE_REQUEST>(request.get());

            target->MessageType = type;
            target->Flags = 0; // MUST be 0
            if(LogonId)
                target->LogonId = LogonId.value();
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbPurgeKdcProxyCacheMessage>
    {
        using input = PURGE_KDC_PROXY_CACHE_REQUEST;
        using output = KERB_PURGE_KDC_PROXY_CACHE_RESPONSE;
    };
    //*******************************************************************************************************
    struct REFRESH_POLICY_REQUEST : public kerb_struct
    {
        std::optional<ULONG> Flags{};

        void construct(KERB_PROTOCOL_MESSAGE_TYPE type)
        {
            size = sizeof(KERB_REFRESH_POLICY_REQUEST);

            allocate_request();

            auto target = reinterpret_cast<PKERB_REFRESH_POLICY_REQUEST>(request.get());

            target->MessageType = type;

            //#define KERB_REFRESH_POLICY_KERBEROS 0x1
            //#define KERB_REFRESH_POLICY_KDC 0x2
            target->Flags = Flags.value_or(1);
        }
    };
    //*******************************************************************************************************
    template<> struct kerb_message_t<KerbRefreshPolicyMessage>
    {
        using input = REFRESH_POLICY_REQUEST;
        using output = KERB_REFRESH_POLICY_RESPONSE;
    };
    //*******************************************************************************************************
    //
    // https://en.cppreference.com/w/cpp/language/aggregate_initialization
    //
    template<KERB_PROTOCOL_MESSAGE_TYPE type>
    std::unique_ptr<typename kerb_message_t<type>::output, _LsaFreeReturnBuffer> XCallAuthenticationPackage(typename kerb_message_t<type>::input input)
    {
        input.construct(type);
        return XCallAuthenticationPackage<typename kerb_message_t<type>::output>(input.request.get(), input.size, "Kerberos");
    }
    //*******************************************************************************************************
}
//***********************************************************************************************************

