#pragma once
//***********************************************************************************************************
#include <Windows.h>
#include <NTSecAPI.h>

#include <string>
#include <sstream>
#include <memory>
//***********************************************************************************************************
namespace XKERB
{
    //***********************************************************************************************************
    auto size_wchar = sizeof(wchar_t);

    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
    #define SEC_SUCCESS(Status) ((Status) >= 0)

    using raw_ptr = std::unique_ptr<unsigned char[]>;
    //*******************************************************************************************************
    //***********************************************************************************************************
    std::string status_to_string(std::string_view function, NTSTATUS status)
    {
        #pragma region Initial variables
        std::ostringstream stream;
        LPVOID message_buffer = NULL;

        auto error_code = LsaNtStatusToWinError(status);
        #pragma endregion

        stream << function << " error #" << error_code;

        if(!FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error_code,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&message_buffer,
            0,
            NULL
        ))
        {
            stream << std::endl;
            return stream.str();
        }

        std::unique_ptr<void, decltype([](void* value){ LocalFree(value); }) > guard{ message_buffer };

        stream << " (" << (LPSTR)message_buffer << ")" << std::endl;

        return stream.str();
    }
    //***********************************************************************************************************
    std::string secstatus_to_string(std::string_view function, SECURITY_STATUS status)
    {
        if(status >= 0)
            return "";

        std::ostringstream stream;
        stream << function << " error#" << std::hex << " 0x" << status << std::dec << " (";

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
            default:
                stream << "Unknown error";
        }

        stream << ")" << std::endl;

        return stream.str();
    }
    //***********************************************************************************************************
    void string_to_unistring(UNICODE_STRING* unistring, byte* address, std::wstring_view string)
    {
        auto bytesize = string.size() * size_wchar;

        unistring->Buffer = (PWSTR)address;
        unistring->Length = (USHORT)bytesize;
        unistring->MaximumLength = (USHORT)bytesize;

        auto data = (byte*)string.data();

        std::copy(
            data,
            data + bytesize,
            (byte*)unistring->Buffer
        );
    }
    //***********************************************************************************************************
    void copy_unistring(UNICODE_STRING* unistring, byte* address, UNICODE_STRING* source)
    {
        auto bytesize = source->Length;

        unistring->Buffer = (PWSTR)address;
        unistring->Length = source->Length;
        unistring->MaximumLength = source->MaximumLength;

        auto data = (byte*)source->Buffer;

        std::copy(
            data,
            data + bytesize,
            (byte*)unistring->Buffer
        );
    }
    //***********************************************************************************************************
}