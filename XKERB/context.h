#pragma once
//***********************************************************************************************************
#define SECURITY_WIN32
#include <sspi.h>

#include <memory>
#include <functional>

#pragma comment(lib, "Secur32.lib")
//***********************************************************************************************************
namespace XKERB
{
    //***********************************************************************************************************
    struct XSecurityContext
    {
        CtxtHandle ContextHandle = { 0 };

        ULONG ContextAttributes = 0;
        TimeStamp Lifetime = { 0 };

        SecBuffer OutputBuffer{ .cbBuffer = 0, .BufferType = SECBUFFER_TOKEN, .pvBuffer = nullptr };
        SecBufferDesc Output{ .ulVersion = 0, .cBuffers = 1, .pBuffers = &OutputBuffer };

        XSecurityContext() = default;
        virtual ~XSecurityContext();

        virtual SECURITY_STATUS Process(SecBufferDesc*) = 0;
        bool HasData();

    protected:
        PCredHandle CredentialsHandle = nullptr;
        ULONG Flags = 0;

        bool Continue = false;
    };
    //***********************************************************************************************************
    XSecurityContext::~XSecurityContext()
    {
        if(Continue)
        {
            if(OutputBuffer.pvBuffer != nullptr)
                FreeContextBuffer(OutputBuffer.pvBuffer);

            DeleteSecurityContext(&ContextHandle);
        }
    }
    //***********************************************************************************************************
    bool XSecurityContext::HasData()
    {
        return (OutputBuffer.cbBuffer > 0);
    }
    //***********************************************************************************************************
    struct XClientSecurityContext : public XSecurityContext
    {
        XClientSecurityContext() = delete;
        XClientSecurityContext(PCredHandle, ULONG, std::wstring_view);
        SECURITY_STATUS Process(SecBufferDesc*);

    private:
        std::wstring_view TargetName;
    };
    //***********************************************************************************************************
    XClientSecurityContext::XClientSecurityContext(PCredHandle credentialsHandle, ULONG flags, std::wstring_view targetName)
    {
        CredentialsHandle = credentialsHandle;
        Flags = flags | ISC_REQ_ALLOCATE_MEMORY;
        TargetName = targetName;
    }
    //***********************************************************************************************************
    SECURITY_STATUS XClientSecurityContext::Process(SecBufferDesc* input)
    {
        if(OutputBuffer.pvBuffer != nullptr)
        {
            FreeContextBuffer(OutputBuffer.pvBuffer);

            OutputBuffer.cbBuffer = 0;
            OutputBuffer.pvBuffer = nullptr;
        }

        auto result = InitializeSecurityContextW(
            CredentialsHandle,
            Continue ? &ContextHandle : nullptr,
            (SEC_WCHAR*)TargetName.data(),
            Flags,
            0,
            SECURITY_NATIVE_DREP,
            Continue ? input : nullptr,
            0,
            &ContextHandle,
            &Output,
            &ContextAttributes,
            &Lifetime
        );

        Continue = true;

        return result;
    }
    //***********************************************************************************************************
    struct XServerSecurityContext : public XSecurityContext
    {
        XServerSecurityContext() = delete;
        XServerSecurityContext(PCredHandle, ULONG);
        SECURITY_STATUS Process(SecBufferDesc*);
        auto Impersonate();
    };
    //***********************************************************************************************************
    XServerSecurityContext::XServerSecurityContext(PCredHandle credentialsHandle, ULONG flags)
    {
        CredentialsHandle = credentialsHandle;
        Flags = flags | ASC_REQ_ALLOCATE_MEMORY;
    }
    //***********************************************************************************************************
    SECURITY_STATUS XServerSecurityContext::Process(SecBufferDesc* input)
    {
        if(OutputBuffer.pvBuffer != nullptr)
        {
            FreeContextBuffer(OutputBuffer.pvBuffer);

            OutputBuffer.cbBuffer = 0;
            OutputBuffer.pvBuffer = nullptr;
        }

        auto result = AcceptSecurityContext(
            CredentialsHandle,
            Continue ? &ContextHandle : nullptr,
            input,
            Flags,
            SECURITY_NATIVE_DREP,
            &ContextHandle,
            &Output,
            &ContextAttributes,
            &Lifetime
        );

        Continue = true;

        return result;
    }
    //***********************************************************************************************************
    auto XServerSecurityContext::Impersonate()
    {
        if(ImpersonateSecurityContext(&ContextHandle) != SEC_E_OK)
            throw std::exception("Cannot perform ImpersonateSecurityContext");

        std::unique_ptr<char, std::function<void(char*)>> result{ new char, [this](char* value){ delete value;  RevertSecurityContext(&ContextHandle); } };
        if(!result)
            throw std::exception("Out of memory");

        return result;
    }
    //***********************************************************************************************************
}