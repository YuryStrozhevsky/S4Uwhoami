/*

XSEC library

Copyright (c) 2021 Yury Strozhevsky <yury@strozhevsky.com>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

*/

#pragma once
//********************************************************************************************
namespace XSEC
{
	//****************************************************************************************
	#pragma region Additional structures necessary for Token processing
	//****************************************************************************************
	typedef struct _LSA_UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING;

	typedef LSA_UNICODE_STRING UNICODE_STRING, * PUNICODE_STRING;
	//********************************************************************************************
	typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
	{
		DWORD64 Version;
		UNICODE_STRING Name;
	} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;
	//****************************************************************************************
	typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
	{
		UNICODE_STRING Name;
		WORD ValueType;
		WORD Reserved;
		DWORD Flags;
		DWORD ValueCount;
		union
		{
			PLONG64 pInt64;
			PDWORD64 pUint64;
			PUNICODE_STRING ppString;
			PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
			PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
		} Values;
	} TOKEN_SECURITY_ATTRIBUTE_V1, * PTOKEN_SECURITY_ATTRIBUTE_V1;
	//****************************************************************************************
	typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
	{
		WORD Version;
		WORD Reserved;
		DWORD AttributeCount;
		union
		{
			PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
		} Attribute;
	} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, * PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;
	//****************************************************************************************
	typedef enum _TOKEN_SECURITY_ATTRIBUTE_OPERATION
	{
		SaOperationNone = 0,
		SaOperationReplaceAll,
		SaOperationAdd,
		SaOperationDelete,
		SaOperationReplace
	} TOKEN_SECURITY_ATTRIBUTE_OPERATION, * PTOKEN_SECURITY_ATTRIBUTE_OPERATION;
	//****************************************************************************************
	typedef struct _TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION
	{
		TOKEN_SECURITY_ATTRIBUTES_INFORMATION* Attributes;
		TOKEN_SECURITY_ATTRIBUTE_OPERATION* Operations;
	} TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION, * PTOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION;
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with SID_AND_ATTRIBUTES structure
	//****************************************************************************************
	struct XSID_AND_ATTRIBUTES
	{
		XSID_AND_ATTRIBUTES() = delete;
		~XSID_AND_ATTRIBUTES() = default;

		XSID_AND_ATTRIBUTES(const XSID_AND_ATTRIBUTES& copy) : Sid(copy.Sid), Attributes(copy.Attributes), Meaning(copy.Meaning) {}

		XSID_AND_ATTRIBUTES(const XSID&, const XBITSET<32> & = { SidAndAttributesMeaningDefault, { L"SE_GROUP_ENABLED" } });

		XSID_AND_ATTRIBUTES(const SID_AND_ATTRIBUTES&, const dword_meaning_t& = SidAndAttributesMeaningDefault);
		XSID_AND_ATTRIBUTES(const msxml_et&, const dword_meaning_t& = SidAndAttributesMeaningDefault);

		explicit operator xml_t() const;
		explicit operator SID_AND_ATTRIBUTES() const;

		std::shared_ptr<XSID> Sid;
		std::shared_ptr<XBITSET<32>> Attributes;

		dword_meaning_t Meaning;

		private:
		std::unique_ptr<bin_t> sid = std::make_unique<bin_t>();
	};
	//****************************************************************************************
	XSID_AND_ATTRIBUTES::XSID_AND_ATTRIBUTES(const XSID& _sid, const XBITSET<32>& _attributes)
	{
		Sid = std::make_shared<XSID>(_sid);
		Attributes = std::make_shared<XBITSET<32>>(_attributes);
		Meaning = _attributes.Meaning;
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES::XSID_AND_ATTRIBUTES(const SID_AND_ATTRIBUTES& data, const dword_meaning_t& meaning) : Meaning(meaning)
	{
		#pragma region Sid
		Sid = std::make_shared<XSID>((BYTE*)data.Sid);
		#pragma endregion

		#pragma region Attributes
		Attributes = std::make_shared<XBITSET<32>>((BYTE*)&(data.Attributes), Meaning);
		#pragma endregion
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES::XSID_AND_ATTRIBUTES(const msxml_et& xml, const dword_meaning_t& meaning) : Meaning(meaning)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("SID_AND_ATTRIBUTES: invalid input XML");
		#pragma endregion

		#pragma region Sid
		msxml_et _sid = xml->selectSingleNode(L"SID");
		if(nullptr == _sid)
			throw std::exception("SID_AND_ATTRIBUTES: cannot find 'SID' XML node");

		Sid = std::make_shared<XSID>(_sid);
		#pragma endregion

		#pragma region Attributes
		msxml_et attributes = xml->selectSingleNode(L"Attributes");
		if(nullptr == attributes)
			throw std::exception("SID_AND_ATTRIBUTES: cannot find 'Attributes' XML node");

		Attributes = std::make_shared<XBITSET<32>>(attributes, Meaning);
		#pragma endregion
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("SID_AND_ATTRIBUTES: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et saa = xml->createElement(std::wstring(root.value_or(L"SID_AND_ATTRIBUTES")).c_str());
			if(nullptr == saa)
				throw std::exception("SID_AND_ATTRIBUTES: cannot create root XML node");
			#pragma endregion

			#pragma region Sid
			if(nullptr == Sid)
				throw std::exception("SID_AND_ATTRIBUTES: initialize data first");

			saa->appendChild(((xml_t)*Sid)(xml, std::nullopt));
			#pragma endregion

			#pragma region Attributes
			if(nullptr == Attributes)
				throw std::exception("SID_AND_ATTRIBUTES: initialize data first");

			saa->appendChild(((xml_t)*Attributes)(xml, L"Attributes"));
			#pragma endregion

			return saa;
		};
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES::operator SID_AND_ATTRIBUTES() const
	{
		if((nullptr == Sid) || (nullptr == Attributes))
			throw std::exception("SID_AND_ATTRIBUTES: initialize data first");

		SID_AND_ATTRIBUTES result{};

		*sid = (bin_t)*Sid;

		result.Sid = (PSID)sid->data();
		result.Attributes = dword_vec((bin_t)*Attributes);

		return result;
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with SID_AND_ATTRIBUTES_HASH structure
	//****************************************************************************************
	struct XSID_AND_ATTRIBUTES_HASH
	{
		XSID_AND_ATTRIBUTES_HASH() = delete;
		~XSID_AND_ATTRIBUTES_HASH() = default;

		XSID_AND_ATTRIBUTES_HASH(const std::vector<XSID_AND_ATTRIBUTES>&, const std::vector<bin_t>&);

		XSID_AND_ATTRIBUTES_HASH(const SID_AND_ATTRIBUTES_HASH&, const dword_meaning_t& = SidAndAttributesMeaningDefault);
		XSID_AND_ATTRIBUTES_HASH(const msxml_et&, const dword_meaning_t& = SidAndAttributesMeaningDefault);

		explicit operator xml_t() const;

		std::vector<XSID_AND_ATTRIBUTES> Attributes;
		std::vector<bin_t> Hashes;

		dword_meaning_t Meaning;
	};
	//****************************************************************************************
	XSID_AND_ATTRIBUTES_HASH::XSID_AND_ATTRIBUTES_HASH(const std::vector<XSID_AND_ATTRIBUTES>& attributes, const std::vector<bin_t>& hashes) : Attributes(attributes), Hashes(hashes)
	{
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES_HASH::XSID_AND_ATTRIBUTES_HASH(const SID_AND_ATTRIBUTES_HASH& data, const dword_meaning_t& meaning) : Meaning(meaning)
	{
		for(DWORD i = 0; i < data.SidCount; i++)
		{
			Attributes.push_back(XSID_AND_ATTRIBUTES(data.SidAttr[i], meaning));

			//// Documentation says it is "An array of pointers to hash values", but it is not.
			//// Untill I found a way how to deal with the value I comment it
			//unsigned char* pointer = (unsigned char*)data.Hash[i];

			//Hashes.push_back(bin_t{ pointer, pointer + SID_HASH_SIZE });
		}
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES_HASH::XSID_AND_ATTRIBUTES_HASH(const msxml_et& xml, const dword_meaning_t& meaning) : Meaning(meaning)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("SID_AND_ATTRIBUTES_HASH: invalid input XML");
		#pragma endregion

		#pragma region SidAttr
		Attributes.clear();

		msxml_nt sidAttrs = xml->selectNodes(L"Attribute");
		if(nullptr == sidAttrs)
			throw std::exception("SID_AND_ATTRIBUTES_HASH: cannot find 'SidAttrs' XML node");

		for(long i = 0; i < sidAttrs->length; i++)
			Attributes.push_back(XSID_AND_ATTRIBUTES(sidAttrs->item[i], meaning));
		#pragma endregion

		#pragma region Hash
		msxml_nt hashes = xml->selectNodes(L"Hash");
		if(nullptr == hashes)
			throw std::exception("SID_AND_ATTRIBUTES_HASH: cannot find 'Hash' XML node");

		for(long i = 0; i < hashes->length; i++)
			Hashes.push_back(from_hex_codes((wchar_t*)hashes->item[i]->text));
		#pragma endregion
	}
	//****************************************************************************************
	XSID_AND_ATTRIBUTES_HASH::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("SID_AND_ATTRIBUTES_HASH: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et saa = xml->createElement(std::wstring(root.value_or(L"SID_AND_ATTRIBUTES_HASH")).c_str());
			if(nullptr == saa)
				throw std::exception("SID_AND_ATTRIBUTES_HASH: cannot create root XML");
			#pragma endregion

			#pragma region Attributes
			for(auto&& element : Attributes)
				saa->appendChild(((xml_t)element)(xml, L"Attribute"));
			#pragma endregion

			#pragma region Hash
			for(auto&& element : Hashes)
			{
				msxml_et hash = xml->createElement(L"Hash");
				if(nullptr == hash)
					throw std::exception("SID_AND_ATTRIBUTES_HASH: cannot create 'Hash' XML node");

				hash->appendChild(xml->createTextNode(whex_codes(element).c_str()));

				saa->appendChild(hash);
			}
			#pragma endregion

			return saa;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with LUID structure
	//****************************************************************************************
	struct XLUID
	{
		XLUID() = delete;
		~XLUID() = default;

		XLUID(const DWORD&, const LONG&);

		XLUID(const LUID);
		XLUID(const std::wstring);
		XLUID(const msxml_et&);

		bool operator==(XLUID) const;

		explicit operator xml_t() const;
		operator LUID() const;

		std::pair<std::wstring, std::wstring> privilegeNames() const;

		DWORD LowPart = 0;
		LONG HighPart = 0;

		#pragma region Static declaratiosn for wel-known LUIDs
		static const XLUID System;
		static const XLUID Anonymous;
		static const XLUID LocalService;
		static const XLUID NetworkService;
		static const XLUID IUser;
		static const XLUID ProtectedToSystem;
		#pragma endregion
	};
	//****************************************************************************************
	const XLUID XLUID::System = { 0x3e7, 0 };
	const XLUID XLUID::Anonymous = { 0x3e6, 0 };
	const XLUID XLUID::LocalService = { 0x3e5, 0 };
	const XLUID XLUID::NetworkService = { 0x3e4, 0 };
	const XLUID XLUID::IUser = { 0x3e3, 0 };
	const XLUID XLUID::ProtectedToSystem = { 0x3e2, 0 };
	//****************************************************************************************
	XLUID::XLUID(const DWORD& low, const LONG& high) : LowPart(low), HighPart(high)
	{
	}
	//****************************************************************************************
	XLUID::XLUID(const LUID luid) : LowPart(luid.LowPart), HighPart(luid.HighPart)
	{
	}
	//****************************************************************************************
	XLUID::XLUID(const std::wstring name)
	{
		LUID luid;

		if(!LookupPrivilegeValueW(nullptr, name.c_str(), &luid))
			throw std::exception("LUID: Cannot find correct LUID for name");

		LowPart = luid.LowPart;
		HighPart = luid.HighPart;
	}
	//****************************************************************************************
	XLUID::XLUID(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("LUID: invalid input XML");
		#pragma endregion

		#pragma region Luid
		msxml_et highPart = xml->selectSingleNode(L"HighPart");
		if(nullptr == highPart)
			throw std::exception("LUID: cannot find 'HighPart' XML node");

		HighPart = dword_vec(from_hex_codes((wchar_t*)highPart->text));

		msxml_et lowPart = xml->selectSingleNode(L"LowPart");
		if(nullptr == lowPart)
			throw std::exception("LUID: cannot find 'LowPart' XML node");

		LowPart = dword_vec(from_hex_codes((wchar_t*)lowPart->text));
		#pragma endregion
	}
	//****************************************************************************************
	bool XLUID::operator ==(XLUID luid) const
	{
		return ((HighPart == luid.HighPart) && (LowPart == luid.LowPart));
	}
	//****************************************************************************************
	XLUID::operator LUID() const
	{
		LUID result = {};

		result.HighPart = HighPart;
		result.LowPart = LowPart;

		return result;
	}
	//****************************************************************************************
	XLUID::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("LUID: invalid input XML");
			#pragma endregion

			#pragma region Initialize common LUID structure
			LUID luid{};

			luid.HighPart = HighPart;
			luid.LowPart = LowPart;
			#pragma endregion

			#pragma region Root element
			msxml_et luidXML = xml->createElement(std::wstring(root.value_or(L"LUID")).c_str());
			if(nullptr == luidXML)
				throw std::exception("LUID: cannot create root XML node");

			#pragma region Trying to get additional information specific for privileges
			auto privilegeNames = this->privilegeNames();
			if(!privilegeNames.first.empty())
			{
				msxml_at privilegeName = xml->createAttribute(L"PrivilegeName");

				privilegeName->value = privilegeNames.first.c_str();
				luidXML->setAttributeNode(privilegeName);

				if(!privilegeNames.second.empty())
				{
					msxml_at privilegeDisplayName = xml->createAttribute(L"PrivilegeDisplayName");

					privilegeDisplayName->value = privilegeNames.second.c_str();
					luidXML->setAttributeNode(privilegeDisplayName);
				}
			}
			#pragma endregion
			#pragma endregion

			#pragma region Luid
			#pragma region LUID high part
			msxml_et highPart = xml->createElement(L"HighPart");
			if(nullptr == highPart)
				throw std::exception("LUID: cannot create 'HighPart' XML node");

			highPart->appendChild(xml->createTextNode(hex_codes(vec_dword(HighPart)).c_str()));

			luidXML->appendChild(highPart);
			#pragma endregion

			#pragma region LUID low part
			msxml_et lowPart = xml->createElement(L"LowPart");
			if(nullptr == lowPart)
				throw std::exception("LUID: cannot create 'LowPart' XML node");

			lowPart->appendChild(xml->createTextNode(hex_codes(vec_dword(LowPart)).c_str()));

			luidXML->appendChild(lowPart);
			#pragma endregion
			#pragma endregion

			return luidXML;
		};
	}
	//****************************************************************************************
	std::pair<std::wstring, std::wstring> XLUID::privilegeNames() const
	{
		#pragma region Initialize common LUID structure
		LUID luid{};

		luid.HighPart = HighPart;
		luid.LowPart = LowPart;
		#pragma endregion

		DWORD privilegeNameSize = 0;

		if(!LookupPrivilegeNameW(nullptr, &luid, nullptr, &privilegeNameSize))
		{
			// Sometimes the "LookupPrivilegeName" could have "access denied" for specific thread tokens
			// In order to lookup name of privileges on current system token need to have rights
			if(GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				std::wstring privilegeNameStr;
				privilegeNameStr.resize(privilegeNameSize - 1);

				if(LookupPrivilegeNameW(nullptr, &luid, privilegeNameStr.data(), &privilegeNameSize))
				{
					DWORD privilegeDisplayNameSize = 0;
					DWORD language = 0;

					if(!LookupPrivilegeDisplayNameW(nullptr, privilegeNameStr.data(), nullptr, &privilegeDisplayNameSize, &language))
					{
						if(GetLastError() == ERROR_INSUFFICIENT_BUFFER)
						{
							std::wstring privilegeDisplayNameStr;
							privilegeDisplayNameStr.resize(privilegeDisplayNameSize - 1);

							if(LookupPrivilegeDisplayNameW(nullptr, privilegeNameStr.data(), privilegeDisplayNameStr.data(), &privilegeDisplayNameSize, &language))
								return std::make_pair<std::wstring, std::wstring>(std::move(privilegeNameStr), std::move(privilegeDisplayNameStr));
						}
					}

					return std::make_pair<std::wstring, std::wstring>(std::move(privilegeNameStr), L"");
				}
			}
		}

		return std::make_pair<std::wstring, std::wstring>(L"", L"");
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with LUID_AND_ATTRIBUTES structure
	//****************************************************************************************
	struct XLUID_AND_ATTRIBUTES
	{
		XLUID_AND_ATTRIBUTES() = delete;
		~XLUID_AND_ATTRIBUTES() = default;

		XLUID_AND_ATTRIBUTES(const XLUID&, const XBITSET<32> & = { DwordMeaningPrivilege , { L"SE_PRIVILEGE_ENABLED" } });
		XLUID_AND_ATTRIBUTES(const std::wstring&, const XBITSET<32>& = { DwordMeaningPrivilege , { L"SE_PRIVILEGE_ENABLED" } });

		XLUID_AND_ATTRIBUTES(const LUID_AND_ATTRIBUTES&, const dword_meaning_t& = DwordMeaningPrivilege);
		XLUID_AND_ATTRIBUTES(const msxml_et&, const dword_meaning_t & = DwordMeaningPrivilege);

		operator LUID_AND_ATTRIBUTES() const;
		operator xml_t() const;

		std::shared_ptr<XLUID> Luid;
		std::shared_ptr<XBITSET<32>> Attributes;
	};
	//****************************************************************************************
	XLUID_AND_ATTRIBUTES::XLUID_AND_ATTRIBUTES(const XLUID& luid, const  XBITSET<32>& attributes)
	{
		Luid = std::make_shared<XLUID>(luid);
		Attributes = std::make_shared<XBITSET<32>>(attributes);
	}
	//****************************************************************************************
	XLUID_AND_ATTRIBUTES::XLUID_AND_ATTRIBUTES(const std::wstring& privilege, const XBITSET<32>& attributes)
	{
		LUID luid;
		if(!LookupPrivilegeValueW(NULL, privilege.c_str(), &luid))
			throw std::exception("XLUID_AND_ATTRIBUTES: cannot find privilege LUID by name");

		Luid = std::make_shared<XLUID>(luid);
		Attributes = std::make_shared<XBITSET<32>>(attributes);
	}
	//****************************************************************************************
	XLUID_AND_ATTRIBUTES::XLUID_AND_ATTRIBUTES(const LUID_AND_ATTRIBUTES& luid_attrs, const dword_meaning_t& meaning)
	{
		Luid = std::make_shared<XLUID>(luid_attrs.Luid);
		Attributes = std::make_shared<XBITSET<32>>(luid_attrs.Attributes, meaning);
	}
	//****************************************************************************************
	XLUID_AND_ATTRIBUTES::XLUID_AND_ATTRIBUTES(const msxml_et& xml, const dword_meaning_t& meaning)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("LUID_AND_ATTRIBUTES: invalid input XML");
		#pragma endregion

		#pragma region Luid
		msxml_et luid = xml->selectSingleNode(L"LUID");
		if(nullptr == luid)
			throw std::exception("LUID_AND_ATTRIBUTES: cannot find 'LUID' XML node");

		Luid = std::make_shared<XLUID>(luid);
		#pragma endregion

		#pragma region Attributes
		msxml_et attributes = xml->selectSingleNode(L"Attributes");
		if(nullptr == attributes)
			throw std::exception("LUID_AND_ATTRIBUTES: cannot find 'Attributes' XML node");

		Attributes = std::make_shared<XBITSET<32>>(attributes, meaning);;
		#pragma endregion
	}
	//****************************************************************************************
	XLUID_AND_ATTRIBUTES::operator LUID_AND_ATTRIBUTES() const
	{
		if((nullptr == Luid) || (nullptr == Attributes))
			throw std::exception("LUID_AND_ATTRIBUTES: initialize data first");

		LUID_AND_ATTRIBUTES result{};

		result.Luid.HighPart = Luid->HighPart;
		result.Luid.LowPart = Luid->LowPart;

		result.Attributes = dword_vec((bin_t)*Attributes);

		return result;
	}
	//****************************************************************************************
	XLUID_AND_ATTRIBUTES::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("LUID_AND_ATTRIBUTES: invalid input XML");
			#pragma endregion

			#pragma region Root element
			msxml_et laa = xml->createElement(std::wstring(root.value_or(L"LUID_AND_ATTRIBUTES")).c_str());
			if(nullptr == laa)
				throw std::exception("LUID_AND_ATTRIBUTES: cannot create root XML node");
			#pragma endregion

			#pragma region Luid
			if(nullptr == Luid)
				throw std::exception("LUID_AND_ATTRIBUTES: initialize data first");

			laa->appendChild(((xml_t)*Luid)(xml, L"LUID"));
			#pragma endregion

			#pragma region Attributes
			if(nullptr == Attributes)
				throw std::exception("LUID_AND_ATTRIBUTES: initialize data first");

			laa->appendChild(((xml_t)*Attributes)(xml, L"Attributes"));
			#pragma endregion

			return laa;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class for working with GUID
	//****************************************************************************************
	std::map<std::wstring, std::wstring> WellKnownGUIDs = { 
		{ L"3E0ABFD0-126A-11D0-A060-00AA006C33ED", L"sAMAccountName" },
		{ L"3F78C3E5-F79A-46BD-A0B8-9D18116DDC79", L"msDS-AllowedToActOnBehalfOfOtherIdentity" },
		{ L"46A9B11D-60AE-405A-B7E8-FF8A58D456D2", L"tokenGroupsGlobalAndUniversal" },
		{ L"4828CC14-1437-45BC-9B07-AD6F015E5F28", L"inetOrgPerson" },
		{ L"5B47D60F-6090-40B2-9F37-2A4DE88F3063", L"msDS-KeyCredentialLink" },
		{ L"6DB69A1C-9422-11D1-AEBD-0000F80367C1", L"terminalServer" },
		{ L"B7C69E6D-2CC7-11D2-854E-00A0C983F608", L"tokenGroups" },
		{ L"BF967950-0DE6-11D0-A285-00AA003049E2", L"description" },
		{ L"BF967953-0DE6-11D0-A285-00AA003049E2", L"displayName" },
		{ L"BF967A7F-0DE6-11D0-A285-00AA003049E2", L"User Certificate" },
		{ L"BF967A86-0DE6-11D0-A285-00AA003049E2", L"computer" },
		{ L"BF967A9C-0DE6-11D0-A285-00AA003049E2", L"group" },
		{ L"BF967AA8-0DE6-11D0-A285-00AA003049E2", L"printQueue" },
		{ L"BF967ABA-0DE6-11D0-A285-00AA003049E2", L"user" },
		{ L"CE206244-5827-4A86-BA1C-1C0C386C1B64", L"Managed Service Account" },
		{ L"EA1B7B93-5E48-46D5-BC6C-4DF4FDA78A35", L"msTPM-TpmInformationForComputer" },

		// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
		{ L"EE914B82-0A98-11D1-ADBB-00C04FD8D5CD" , L"Abandon-Replication" },

		// https://github.com/canix1/SDDL-Converter/blob/master/SDDL-Converter.ps1
		{ L"BF967ABB-0DE6-11D0-A285-00AA003049E2" , L"volume" },
		{ L"F30E3BBE-9FF0-11D1-B603-0000F80367C1" , L"gPLink" },
		{ L"F30E3BBF-9FF0-11D1-B603-0000F80367C1" , L"gPOptions" },
		{ L"5CB41ED0-0E4C-11D0-A286-00AA003049E2" , L"contact" },
		{ L"BF967AA5-0DE6-11D0-A285-00AA003049E2" , L"organizationalUnit" },
		{ L"BF967A0A-0DE6-11D0-A285-00AA003049E2" , L"pwdLastSet" }, 

		// https://www.vinytech.com/setting-acls-on-ou-in-ad/
		{ L"00000000-0000-0000-0000-000000000000", L"All" },
		{ L"BF96793F-0DE6-11D0-A285-00AA003049E2", L"CN" },
		{ L"5CB41ED0-0E4C-11D0-A286-00AA003049E2", L"Contact" },
		{ L"BF9679E4-0DE6-11D0-A285-00AA003049E2", L"distinguishedName" },
		{ L"F30E3BBE-9FF0-11D1-B603-0000F80367C1", L"gPLink" },
		{ L"7B8B558A-93A5-4AF7-ADCA-C017E67F1057", L"Group Managed Service Account" },
		{ L"BF967A0E-0DE6-11D0-A285-00AA003049E2", L"name" },
		{ L"BF967AA5-0DE6-11D0-A285-00AA003049E2", L"Organizational Unit" },
		{ L"BF967A6D-0DE6-11D0-A285-00AA003049E2", L"userParameters" },

		// C:\Windows\System32\schema.ini (on domain controller)
		{ L"AB721A52-1E2F-11D0-9819-00AA0040529B", L"Domain Administer Server" },
		{ L"AB721A53-1E2F-11D0-9819-00AA0040529B", L"Change Password" },
		{ L"00299570-246D-11D0-A768-00AA006E0529", L"Reset Password" },
		{ L"AB721A54-1E2F-11D0-9819-00AA0040529B", L"Send As" },
		{ L"AB721A56-1E2F-11D0-9819-00AA0040529B", L"Receive As" },
		{ L"AB721A55-1E2F-11D0-9819-00AA0040529B", L"Send To" },
		{ L"C7407360-20BF-11D0-A768-00AA006E0529", L"Domain Password & Lockout Policies" },
		{ L"59BA2F42-79A2-11D0-9020-00C04FC2D3CF", L"General Information" },
		{ L"4C164200-20C0-11D0-A768-00AA006E0529", L"Account Restrictions" },
		{ L"5F202010-79A5-11D0-9020-00C04FC2D4CF", L"Logon Information" },
		{ L"BC0AC240-79A9-11D0-9020-00C04FC2D4CF", L"Group Membership" },
		{ L"A1990816-4298-11D1-ADE2-00C04FD8D5CD", L"Open Address List" },
		{ L"E45795B2-9455-11D1-AEBD-0000F80367C1", L"Phone and Mail Options" },
		{ L"77B5B886-944A-11D1-AEBD-0000F80367C1", L"Personal Information" },
		{ L"E45795B3-9455-11D1-AEBD-0000F80367C1", L"Web Information" },
		{ L"1131F6AA-9C07-11D1-F79F-00C04FC2DCD2", L"Replicating Directory Changes" },
		{ L"1131F6AB-9C07-11D1-F79F-00C04FC2DCD2", L"Replication Synchronization" },
		{ L"1131F6AC-9C07-11D1-F79F-00C04FC2DCD2", L"Manage Replication Topology" },
		{ L"E12B56B6-0A95-11D1-ADBB-00C04FD8D5CD", L"Change Schema Master" },
		{ L"D58D5F36-0A98-11D1-ADBB-00C04FD8D5CD", L"Change Rid Master" },
		{ L"FEC364E0-0A98-11D1-ADBB-00C04FD8D5CD", L"Do Garbage Collection" },
		{ L"0BC1554E-0A99-11D1-ADBB-00C04FD8D5CD", L"Recalculate Hierarchy" },
		{ L"1ABD7CF8-0A99-11D1-ADBB-00C04FD8D5CD", L"Allocate Rids" },
		{ L"BAE50096-4752-11D1-9052-00C04FC2D4CF", L"Change PDC" },
		{ L"440820AD-65B4-11D1-A3DA-0000F875AE0D", L"Add GUID" },
		{ L"014BF69C-7B3B-11D1-85F6-08002BE74FAB", L"Change Domain Master" },
		{ L"E48D0154-BCF8-11D1-8702-00C04FB96050", L"Public Information" },
		{ L"4B6E08C0-DF3C-11D1-9C86-006008764D0E", L"Receive Dead Letter" },
		{ L"4B6E08C1-DF3C-11D1-9C86-006008764D0E", L"Peek Dead Letter" },
		{ L"4B6E08C2-DF3C-11D1-9C86-006008764D0E", L"Receive Computer Journal" },
		{ L"4B6E08C3-DF3C-11D1-9C86-006008764D0E", L"Peek Computer Journal" },
		{ L"06BD3200-DF3E-11D1-9C86-006008764D0E", L"Receive Message" },
		{ L"06BD3201-DF3E-11D1-9C86-006008764D0E", L"Peek Message" },
		{ L"06BD3202-DF3E-11D1-9C86-006008764D0E", L"Send Message" },
		{ L"06BD3203-DF3E-11D1-9C86-006008764D0E", L"Receive Journal" },
		{ L"B4E60130-DF3F-11D1-9C86-006008764D0E", L"Open Connector Queue" },
		{ L"EDACFD8F-FFB3-11D1-B41D-00A0C968F939", L"Apply Group Policy" },
		{ L"037088F8-0AE1-11D2-B422-00A0C968F939", L"Remote Access Information" },
		{ L"9923A32A-3607-11D2-B9BE-0000F87A36B2", L"Add/Remove Replica In Domain" },
		{ L"CC17B1FB-33D9-11D2-97D4-00C04FD8D5CD", L"Change Infrastructure Master" },
		{ L"BE2BB760-7F46-11D2-B9AD-00C04F79F805", L"Update Schema Cache" },
		{ L"62DD28A8-7F46-11D2-B9AD-00C04F79F805", L"Recalculate Security Inheritance" },
		{ L"69AE6200-7F46-11D2-B9AD-00C04F79F805", L"Check Stale Phantoms" },
		{ L"0E10C968-78FB-11D2-90D4-00C04F79DC55", L"Enroll" },
		{ L"BF9679C0-0DE6-11D0-A285-00AA003049E2", L"Add/Remove self as member" },
		{ L"72E39547-7B18-11D1-ADEF-00C04FD8D5CD", L"Validated write to DNS host name" },
		{ L"F3A64788-5306-11D1-A9C5-0000F80367C1", L"Validated write to service principal name" },
		{ L"B7B1B3DD-AB09-4242-9E30-9980E5D322F7", L"Generate Resultant Set of Policy (Planning)" },
		{ L"9432C620-033C-4DB7-8B58-14EF6D0BF477", L"Refresh Group Cache for Logons" },
		{ L"91D67418-0135-4ACC-8D79-C08E857CFBEC", L"Enumerate Entire SAM Domain" },
		{ L"B7B1B3DE-AB09-4242-9E30-9980E5D322F7", L"Generate Resultant Set of Policy (Logging)" },
		{ L"B8119FD0-04F6-4762-AB7A-4986C76B3F9A", L"Other Domain Parameters (for use by SAM)" },
		{ L"E2A36DC9-AE17-47C3-B58B-BE34C55BA633", L"Create Inbound Forest Trust" },
		{ L"1131F6AD-9C07-11D1-F79F-00C04FC2DCD2", L"Replicating Directory Changes All" },
		{ L"BA33815A-4F93-4C76-87F3-57574BFF8109", L"Migrate SID History" },
		{ L"45EC5156-DB7E-47BB-B53F-DBEB2D03C40F", L"Reanimate Tombstones" },
		{ L"68B1D179-0D15-4D4F-AB71-46152E79A7BC", L"Allowed to Authenticate" },
		{ L"2F16C4A5-B98E-432C-952A-CB388BA33F2E", L"Execute Forest Update Script" },
		{ L"F98340FB-7C5B-4CDB-A00B-2EBDFA115A96", L"Monitor Active Directory Replication" },
		{ L"280F369C-67C7-438E-AE98-1D46F3C6F541", L"Update Password Not Required Bit" },
		{ L"CCC2DC7D-A6AD-4A7A-8846-C04E3CC53501", L"Unexpire Password" },
		{ L"05C74C5E-4DEB-43B4-BD9F-86664C2A7FD5", L"Enable Per User Reversibly Encrypted Password" },
		{ L"4ECC03FE-FFC0-4947-B630-EB672A8A9DBC", L"Query Self Quota" },
		{ L"91E647DE-D96F-4B70-9557-D63FF4F3CCD8", L"Private Information" },
		{ L"1131F6AE-9C07-11D1-F79F-00C04FC2DCD2", L"Read Only Replication Secret Synchronization" },
		{ L"FFA6F046-CA4B-4FEB-B40D-04DFEE722543", L"MS-TS-GatewayAccess" },
		{ L"5805BC62-BDC9-4428-A5E2-856A0F4C185E", L"Terminal Server License Server" },
		{ L"1A60EA8D-58A6-4B20-BCDC-FB71EB8A9FF8", L"Reload SSL/TLS Certificate" },
		{ L"89E95B76-444D-4C62-991A-0FACBEDA640C", L"Replicating Directory Changes In Filtered Set" },
		{ L"7726B9D5-A4B4-4288-A6B2-DCE952E80A7F", L"Run Protect Admin Groups Task" },
		{ L"7C0E2A7C-A419-48E4-A995-10180AAD54DD", L"Manage Optional Features for Active Directory" },
		{ L"3E0F7E18-2C7A-4C10-BA82-4D926DB99A3E", L"Allow a DC to create a clone of itself" },
		{ L"D31A8757-2447-4545-8081-3BB610CACBF2", L"Validated write to MS DS behavior version" },
		{ L"80863791-DBE9-4EB8-837E-7F0AB55D9AC7", L"Validated write to MS DS Additional DNS Host Name" },
		{ L"A05B8CC2-17BC-4802-A710-E7C15AB866A2", L"AutoEnrollment" },
		{ L"4125C71F-7FAC-4FF0-BCB7-F09A41325286", L"Set Owner of an object during creation." },
		{ L"88A9933E-E5C8-4F2A-9DD7-2527416B8092", L"Bypass the quota restrictions during creation." },
		{ L"084C93A2-620D-4879-A836-F0AE47DE0E89", L"Read secret attributes of objects in a Partition." },
		{ L"94825A8D-B171-4116-8146-1E34D8F54401", L"Write secret attributes of objects in a Partition." },
		{ L"9B026DA6-0D3C-465C-8BEE-5199D7165CBA", L"Validated write to computer attributes." },
	};
	//****************************************************************************************
	struct XGUID
	{
		XGUID() = delete;
		~XGUID() = default;

		XGUID(const GUID&);
		XGUID(const std::wstring&);
		XGUID(const bin_t&);
		XGUID(const msxml_et&);

		static XGUID Create();

		explicit operator bin_t() const;
		explicit operator GUID() const;
		explicit operator std::wstring() const;
		explicit operator std::string() const;
		explicit operator xml_t() const;

		bin_t Value;

	private:
		void FromString(const std::wstring&);
	};
	//****************************************************************************************
	XGUID XGUID::Create()
	{
		GUID guid;
		ZeroMemory(&guid, sizeof(GUID));

		HRESULT hr = CoCreateGuid(&guid);
		if(S_OK != hr)
			throw std::exception("XGUID: cannot create GUID");

		return XGUID(guid);
	}
	//****************************************************************************************
	XGUID::XGUID(const GUID& value)
	{
		Value.resize(16);
		std::copy_n((unsigned char*)&value, 16, Value.begin());
	}
	//****************************************************************************************
	void XGUID::FromString(const std::wstring& value)
	{
		#pragma region Initial variables
		std::wstringstream stream;

		std::wregex regex(L"([0-9a-fA-F]{8})-{0,1}([0-9a-fA-F]{4})-{0,1}([0-9a-fA-F]{4})-{0,1}([0-9a-fA-F]{4})-{0,1}([0-9a-fA-F]{12})");
		std::match_results<std::wstring::const_iterator> match;
		#pragma endregion

		#pragma region Check input string format
		if(false == std::regex_match(value, match, regex))
			throw std::exception("XGUID: invalid format of the input string");
		#pragma endregion

		#pragma region Parse input string
		for(size_t i = 1; i < 6; i++)
		{
			size_t index = 0;

			std::wstring value = match[i];
			std::vector<std::wstring> chunks(value.size() >> 1, std::wstring{ 2, L' ' });

			for(auto j = value.begin(); j != value.end(); j += 2)
				std::copy_n(j, 2, chunks[index++].begin());

			if(i < 4)
				std::reverse(chunks.begin(), chunks.end());

			std::copy(chunks.begin(), chunks.end(), std::ostream_iterator<std::wstring, wchar_t>(stream, L" "));
		}
		#pragma endregion

		#pragma region Convert string to binary format
		Value = XSEC::from_hex_codes(stream.str());
		#pragma endregion
	}
	//****************************************************************************************
	XGUID::XGUID(const std::wstring& value)
	{
		FromString(value);
	}
	//****************************************************************************************
	XGUID::XGUID(const bin_t& value)
	{
		if(value.size() != 16)
			throw std::exception("XGUID: invalid input value");

		Value = value;
	}
	//****************************************************************************************
	XGUID::XGUID(const msxml_et& xml)
	{
		#pragma region Additional check
		if(nullptr == xml)
			throw std::exception("XGUID: incorrect input XML");
		#pragma endregion

		FromString((wchar_t*)xml->text);
	}
	//****************************************************************************************
	XGUID::operator bin_t() const
	{
		return Value;
	}
	//****************************************************************************************
	XGUID::operator GUID() const
	{
		return *(GUID*)Value.data();
	}
	//****************************************************************************************
	XGUID::operator std::wstring() const
	{
		#pragma region Initial variables
		std::wstring hex = XSEC::whex_codes(Value);
		hex.erase(std::remove(hex.begin(), hex.end(), L' '), hex.end());

		std::wstringstream stream;

		std::wregex regex(L"([0-9a-fA-F]{8})-{0,1}([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{12})");
		std::match_results<std::wstring::const_iterator> match;
		#pragma endregion

		#pragma region Check input string format
		if(false == std::regex_match(hex, match, regex))
			throw std::exception("XGUID: invalid Value");
		#pragma endregion

		#pragma region Parse input string
		for(size_t i = 1; i < 6; i++)
		{
			size_t index = 0;

			std::wstring value = match[i];
			std::vector<std::wstring> chunks(value.size() >> 1, std::wstring{ 2, L' ' });

			for(auto j = value.begin(); j != value.end(); j += 2)
				std::copy_n(j, 2, chunks[index++].begin());

			if(i < 4)
				std::reverse(chunks.begin(), chunks.end());

			if((size_t)stream.tellp())
				stream << L"-";

			std::copy(chunks.begin(), chunks.end(), std::ostream_iterator<std::wstring, wchar_t>(stream));
		}
		#pragma endregion

		return stream.str();
	}
	//****************************************************************************************
	XGUID::operator std::string() const
	{
		#pragma region Initial variables
		std::string hex = XSEC::hex_codes(Value);
		hex.erase(std::remove(hex.begin(), hex.end(), ' '), hex.end());

		std::stringstream stream;

		std::regex regex("([0-9a-fA-F]{8})-{0,1}([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{12})");
		std::match_results<std::string::const_iterator> match;
		#pragma endregion

		#pragma region Check input string format
		if(false == std::regex_match(hex, match, regex))
			throw std::exception("XGUID: invalid Value");
		#pragma endregion

		#pragma region Parse input string
		for(size_t i = 1; i < 6; i++)
		{
			size_t index = 0;

			std::string value = match[i];
			std::vector<std::string> chunks(value.size() >> 1, std::string{ 2, ' ' });

			for(auto j = value.begin(); j != value.end(); j += 2)
				std::copy_n(j, 2, chunks[index++].begin());

			if(i < 4)
				std::reverse(chunks.begin(), chunks.end());

			if((size_t)stream.tellp())
				stream << "-";

			std::copy(chunks.begin(), chunks.end(), std::ostream_iterator<std::string, char>(stream));
		}
		#pragma endregion

		return stream.str();
	}
	//****************************************************************************************
	XGUID::operator xml_t() const
	{
		return[&](msxml_dt xml, std::optional<const wchar_t*> root)->msxml_et
		{
			#pragma region Additional check
			if(nullptr == xml)
				throw std::exception("XSID: invalid output XML");
			#pragma endregion

			#pragma region Root element
			msxml_et guid = xml->createElement(std::wstring(root.value_or(L"GUID")).c_str());

			auto string = (std::wstring)*this;

			auto search = WellKnownGUIDs.find(string);
			if(search != WellKnownGUIDs.end())
			{
				msxml_at name = xml->createAttribute(L"Name");

				name->value = search->second.c_str();
				guid->setAttributeNode(name);
			}

			guid->appendChild(xml->createTextNode(string.c_str()));
			#pragma endregion

			return guid;
		};
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
	#pragma region Class fo working with OBJECT_TYPE_LIST
	//****************************************************************************************
	struct XOBJECT_TYPE_LIST
	{
		XOBJECT_TYPE_LIST() = delete;
		~XOBJECT_TYPE_LIST() = default;

		XOBJECT_TYPE_LIST(const OBJECT_TYPE_LIST&);
		XOBJECT_TYPE_LIST(const bin_t&, const WORD& = 0);
		XOBJECT_TYPE_LIST(const std::wstring&, const WORD& = 0);

		explicit operator OBJECT_TYPE_LIST();

		WORD Level = 0;
		std::shared_ptr<XGUID> ObjectType;
	};
	//****************************************************************************************
	XOBJECT_TYPE_LIST::XOBJECT_TYPE_LIST(const OBJECT_TYPE_LIST& list) : Level(list.Level), ObjectType(std::make_shared<XGUID>(*list.ObjectType))
	{
	}
	//****************************************************************************************
	XOBJECT_TYPE_LIST::XOBJECT_TYPE_LIST(const bin_t& objectType, const WORD& level) : Level(level), ObjectType(std::make_shared<XGUID>(objectType))
	{
	}
	//****************************************************************************************
	XOBJECT_TYPE_LIST::XOBJECT_TYPE_LIST(const std::wstring& objectType, const WORD& level) : Level(level), ObjectType(std::make_shared<XGUID>(objectType))
	{
	}
	//****************************************************************************************
	XOBJECT_TYPE_LIST::operator OBJECT_TYPE_LIST()
	{
		if(nullptr == ObjectType)
			throw std::exception("XOBJECT_TYPE_LIST: initialize data first");

		return { Level, 0, (GUID*)ObjectType->Value.data() };
	}
	//****************************************************************************************
	#pragma endregion
	//****************************************************************************************
};
//********************************************************************************************

