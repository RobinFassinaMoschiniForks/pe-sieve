#pragma once

#include <windows.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <peconv.h>
#include "pe_sieve_types.h"

#include "../utils/path_util.h"
#include "../utils/format_util.h"

namespace pesieve {

	typedef enum module_scan_status {
		SCAN_ERROR = -1,
		SCAN_NOT_SUSPICIOUS = 0,
		SCAN_SUSPICIOUS = 1
	} t_scan_status;

	//!  A base class of all the reports detailing on the output of the performed element scan.
	class ElementScanReport
	{
	public:
		ElementScanReport(t_scan_status _status = SCAN_NOT_SUSPICIOUS)
			: status(_status)
		{
		}

		static const size_t JSON_LEVEL = 1;

		static t_scan_status get_scan_status(const ElementScanReport* report)
		{
			if (report == nullptr) {
				return SCAN_ERROR;
			}
			return report->status;
		}

		t_scan_status status;

	protected:
		const virtual bool _toJSON(std::stringstream& outs, size_t level = JSON_LEVEL, const pesieve::t_json_level& jdetails = JSON_BASIC)
		{
			OUT_PADDED(outs, level, "\"status\" : ");
			outs << std::dec << status;
			return true;
		}
	};

	//!  A base class of all the reports detailing on the output of the performed module's scan.
	class ModuleScanReport : public ElementScanReport
	{
	public:
		ModuleScanReport(HMODULE _module, size_t _moduleSize, t_scan_status _status = SCAN_NOT_SUSPICIOUS)
			: ElementScanReport(_status),
			module(_module), moduleSize(_moduleSize), isDotNetModule(false),
			origBase(0), relocBase((ULONGLONG)_module)
		{
		}

		virtual ~ModuleScanReport() {}

		virtual ULONGLONG getRelocBase()
		{
			return (ULONGLONG)this->module;
		}

		const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL, const pesieve::t_json_level &jdetails = JSON_BASIC) = 0;

		HMODULE module;
		size_t moduleSize;
		bool isDotNetModule;
		std::string moduleFile;
		ULONGLONG origBase;
		ULONGLONG relocBase;

	protected:
		const virtual bool _toJSON(std::stringstream& outs, size_t level = JSON_LEVEL, const pesieve::t_json_level& jdetails = JSON_BASIC)
		{
			ElementScanReport::_toJSON(outs, level, jdetails);
			if (module) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"module\" : ");
				outs << "\"" << std::hex << (ULONGLONG)module << "\"";
				if (moduleSize) {
					outs << ",\n";
					OUT_PADDED(outs, level, "\"module_size\" : ");
					outs << "\"" << std::hex << (ULONGLONG)moduleSize << "\"";
				}
			}
#ifdef _DEBUG
			if (origBase) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"original_base\" : ");
				outs << std::hex << "\"" << origBase << "\"";
			}
#endif //_DEBUG
			if (relocBase && relocBase != (ULONGLONG)module) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"reloc_base\" : ");
				outs << std::hex << "\"" << relocBase << "\"";
			}
			if (moduleFile.length()) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"module_file\" : ");
				outs << "\"" << pesieve::util::escape_path_separators(moduleFile) << "\"";
			}
			if (isDotNetModule) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"is_dot_net\" : \"");
				outs << isDotNetModule << "\"";
			}
			return true;
		}

	};

	class UnreachableModuleReport : public ModuleScanReport
	{
	public:
		UnreachableModuleReport(HMODULE _module, size_t _moduleSize, std::string _moduleFile)
			: ModuleScanReport(_module, _moduleSize, SCAN_ERROR)
		{
			moduleFile = _moduleFile;
		}

		const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL, const pesieve::t_json_level &jdetails = JSON_BASIC)
		{
			OUT_PADDED(outs, level, "\"unreachable_scan\" : ");
			outs << "{\n";
			ModuleScanReport::_toJSON(outs, level + 1);
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}
	};

	class SkippedModuleReport : public ModuleScanReport
	{
	public:
		SkippedModuleReport(HMODULE _module, size_t _moduleSize, std::string _moduleFile)
			: ModuleScanReport(_module, _moduleSize, SCAN_NOT_SUSPICIOUS)
		{
			moduleFile = _moduleFile;
		}

		const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL, const pesieve::t_json_level &jdetails = JSON_BASIC)
		{
			OUT_PADDED(outs, level, "\"skipped_scan\" : ");
			outs << "{\n";
			ModuleScanReport::_toJSON(outs, level + 1);
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}
	};

	class MalformedHeaderReport : public ModuleScanReport
	{
	public:
		MalformedHeaderReport(HMODULE _module, size_t _moduleSize, std::string _moduleFile)
			: ModuleScanReport(_module, _moduleSize, SCAN_SUSPICIOUS)
		{
			moduleFile = _moduleFile;
		}

		const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL, const pesieve::t_json_level &jdetails = JSON_BASIC)
		{
			OUT_PADDED(outs, level, "\"malformed_header\" : ");
			outs << "{\n";
			ModuleScanReport::_toJSON(outs, level + 1);
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}
	};

}; //namespace pesieve
