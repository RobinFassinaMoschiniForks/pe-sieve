#include "pe_buffer.h"

#include <iostream>
#include "../scanners/artefact_scanner.h"

size_t PeBuffer::calcRemoteImgSize(HANDLE processHandle, ULONGLONG modBaseAddr)
{
	const size_t hdr_buffer_size = PAGE_SIZE;
	BYTE hdr_buffer[hdr_buffer_size] = { 0 };
	size_t pe_vsize = 0;

	PIMAGE_SECTION_HEADER hdr_ptr = NULL;
	if (peconv::read_remote_pe_header(processHandle, (BYTE*)modBaseAddr, hdr_buffer, hdr_buffer_size)) {
		hdr_ptr = peconv::get_section_hdr(hdr_buffer, hdr_buffer_size, 0);
	}
	if (!hdr_ptr) {
		pe_vsize = peconv::fetch_region_size(processHandle, (PBYTE)modBaseAddr);
		//std::cout << "[!] Image size at: " << std::hex << modBaseAddr << " undetermined, using region size instead: " << pe_vsize << std::endl;
		return pe_vsize;
	}
	pe_vsize = ArtefactScanner::calcImgSize(processHandle, (HMODULE)modBaseAddr, hdr_buffer, hdr_buffer_size, hdr_ptr);
	//std::cout << "[!] Image size at: " << std::hex << modBaseAddr << " undetermined, using calculated img size: " << pe_vsize << std::endl;
	return pe_vsize;
}

bool PeBuffer::readRemote(HANDLE process_hndl, ULONGLONG module_base, size_t pe_vsize)
{
	if (pe_vsize == 0) {
		// if not size supplied, try with the size fetched from the header
		pe_vsize = peconv::get_remote_image_size(process_hndl, (BYTE*)module_base);
	}
	if (_readRemote(process_hndl, module_base, pe_vsize)) {
		return true; //success
	}
	// try with the calculated size
	pe_vsize = calcRemoteImgSize(process_hndl, module_base);
	std::cout << "[!] Image size at: " << std::hex << module_base << " undetermined, using calculated size: " << pe_vsize << std::endl;
	return _readRemote(process_hndl, module_base, pe_vsize);
}

bool PeBuffer::_readRemote(HANDLE process_hndl, ULONGLONG module_base, size_t pe_vsize)
{
	if (pe_vsize == 0) {
		return false;
	}
	if (!allocBuffer(pe_vsize)) {
		return false;
	}
	size_t read_size = peconv::read_remote_area(process_hndl, (BYTE*)module_base, vBuf, pe_vsize);
	if (read_size != pe_vsize) {
		std::cout << "[!] Failed reading Image at: " << std::hex << module_base << " img size: " << pe_vsize << std::endl;
		freeBuffer();
		return false;
	}
	this->moduleBase = module_base;
	this->relocBase = module_base; //by default set the same as module base
	return true;
}

bool PeBuffer::resizeBuffer(size_t new_size)
{
	if (!vBuf) return false;

	BYTE *new_buf = peconv::alloc_aligned(new_size, PAGE_READWRITE);
	if (!new_buf) {
		return false;
	}
	//preserve the module base:
	ULONGLONG module_base = this->moduleBase;

	size_t smaller_size = (vBufSize < new_size) ? vBufSize : new_size;
	memcpy(new_buf, this->vBuf, smaller_size);
	freeBuffer();

	this->moduleBase = module_base;
	this->vBuf = new_buf;
	this->vBufSize = new_size;
	return true;
}

bool PeBuffer::resizeLastSection(size_t new_img_size)
{
	if (!vBuf) return false;

	PIMAGE_SECTION_HEADER last_sec = peconv::get_last_section(vBuf, vBufSize, false);
	if (!last_sec) {
		return false;
	}

	if (new_img_size < last_sec->VirtualAddress) {
		return false;
	}

	const size_t new_sec_vsize = new_img_size - last_sec->VirtualAddress;
	const size_t new_sec_rsize = new_sec_vsize;

	if (last_sec->VirtualAddress + new_sec_vsize > this->vBufSize) {
		//buffer too small
		return false;
	}

	if (!peconv::update_image_size(vBuf, new_img_size)) {
		return false;
	}

	last_sec->Misc.VirtualSize = new_sec_vsize;
	last_sec->SizeOfRawData = new_sec_rsize;
	return true;
}

bool PeBuffer::dumpPeToFile(
	IN std::string dumpFileName,
	IN OUT peconv::t_pe_dump_mode &dumpMode,
	IN OPTIONAL const peconv::ExportsMapper* exportsMap,
	OUT OPTIONAL peconv::ImpsNotCovered *notCovered
)
{
	if (!vBuf || !isValidPe()) return false;
#ifdef _DEBUG
	std::cout << "Dumping using relocBase: " << std::hex << relocBase << "\n";
#endif
	if (exportsMap != nullptr) {
		if (!peconv::fix_imports(this->vBuf, this->vBufSize, *exportsMap, notCovered)) {
			std::cerr << "[-] Unable to fix imports!" << std::endl;
		}
	}
	if (dumpMode == peconv::PE_DUMP_AUTO) {
		bool is_raw_alignment_valid = peconv::is_valid_sectons_alignment(vBuf, vBufSize, true);
		bool is_virtual_alignment_valid = peconv::is_valid_sectons_alignment(vBuf, vBufSize, false);
#ifdef _DEBUG
		std::cout << "Is raw alignment valid: " << is_raw_alignment_valid << std::endl;
		std::cout << "Is virtual alignment valid: " << is_virtual_alignment_valid << std::endl;
#endif
		if (!is_raw_alignment_valid && is_virtual_alignment_valid) {
			//in case if raw alignment is invalid and virtual valid, try to dump using Virtual Alignment first
			dumpMode = peconv::PE_DUMP_REALIGN;
			bool is_dumped = peconv::dump_pe(dumpFileName.c_str(), this->vBuf, this->vBufSize, this->relocBase, dumpMode);
			if (is_dumped) {
				return is_dumped;
			}
			dumpMode = peconv::PE_DUMP_AUTO; //revert and try again
		}
	}
	// save the read module into a file
	return peconv::dump_pe(dumpFileName.c_str(), this->vBuf, this->vBufSize, this->relocBase, dumpMode);
}

bool PeBuffer::dumpToFile(IN std::string dumpFileName)
{
	if (!vBuf) return false;
	return peconv::dump_to_file(dumpFileName.c_str(), vBuf, vBufSize);
}
