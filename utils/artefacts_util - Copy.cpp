#include "artefacts_util.h"
#include <peconv.h>
#include <sig_finder.h>
using namespace sig_finder;

#ifdef _DEBUG
	#include <iostream>
#endif

BYTE* pesieve::util::find_pattern(BYTE* buffer, size_t buf_size, BYTE* pattern_buf, size_t pattern_size, size_t max_iter)
{
	for (size_t i = 0; (i + pattern_size) < buf_size; i++) {
		if (max_iter != 0 && i > max_iter) break;
		if (memcmp(buffer + i, pattern_buf, pattern_size) == 0) {
			return (buffer + i);
		}
	}
	return nullptr;
}

bool init_32_patterns(Node* rootN)
{
	if (!rootN) return false;

	BYTE prolog32_pattern[] = {
		0x55, // PUSH EBP
		0x8b, 0xEC // MOV EBP, ESP
	};

	BYTE prolog32_2_pattern[] = {
		0x55, // PUSH EBP
		0x89, 0xE5 // MOV EBP, ESP
	};

	BYTE prolog32_3_pattern[] = {
		0x60, // PUSHAD
		0x89, 0xE5 // MOV EBP, ESP
	};

	rootN->addPattern("prolog32_1", prolog32_pattern, sizeof(prolog32_pattern));
	rootN->addPattern("prolog32_2", prolog32_2_pattern, sizeof(prolog32_2_pattern));
	rootN->addPattern("prolog32_3", prolog32_3_pattern, sizeof(prolog32_3_pattern));
	return true;
}

bool init_64_patterns(Node* rootN64)
{
	if (!rootN64) return false;

	BYTE prolog64_pattern[] = {
		0x40, 0x53,       // PUSH RBX
		0x48, 0x83, 0xEC // SUB RSP, <BYTE>
	};
	BYTE prolog64_2_pattern[] = {
		0x55,            // PUSH RBP
		0x48, 0x8B, 0xEC // MOV RBP, RSP
	};
	BYTE prolog64_3_pattern[] = {
		0x40, 0x55,      // PUSH RBP
		0x48, 0x83, 0xEC // SUB RSP, <BYTE>
	};
	BYTE prolog64_4_pattern[] = {
		0x53,            // PUSH RBX
		0x48, 0x81, 0xEC // SUB RSP, <DWORD>
	};
	BYTE prolog64_5_pattern[] = {
		0x48, 0x83, 0xE4, 0xF0 // AND rsp, FFFFFFFFFFFFFFF0; Align RSP to 16 bytes
	};
	BYTE prolog64_6_pattern[] = {
		0x57,            // PUSH RDI
		0x48, 0x89, 0xE7 // MOV RDI, RSP
	};
	BYTE prolog64_7_pattern[] = {
		 0x48, 0x8B, 0xC4, // MOV RAX, RSP
		 0x48, 0x89, 0x58, 0x08, // MOV QWORD PTR [RAX + 8], RBX
		 0x4C, 0x89, 0x48, 0x20, // MOV QWORD PTR [RAX + 0X20], R9
		 0x4C, 0x89, 0x40, 0x18, // MOV QWORD PTR [RAX + 0X18], R8
		 0x48, 0x89, 0x50, 0x10, // MOV QWORD PTR [RAX + 0X10], RDX
		 0x55, // PUSH RBP
		 0x56, // PUSH RSI
		 0x57, // PUSH RDI 
		 0x41, 0x54, // PUSH R12
		 0x41, 0x55, // PUSH R13
		 0x41, 0x56, // PUSH R14
		 0x41, 0x57 // PUSH R15
	};

	rootN64->addPattern("prolog64_1", prolog64_pattern, sizeof(prolog64_pattern));
	rootN64->addPattern("prolog64_2", prolog64_2_pattern, sizeof(prolog64_2_pattern));
	rootN64->addPattern("prolog64_3", prolog64_3_pattern, sizeof(prolog64_3_pattern));
	rootN64->addPattern("prolog64_4", prolog64_4_pattern, sizeof(prolog64_4_pattern));
	rootN64->addPattern("prolog64_5", prolog64_5_pattern, sizeof(prolog64_5_pattern));
	rootN64->addPattern("prolog64_6", prolog64_6_pattern, sizeof(prolog64_6_pattern));
	rootN64->addPattern("prolog64_7", prolog64_7_pattern, sizeof(prolog64_7_pattern));
	return true;
}

size_t search_till_pattern(sig_finder::Node& rootN, const BYTE* loadedData, size_t loadedSize)
{
	std::vector<Match> allMatches;
	sig_finder::find_all_matches(rootN, loadedData, loadedSize, allMatches);
	if (!allMatches.size()) {
		return CODE_PATTERN_NOT_FOUND;
	}
	return allMatches.size();
}

size_t pesieve::util::is_32bit_code(BYTE *loadedData, size_t loadedSize)
{
	static sig_finder::Node rootN;
	if(rootN.isEnd()) {
		init_32_patterns(&rootN);
	}
	return search_till_pattern(rootN, loadedData, loadedSize);
}

size_t pesieve::util::is_64bit_code(BYTE* loadedData, size_t loadedSize)
{
	static sig_finder::Node rootN;
	if (rootN.isEnd()) {
		init_64_patterns(&rootN);
	}
	return search_till_pattern(rootN, loadedData, loadedSize);
}

bool pesieve::util::is_code(BYTE* loadedData, size_t loadedSize)
{
	if (peconv::is_padding(loadedData, loadedSize, 0)) {
		return false;
	}

	static Node rootN;
	if (rootN.isEnd()) {
		init_32_patterns(&rootN);
		init_64_patterns(&rootN);
	}

	if ((search_till_pattern(rootN, loadedData, loadedSize)) != CODE_PATTERN_NOT_FOUND) {
		return true;
	}
	return false;
}

bool pesieve::util::is_executable(DWORD mapping_type, DWORD protection)
{
	const bool is_any_exec = (protection & PAGE_EXECUTE_READWRITE)
		|| (protection & PAGE_EXECUTE_READ)
		|| (protection & PAGE_EXECUTE)
		|| (protection & PAGE_EXECUTE_WRITECOPY);
	return is_any_exec;
}

bool pesieve::util::is_readable(DWORD mapping_type, DWORD protection)
{
	const bool is_read = (protection & PAGE_READWRITE)
		|| (protection & PAGE_READONLY);
	return is_read;
}

bool pesieve::util::is_normal_inaccessible(DWORD state, DWORD mapping_type, DWORD protection)
{
	if ((state & MEM_COMMIT) == 0) {
		//not committed
		return false;
	}
	if (mapping_type != MEM_IMAGE && (mapping_type != MEM_MAPPED) && mapping_type != MEM_PRIVATE) {
		// invalid mapping type
		return false;
	}
	if (protection & PAGE_NOACCESS) {
		// inaccessible found
		return true;
	}
	return false;
}