#pragma once

#include <windows.h>
#include <stdexcept>
#include <vector>

namespace pesieve {
	namespace util {
		size_t enum_modules(IN HANDLE hProcess, OUT std::vector<HMODULE>& hMods, IN DWORD filters); //throws exceptions
	};
};
