#include "console_color.h"
#include <iostream>
#include <paramkit.h>

void pesieve::util::print_in_color(int color, const std::string & text, bool is_error)
{
    int descriptor = is_error ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE;
    paramkit::print_in_color(color, text, descriptor);
}
