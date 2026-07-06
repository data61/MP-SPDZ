/*
 * ValueInterface.cpp
 *
 */

#include "bigint.h"
#include "ValueInterface.h"

#include <sys/stat.h>

const false_type ValueInterface::binary;
const false_type ValueInterface::optimized_packing;

const true_type ValueInterface::is_clear;

void ValueInterface::check_setup(const string& directory)
{
    struct stat sb;
    if (stat(directory.c_str(), &sb) != 0)
        throw setup_error(directory + " does not exist");
    if (not (sb.st_mode & S_IFDIR))
        throw setup_error(directory + " is not a directory");
}
