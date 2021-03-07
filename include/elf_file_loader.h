// 
// File: elf_file_loader.h
// Author: GrandChris
// Date: 2021-03-07
// Brief: Loads and provides an elf file for the elfin library
//

#pragma once

#include "elf/elf++.hh"
#include "read_file.h"
#include <string>
#include <stdexcept>

///
/// \class elf_file_loader
/// \brief  Reads an elf file into memory
///
class elf_file_loader : public elf::loader
{
public:
    ///////////////////////////////////////////////////////////////////////////////
    // Constructor

    elf_file_loader(std::string const &filename);

    ///////////////////////////////////////////////////////////////////////////////
    // Inherited functions

    virtual void const *load(off_t offset, size_t size) override;

private:
    std::vector<char> mFile;
};

///////////////////////////////////////////////////////////////////////////////
// Implementation

///
/// \brief  Constructor
/// \param filename   Path to an elf-file
///
inline elf_file_loader::elf_file_loader(std::string const &filename)
{
    mFile = read_file(filename);
}

inline void const *elf_file_loader::load(off_t offset, size_t size)
{
    if((offset + size) > mFile.size()) {
        throw std::range_error("elf_file_loader::load: index out of range");
    }

    return &mFile[offset];
}
