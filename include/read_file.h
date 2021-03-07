///////////////////////////////////////////////////////////////////////////////
// File: file.h
// Date: 23.08.2019
// Version: 1
// Author: Christian Steinbrecher
// Description: Function to load a file
///////////////////////////////////////////////////////////////////////////////

#pragma once

#include <fstream>
#include <vector>
#include <filesystem>

inline std::vector<char> read_file(std::string const & filename) {
	std::ifstream file(filename, std::ios::ate | std::ios::binary);

	if (!file.is_open()) {
		throw std::runtime_error("failed to open file: \"" + filename + 
            "\", current path: \"" + std::filesystem::current_path().c_str() + "\"");
	}

	size_t const fileSize = static_cast<size_t>(file.tellg());
	std::vector<char> buffer(fileSize);

	file.seekg(0);
	file.read(buffer.data(), fileSize);

	file.close();

	return buffer;
}