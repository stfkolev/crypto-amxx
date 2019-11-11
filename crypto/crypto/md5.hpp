#pragma once

#include <string>

/*! Computing MD5 Hash
 *
 * Usage:
 *
 *	MD5 md5;
 *  auto myHash = md5("Hello World"); // std::string
 *	auto myHash2 = md5("How are you", 11);	// arbitrary data, 11 bytes
 *
 *	MD5 md5;
 *	while (more data available)
 *		md5.add(pointer to fresh data, number of new bytes);
 */

class MD5 {
public:

	/*!
	 * Split into 64 byte blocks (=> 512 bits), hash is 16 bytes long
	 */
	enum {
		BlockSize = 512 / 8,
		HashBytes = 16
	};

	/*!
	 *	Reset
	 */
	MD5();

	/*!
	 * Compute MD5 of a memory block
	 */
	auto operator()(const void* data, size_t numBytes)->std::string;

	/*!
	 * Compute MD5 of a strng, excluding the terminating zero
	 */
	auto operator()(const std::string& text)->std::string;

	/*!
	 * Split into 64 byte blocks (=> 512 bits), hash is 16 bytes long
	 */
	auto add(const void* data, size_t numBytes) -> void;

	/*!
	 * Return latest hash as 32 hex chars
	 */
	auto getHash()->std::string;

	/*!
	 * return latest hash as bytes
	 */
	auto getHash(unsigned char buffer[HashBytes]) -> void;

	/*!
	 * Reset
	 */
	auto reset() -> void;

private:

	/*!
	 * Process 64 bytes
	 */
	auto processBlock(const void* data) -> void;

	/*!
	 * Process everything left in the internal buffer
	 */
	auto processBuffer() -> void;

	/*!
	 * Size of processed data in bytes
	 */
	uint64_t m_numBytes;

	/*!
	 * Valid bytes in m_buffer
	 */
	size_t m_bufferSize;

	/*!
	 * Bytes not processed yet
	 */
	uint8_t m_buffer[BlockSize];

	enum {
		HashValues = HashBytes / 4
	};

	uint32_t m_hash[HashValues];
};