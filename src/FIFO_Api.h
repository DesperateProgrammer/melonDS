#ifndef FIFO_API_H
#define FIFO_API_H

#include "NDS.h"
#include <stdint.h>
#include <string>

namespace melonDS
{
	class NDS;

	class FIFOApi
	{
	public:
	    FIFOApi(NDS& nds);
	    ~FIFOApi() = default;

	    bool ExecuteHook(const uint8_t cpu, const uint32_t value);

	    bool ExecuteFileIORequest(const uint8_t cpu, uint32_t requestDataAddress);
	    bool ExecuteWifiRequest(const uint8_t cpu, uint32_t requestDataAddress);
	private:
    	melonDS::NDS& nds;

    	std::string ReadString(const uint8_t cpu, uint32_t address);
    	std::string ReadDataAsHexString(const uint8_t cpu, uint32_t address, uint32_t length);

    	void LogFileIORequest(uint8_t cpu, uint32_t addr);
    	void LogWifiRequest(uint8_t cpu, uint32_t addr);
    };

}

#endif