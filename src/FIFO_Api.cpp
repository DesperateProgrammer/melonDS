/*
    Copyright 2016-2024 melonDS team

    This file is part of melonDS.

    melonDS is free software: you can redistribute it and/or modify it under
    the terms of the GNU General Public License as published by the Free
    Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    melonDS is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with melonDS. If not, see http://www.gnu.org/licenses/.
*/

#include "NDS.h"
#include <string>
#include <stdbool.h>
#include <ios>
#include <sstream>
#include <stdio.h>
#include <time.h>

namespace melonDS
{

    using Platform::Log;
    using Platform::LogLevel;

    constexpr uint32_t REQUEST_GETARCHIVERESOURCE = 0x04;
    constexpr uint32_t REQUEST_GETPATHINFO = 0x06;
    constexpr uint32_t REQUEST_DELETEFOLDER = 0x0B;
    constexpr uint32_t REQUEST_CREATEFOLDER = 0x0C;
    constexpr uint32_t REQUEST_OPENFILE = 0x0E;
    constexpr uint32_t REQUEST_CLOSEFILE = 0x0F;
    constexpr uint32_t REQUEST_READFILE = 0x10;
    constexpr uint32_t REQUEST_WRITEFILE = 0x11;
    constexpr uint32_t REQUEST_SEEKFILE = 0x12;
    constexpr uint32_t REQUEST_GETFILELENGTH = 0x14;
    constexpr uint32_t REQUEST_SETFILELENGTH = 0x15;
    constexpr uint32_t REQUEST_OPENFOLDER = 0x16;
    constexpr uint32_t REQUEST_CLOSEFOLDER = 0x17;
    constexpr uint32_t REQUEST_READFOLDER = 0x18;

    void InitializeCapture()
    {
        FILE *f = fopen("network.pcap", "w+");
        uint8_t header[] =  {
                                0xd4,0xc3,0xb2,0xa1,0x02,0x00,0x04,0x00,
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                0x00,0x00,0x04,0x00,0x01,0x00,0x00,0x00,
                            };
        fwrite(&header[0], sizeof(header), 1, f);
        fclose(f);
    }
    void AppendCapture(uint8_t *data, uint length)
    {
        FILE *f = fopen("network.pcap", "a");
        for (int i=0;i<8;i++)
        {
            fwrite("\0", 1, 1, f);           
        }

        uint8_t lenBuff[4] = {(length >> 0) & 0xff, (length >> 8) & 0xff, (length >> 16) & 0xff, (length >> 24) & 0xff};
        fwrite(&lenBuff[0],4,1,f);
        fwrite(&lenBuff[0],4,1,f);
        fwrite(data,length,1,f);
        fclose(f);
    }


    FIFOApi::FIFOApi(melonDS::NDS& nds) :
        nds(nds)
    {
        InitializeCapture();
    }



    struct FileIORequest
    {
        uint32_t command;
        uint32_t unkn_04;
        uint32_t unkn_08;
        uint32_t unkn_0C;
        union
        {
            struct
            {
                uint32_t index;
                uint32_t pFilename;
            } getDriver;
            struct
            { 
                uint32_t handle;
                char     fileMode[4];
                char     refName;
            } openFile;
            struct
            { 
                uint32_t handle;
            } closeFile;
            struct
            {
                uint32_t handle;
                uint32_t pBuffer;
                uint32_t length;
            } readWriteFile;
            struct 
            {
                uint32_t handle;
                uint32_t length;                
            } getSetFileLength;
        } params;
    };

    std::string FIFOApi::ReadString(const uint8_t cpu, uint32_t address)
    {
        if ((address & 0xFF000000) != 0x02000000)
            return "";
        std::string tmp = "";
        do
        {
            uint8_t asc = nds.ARM9Read8(address);
            if ((asc == 0) && (address & 0x03) && (tmp == ""))
            {
                address ++;
                continue;
            } 
            if ((tmp == "") && !(address & 0x03))
            {
                uint32_t refAddr = nds.ARM9Read32(address);;
                std::string refString = ReadString(cpu, refAddr);
                if (refString != "")
                    return refString;
            }
            if ((asc == 0) && !(address & 0x01))
                return tmp;    
            if (asc != 0)
                tmp += (char)asc;
            address++ ;
        } while (true);
    }

    std::string FIFOApi::ReadDataAsHexString(const uint8_t cpu, uint32_t address, uint32_t length)
    {
        if ((address & 0xFF000000) != 0x02000000)
            return "<null>";
        std::string tmp = "";
        for (int i=0;i<length;i++)
        {
            int asc = nds.ARM9Read8(address++);
            if (tmp != "")
                tmp += " ";
            std::stringstream stream;
            stream << std::hex << asc;
            tmp += stream.str();
        } 
        return tmp;
    }

    std::string FileIOCommandCodeToName(uint32_t commandCode)
    {
        switch (commandCode)
        {
            case REQUEST_GETARCHIVERESOURCE:
                return "GetArchiveResource";
            case REQUEST_GETPATHINFO:
                return "GetPathInfo";
            case REQUEST_OPENFILE:
                return "OpenFile";
            case REQUEST_CLOSEFILE:
                return "CloseFile";
            case REQUEST_READFILE:
                return "ReadFile";
            case REQUEST_WRITEFILE:
                return "WriteFile";
            case REQUEST_SEEKFILE:
                return "SeekFile";
            case REQUEST_DELETEFOLDER:
                return "DeleteFolder";
            case REQUEST_CREATEFOLDER:
                return "CreateFolder";
            case REQUEST_OPENFOLDER:
                return "OpenFolder";
            case REQUEST_CLOSEFOLDER:
                return "CloseFolder";
            case REQUEST_READFOLDER:
                return "ReadFolder";
            case REQUEST_GETFILELENGTH:
                return "GetFileLength";
            case REQUEST_SETFILELENGTH:
                return "SetFileLength";
            default:
                return "FileIO_" + std::to_string(commandCode);
        }
    }

    void FIFOApi::LogFileIORequest(uint8_t cpu, uint32_t addr)
    {
        std::stringstream stream;

        int pos = addr;
        uint32_t commandCode = nds.ARM9Read32(pos); pos += 4;
        stream << "\n  IO Command = " << std::hex << FileIOCommandCodeToName(commandCode);
        stream << "\n  Status = ";
        uint32_t statusCode = nds.ARM9Read32(pos); pos += 4;
        if (statusCode & 2)
            stream << "pending ";
        if (statusCode & 4)
            stream << "fault ";
        if (!statusCode)
            stream << "completed";
        uint32_t returnCode = nds.ARM9Read32(pos); pos += 4;
        stream << "\n  ReturnCode = " << std::hex << returnCode;
        uint32_t nextRequest = nds.ARM9Read32(pos); pos += 4;
        stream << "\n  NextRequestCode = " << std::hex << nextRequest;
        switch (commandCode)
        {
            case REQUEST_CLOSEFILE:
                {
                    if (statusCode != 0)
                    {
                        uint32_t handle = nds.ARM9Read32(pos); pos += 4;
                        stream << "\n    Handle = " << std::hex << handle;
                    }
                }
                break;
            case REQUEST_OPENFILE:
                {
                    if (statusCode == 0)
                    {
                        uint32_t handle = nds.ARM9Read32(pos); pos += 4;
                        stream << "\n    Handle = " << std::hex << handle;
                    } else
                    {
                        pos += 4;
                    }
                    std::string mode = "";
                    uint8_t asc = 0;
                    do
                    {
                        asc = nds.ARM9Read8(pos);
                        pos++;
                        if (asc != 0)
                            mode += asc;
                    } while (asc != 0);                    
                    stream << "\n    Mode = " << mode;
                    pos = pos - (mode.length()+1) + 16;

                    std::string name = "";
                    do
                    {
                        uint16_t uni = nds.ARM9Read16(pos);
                        pos += 2;
                        if (uni == 0)
                            break;
                        name += (char)uni;
                    } while (true);
                    stream << "\n    Name = " << name;

/*                    stream << "\n    Other = ";
                    for (int i=0;i<64;i++)
                    {
                        int dataB = nds.ARM9Read8(pos++);
                        stream << std::hex << dataB << "-";
                    }
*/
                }
                break;

            case REQUEST_GETARCHIVERESOURCE:
                {
                    std::string name = "";
                    uint8_t asc = 0;
                    do
                    {
                        asc = nds.ARM9Read8(pos);
                        pos++;
                        if (asc != 0)
                            name += asc;
                    } while (asc != 0);
                    stream << "\n    Name = " << name;
                    stream << "\n    Other = ";
                    for (int i=0;i<64;i++)
                    {
                        int dataB = nds.ARM9Read8(pos++);
                        stream << std::hex << dataB << "-";
                    }
                }
                break;
            case REQUEST_OPENFOLDER:
                {
                    uint32_t handle = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Handle = " << std::hex << handle;
                    std::string mode = "";
                    uint8_t asc = 0;
                    do
                    {
                        asc = nds.ARM9Read8(pos);
                        pos++;
                        if (asc != 0)
                            mode += asc;
                    } while (asc != 0);
                    stream << "\n    Mode = " << mode;
                    pos = pos - (mode.length()+1) + 16;

                    std::string name = "";
                    do
                    {
                        uint16_t uni = nds.ARM9Read16(pos);
                        pos += 2;
                        if (uni == 0)
                            break;
                        name += (char)uni;
                    } while (true);
                    stream << "\n    Name = " << name;

/*
                    stream << "\n    Other = ";
                    for (int i=0;i<64;i++)
                    {
                        int dataB = nds.ARM9Read8(pos++);
                        stream << std::hex << dataB << "-";
                    }
*/
                }
                break;
            case REQUEST_GETPATHINFO:
                {
                    std::string name = "";
                    do
                    {
                        uint16_t uni = nds.ARM9Read16(pos);
                        pos += 2;
                        if (uni == 0)
                            break;
                        name += (char)uni;
                    } while (true);
                    stream << "\n    Name = " << name;   
                }              
                break;
            case REQUEST_CLOSEFOLDER:
                {
                    if (statusCode != 0)
                    {
                        uint32_t handle = nds.ARM9Read32(pos); pos += 4;
                        stream << "\n    Handle = " << std::hex << handle;
                    } else
                        pos += 4;
                }
                break;
            case REQUEST_DELETEFOLDER:
                {
                    pos += 16;
                    std::string name = "";
                    do
                    {
                        uint16_t uni = nds.ARM9Read16(pos);
                        pos += 2;
                        if (uni == 0)
                            break;
                        name += (char)uni;
                    } while (true);
                    stream << "\n    Name = " << name;
                }
                break;
            case REQUEST_CREATEFOLDER:
                {
                    std::string name = "";
                    do
                    {
                        uint16_t uni = nds.ARM9Read16(pos);
                        pos += 2;
                        if (uni == 0)
                            break;
                        name += (char)uni;
                    } while (true);
                    stream << "\n    Name = " << name;
                }
                break;
            case REQUEST_READFOLDER:
                {
                    uint32_t handle = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Handle = " << std::hex << handle;
                    if (statusCode == 0)
                    {
                        std::string filename = "";
                        uint8_t asc = 0;
                        do
                        {
                            asc = nds.ARM9Read8(pos);
                            pos++;
                            if (asc != 0)
                                filename += asc;
                        } while (asc != 0);
                        stream << "\n    Name = " << filename;
                    }
/*                    stream << "\n    Other = ";
                    for (int i=0;i<64;i++)
                    {
                        int dataB = nds.ARM9Read8(pos++);
                        stream << std::hex << dataB << "-";
                    }
*/
                }
                break;
            case REQUEST_READFILE:
                {
                    uint32_t handle = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Handle = " << std::hex << handle;
                    uint32_t bufferAddress = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Buffer Address = " << std::hex << bufferAddress;
                    uint32_t length = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Length = " << length << " (0x"  << std::hex << length << ")";
                }
                break;
            case REQUEST_WRITEFILE:
                {
                    uint32_t handle = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Handle = " << std::hex << handle;
                    uint32_t bufferAddress = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Buffer Address = " << std::hex << bufferAddress;
                    uint32_t length = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Length = " << length << " (0x"  << std::hex << length << ")";
                }
                break;
            case REQUEST_SEEKFILE:
                {
                    uint32_t handle = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Handle = " << std::hex << handle;
                    uint32_t Offset = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Offset = " << std::hex << Offset;
                    uint32_t Direction = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Direction = " << std::hex << Direction;
                }
                break;
            case REQUEST_SETFILELENGTH:
                {
                    uint32_t handle = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Handle = " << std::hex << handle;
                    uint32_t length = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Length = " << std::hex << length;
                }
                break;
            case REQUEST_GETFILELENGTH:
                {
                    uint32_t handle = nds.ARM9Read32(pos); pos += 4;
                    stream << "\n    Handle = " << std::hex << handle;
                    if (statusCode == 0)
                    {
                        uint32_t length = nds.ARM9Read32(pos); pos += 4;
                        stream << "\n    Length = " << std::hex << length;
                    }
                }
                break;
            default:
                {
                    stream << "\n    Other = ";
                    for (int i=0;i<64;i++)
                    {
                        int dataB = nds.ARM9Read8(pos++);
                        stream << std::hex << dataB << "-";
                    }
                }
                break;
        }


        Log(LogLevel::Info, "%s\n", stream.str().c_str());
    }

    bool FIFOApi::ExecuteFileIORequest(const uint8_t cpu, uint32_t requestDataAddress)
    {
        // Log the FileIO to the console
        // LogFileIORequest(cpu, requestDataAddress);

        // we could intercept the API calls and do them directy instead of through the emulation
        // this would allow us to 
        // a) fasten up the emulation on IO
        // b) manipulate data and insert/remove files while keeping the nand image intact
        return false;
    }

    std::string WifiCommandCodeToName(uint32_t commandCode)
    {
        switch (commandCode)
        {
            case 0x03:
                return "SetOwnMACAddress";
            case 0x08:
                return "ConnectToAP";
            case 0x0a:
                return "RecvEthernetFrame";
            case 0x0b:
                return "SendEthernetFrame";
            default:
                return "WifiCmd_" + std::to_string(commandCode);
        }
    }

    void FIFOApi::LogWifiRequest(uint8_t cpu, uint32_t addr)
    {        
        if ((addr & 0xFF000003) != 0x02000000)
        {
            Log(LogLevel::Debug, "IPC WIFI: Ptr is not valid: %08x\n",addr);
            return;
        }
        std::stringstream stream;
        int pos = addr;
        uint16_t command = nds.ARM9Read16(pos); pos += 2;
        stream << "\n    CPU: " << (int)cpu;
        stream << "\n    Wifi Command: " << WifiCommandCodeToName(command);
        switch (command)
        {
            case 0x03:
                {
                    if (cpu == 0)
                    {
                        stream << "\n    Unknown = ";
                        for (int i=0;i<64;i++)
                        {
                            int dataB = nds.ARM9Read8(pos++);
                            stream << std::hex << dataB << "-";
                        }   
                    }                    
                }
                break;
            case 0x08:
                {
                    stream << "\n    Unknown = ";
                    for (int i=0;i<64;i++)
                    {
                        int dataB = nds.ARM9Read8(pos++);
                        stream << std::hex << dataB << "-";
                    }                    
                }
                break;                
            case 0x0a:
                {
                    if (cpu == 1)
                    {
                        pos += 4 ;
                        uint16_t Type = nds.ARM9Read16(pos); pos += 2;
                        stream << "\n    Type: " << std::hex << Type;
                        uint32_t length = nds.ARM9Read32(pos); pos += 4;
                        stream << "\n    Length: " << std::dec << length;
                        uint32_t ptr = nds.ARM9Read32(pos); pos += 4;
                        stream << "\n    Ptr: " << std::hex << ptr;

                        if ((ptr & 0xFF000000) == 0x02000000)
                        {
                            uint8_t *buffer = new uint8_t[length];
                            stream << "\n    Data pointed to = ";
                            for (int i=0;i<length;i++)
                            {
                                int dataB = nds.ARM9Read8(ptr++);
                                stream << std::hex << dataB << "-";
                                buffer[i] = dataB;
                            }
                            AppendCapture(buffer, length);
                            delete buffer;
                        }
                    }
                }
                break;
            case 0x0b:
                {
                    // Send Ethernet Frame?
                    if (cpu == 0)
                    {
                        pos += 6;

                        uint32_t ptr = nds.ARM9Read32(pos); pos += 4;
                        stream << "\n    ptr: " << std::hex << ptr;
                        uint16_t length = nds.ARM9Read16(pos); pos += 2;
                        stream << "\n    Length: " << std::hex << length;

                        if ((ptr & 0xFF000000) == 0x02000000)
                        {
                            uint8_t *buffer = new uint8_t[length];
                            stream << "\n    Data pointed to = ";
                            for (int i=0;i<length;i++)
                            {
                                int dataB = nds.ARM9Read8(ptr++);
                                stream << std::hex << dataB << "-";
                                buffer[i] = dataB;
                            }
                            AppendCapture(buffer, length);
                            delete buffer;
                        }
                    }
                }
                break;
            default:
                {
                    stream << "\n    Other = ";
                    for (int i=0;i<64;i++)
                    {
                        int dataB = nds.ARM9Read8(pos++);
                        stream << std::hex << dataB << "-";
                    }
                }
                break;
        }
        Log(LogLevel::Info, "%s\n", stream.str().c_str());
    }

    bool FIFOApi::ExecuteWifiRequest(const uint8_t cpu, uint32_t requestDataAddress)
    {
        // Log the Wifi to the console
        LogWifiRequest(cpu, requestDataAddress);
        return false;
    }

    bool FIFOApi::ExecuteHook(const uint8_t cpu, const uint32_t value)
    {
        /*
        uint32_t ipcRegisteredFifoHandlerFlagsAddress = 0x02ffff88 + (!cpu)?0:4;
        uint32_t ipdRegisteredFifohandlerFlags = nds.ARM9Read32(ipcRegisteredFifoHandlerFlagsAddress);
        if ((ipdRegisteredFifohandlerFlags & (1 << (value & 0x1F))) == 0)
        {
            Log(LogLevel::Info, "IPC Api Request from %u: %i is not registered\n", cpu, value & 0x1F);
            return false;
        }
        */
        switch (value & 0x1F)
        {
            case 0x14:
                return ExecuteFileIORequest(cpu, ((value >> 1) & ~0x1Fu));
            case 0x01:
                // Message Box related
            case 0x02:
                // Message Box related
                break;
            case 0x04:
                // Called in Pictochat after wifi enabled
                // Same on DS Download Play
                break;
            case 0x06:
                // Constantly used, synching or button/touch IO?                
                break;
            case 0x07:
                // Constantly used, synching or button/touch IO?
                break;
            case 0x05:
                // Constantly used in main menu
                break;
            case 0x08:
                // Constantly used in main menu
                break;
            case 0x0A:
                // Constantly used in main menu
                break;
            case 0x0D:
                // Called in Pictochat, just before wifi is enabled
                // Same on DS Download Play
                break;
            case 0x13:
                // some AES related stuff
                // one from arm9, then a remapping SWRAM occures and 
                // about 14 to 15 times from arm9, then a return from arm7 happens 
                break;
            case 0x15:
                // Called 3 times in a row every few secs in health warning screen
                break;
            case 0x16:
                // Called in DS Network
                return ExecuteWifiRequest(cpu, (value >> 6));
                break;
            case 0x17:
                // Called just after reset in DSi Menu
                {
                    uint8_t subcommand = (uint8_t)((value >> 26) & 0x3F) ;
                    uint32_t data = (value >> 6) & 0xffff ;
                    //Log(LogLevel::Debug, "IPC command related to 0x0380ffc8 from %i: cmd = %02x, data = %04x\n", cpu, subcommand, data);
                }
                break;
            case 0x18:
                // Constantly used in main menu
                break;
            default:
                //Log(LogLevel::Info, "IPC Api Request from %u: %02X, %u %07x\n", cpu, (value & 0x1F), (bool)(value & 0x20), value >> 6);
                break;
        }        
        return false;        
    }
}