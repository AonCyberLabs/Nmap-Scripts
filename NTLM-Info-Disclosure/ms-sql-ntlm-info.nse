local nmap = require "nmap"
local bin = require "bin"
local shortport = require "shortport"
local stdnse = require "stdnse"
local smbauth = require "smbauth"
local string = require "string"
local table = require "table"


description = [[
This script enumerates information from remote Microsoft SQL services with NTLM
authentication enabled.

Sending a MS-TDS NTLM authentication request with an invalid domain and null
credentials will cause the remote service to respond with a NTLMSSP message
disclosing information to include NetBIOS, DNS, and OS build version.
]]


---
-- @usage
-- nmap -p 1433 --script ms-sql-ntlm-info <target>
--
-- @output
-- 1433/tcp   open     ms-sql-s
-- | ms-sql-ntlm-info:
-- |   Target_Name: ACTIVESQL
-- |   NetBIOS_Domain_Name: ACTIVESQL
-- |   NetBIOS_Computer_Name: DB-TEST2
-- |   DNS_Domain_Name: somedomain.com
-- |   DNS_Computer_Name: db-test2.somedomain.com
-- |   DNS_Tree_Name: somedomain.com
-- |_  Product_Version: 6.1 (Build 7601)
--
--@xmloutput
-- <elem key="Target_Name">ACTIVESQL</elem>
-- <elem key="NetBIOS_Domain_Name">ACTIVESQL</elem>
-- <elem key="NetBIOS_Computer_Name">DB-TEST2</elem>
-- <elem key="DNS_Domain_Name">somedomain.com</elem>
-- <elem key="DNS_Computer_Name">db-test2.somedomain.com</elem>
-- <elem key="DNS_Tree_Name">somedomain.com</elem>
-- <elem key="Product_Version">6.1 (Build 7601)</elem>


author = "Justin Cacak"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


-- 
-- Create MS-TDS Login Packet
-- Ref 1: http://www.freetds.org/tds.html
-- Ref 2: http://msdn.microsoft.com/en-us/library/dd304523.aspx
local tds7_login_packet = 
  "\x10" .. -- TDS7 Packet Type (0x10 = TDS 7.0 Login Packet)
  "\x01" .. -- Last Packet Indicator (0x01 = true)
  bin.pack(">S", 186) .. -- Total Packet Length
  "\x00\x00" .. -- Channel (0)
  "\x01" .. -- Packet Number (1)
  "\x00" .. -- Window (0)
  bin.pack("I", 178) .. -- Login Packet Length 
  "\x01\x00\x00\x71" .. -- TDS Version (7.1)
  "\x00\x00\x00\x00" .. -- Packet Size (0)
  "\x07\x00\x00\x00" .. -- Client Version
  "\x7b\x00\x00\x00" .. -- Client PID (123)
  "\x00\x00\x00\x00" .. -- Connection ID (0)
  "\xe0" .. -- Option Flags 1 (0xe0)
  "\x83" .. -- Option Flags 2 (0x83)
  "\x00" .. -- SQL Type Flags (0x00)
  "\x00" .. -- Reserved Flags (0x00)
  "\x00\x00\x00\x00" .. -- Time Zone (0x00000000)
  "\x00\x00\x00\x00" .. -- Collation (0x00000000)
  bin.pack("S", 86) .. -- Client Name Offset
  bin.pack("S", 8) .. -- Client Name Length
  bin.pack("S", 102) .. -- Username Offset
  bin.pack("S", 0) .. -- Username Length
  bin.pack("S", 102) .. -- Password Offset
  bin.pack("S", 0) .. -- Password Length 
  bin.pack("S", 102) .. -- App Name Offset
  bin.pack("S", 4) .. -- App Name Length  
  bin.pack("S", 110) .. -- Server Name Offset
  bin.pack("S", 11) .. -- Server Name Length
  bin.pack("S", 0) .. -- Unknown Offset
  bin.pack("S", 0) .. -- Unknown Length
  bin.pack("S", 124) .. -- Library Name Offset
  bin.pack("S", 4) .. -- Library Name Length  
  bin.pack("S", 132) .. -- Locale Offset
  bin.pack("S", 0) .. -- Locale Length  
  bin.pack("S", 132) .. -- Database Name Offset
  bin.pack("S", 0) .. -- Database Length
  "\x00\x00\x00\x00\x00\x00" .. -- MAC (INT8[6])
  bin.pack("S", 132) .. -- Auth Offset
  bin.pack("S", 46) .. -- Auth Length
  bin.pack("S", 178) .. -- Next Position (same as login packet length)
  "\x00\x00" .. -- Empty (INT16)
  "\x43\x00\x4c\x00\x49\x00\x45\x00\x4e\x00\x54\x00\x30\x00\x31\x00" .. -- Client Name (CLIENT01)
  "\x6a\x00\x54\x00\x44\x00\x53\x00" .. -- App Name (jTDS)
  "\x31\x00\x2e\x00\x32\x00\x2e\x00\x33\x00\x2e\x00\x34\x00" .. -- Server Name (1.2.3.4)
  "\x6a\x00\x54\x00\x44\x00\x53\x00" .. -- Library Name (jTDS)
  "NTLMSSP\x00" .. -- NTLMSSP Identifier
  "\x01\x00\x00\x00" .. -- NTLM Type 1 Message
  "\x05\xb2\x08\x00" .. -- Set Flags
  bin.pack("S", 14) .. -- Calling Workstation Length
  bin.pack("S", 14) .. -- Calling Workstation Max Length
  bin.pack("I", 32) .. -- Calling Workstation Offset
  "\x00\x00\x00\x00\x20\x00\x00\x00" .. -- Calling Workstation Name = NULL
  "NO_SUCH_DOMAIN" -- Set Domain: "NO_SUCH_DOMAIN"
 
portrule = shortport.port_or_service({1433}, {"ms-sql-s"})
 
action = function(host, port)

  local output = stdnse.output_table()

  local socket = nmap.new_socket()
  socket:set_timeout(10000)
  socket:connect(host.ip, port.number)
  socket:send(tds7_login_packet)
  local status, response = socket:receive() 
  if not response then
    return
  end   
  
  socket:close()
  
  -- Continue only if NTLMSSP response is returned
  if string.match(response, "(NTLMSSP.*)") then

    -- Extract NTLMSSP response
    local data = string.match(response, "(NTLMSSP.*)")

    -- Leverage smbauth.get_host_info_from_security_blob() for decoding
    local ntlm_decoded = smbauth.get_host_info_from_security_blob(data)

    -- Target Name will always be returned under any implementation
    output.Target_Name = ntlm_decoded.target_realm

    -- Display information returned & ignore responses with null values
    if ntlm_decoded.netbios_domain_name and #ntlm_decoded.netbios_domain_name > 0 then
      output.NetBIOS_Domain_Name = ntlm_decoded.netbios_domain_name
    end

    if ntlm_decoded.netbios_computer_name and #ntlm_decoded.netbios_computer_name > 0 then
      output.NetBIOS_Computer_Name = ntlm_decoded.netbios_computer_name
    end

    if ntlm_decoded.dns_domain_name and #ntlm_decoded.dns_domain_name > 0 then
      output.DNS_Domain_Name = ntlm_decoded.dns_domain_name
    end

    if ntlm_decoded.fqdn and #ntlm_decoded.fqdn > 0 then
      output.DNS_Computer_Name = ntlm_decoded.fqdn
    end

    if ntlm_decoded.dns_forest_name and #ntlm_decoded.dns_forest_name > 0 then
      output.DNS_Tree_Name = ntlm_decoded.dns_forest_name
    end

    -- Query product build version (typically OS version under Windows)
    -- Compute offset for Target Name
    local target_offset = data:sub(17, 21)
    local pos, target_offset_dec = bin.unpack("<I", target_offset)

    if #data > 48 and target_offset_dec ~= 48 then
      -- Get product major version
      local major_version = data:sub(49, 50)
      local pos, major_version_dec = bin.unpack("C", major_version)

      -- Get product minor version
      local minor_version = data:sub(50, 51)
      local pos, minor_version_dec = bin.unpack("C", minor_version)

      -- Get product build version
      local build = data:sub(51, 53)
      local pos, build_dec = bin.unpack("<S", build)

      output.Product_Version = major_version_dec .. "." .. minor_version_dec .. " (Build " .. build_dec .. ")"
    end

    return output

  end

end