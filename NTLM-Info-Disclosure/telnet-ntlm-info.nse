local nmap = require "nmap"
local bin = require "bin"
local shortport = require "shortport"
local stdnse = require "stdnse"
local smbauth = require "smbauth"
local string = require "string"
local table = require "table"


description = [[
This script enumerates information from remote Microsoft Telnet services with NTLM
authentication enabled.

Sending a MS-TNAP NTLM authentication request with null credentials will cause the
remote service to respond with a NTLMSSP message disclosing information to include
NetBIOS, DNS, and OS build version.
]]


---
-- @usage
-- nmap -p 23 --script telnet-ntlm-info <target>
--
-- @output
-- 23/tcp   open     telnet
-- | telnet-ntlm-info:
-- |   Target_Name: ACTIVETELNET
-- |   NetBIOS_Domain_Name: ACTIVETELNET
-- |   NetBIOS_Computer_Name: HOST-TEST2
-- |   DNS_Domain_Name: somedomain.com
-- |   DNS_Computer_Name: host-test2.somedomain.com
-- |   DNS_Tree_Name: somedomain.com
-- |_  Product_Version: 5.1 (Build 2600)
--
--@xmloutput
-- <elem key="Target_Name">ACTIVETELNET</elem>
-- <elem key="NetBIOS_Domain_Name">ACTIVETELNET</elem>
-- <elem key="NetBIOS_Computer_Name">HOST-TEST2</elem>
-- <elem key="DNS_Domain_Name">somedomain.com</elem>
-- <elem key="DNS_Computer_Name">host-test2.somedomain.com</elem>
-- <elem key="DNS_Tree_Name">somedomain.com</elem>
-- <elem key="Product_Version">5.1 (Build 2600)</elem>


author = "Justin Cacak"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


-- 
-- Create MS-TNAP Login Packet (Option Command IS)
-- Ref: http://msdn.microsoft.com/en-us/library/cc247789.aspx
local tnap_login_packet = 
  "\xff" .. --
  "\xfa" .. -- Sub-option (250)
  "\x25" .. -- Subcommand: auth option
  "\x00" .. -- Auth Cmd: IS (0)
  "\x0f" .. -- Auth Type: NTLM (15)
  "\x00" .. -- Who: Mask client to server (0)
  "\x00" .. -- Command: NTLM_NEGOTIATE (0)
  "\x28\x00\x00\x00" .. -- NTLM_DataSize (4 bytes, little-endian)
  "\x02\x00\x00\x00" .. -- NTLM_BufferType (4 bytes, little-endian)
  "NTLMSSP\x00" ..
  "\x01\x00\x00\x00" .. -- NTLM Type 1 Message
  bin.pack("<I", --flags
    0x00000001 + -- Negotiate Unicode
    0x00000002 + -- Negotiate OEM strings
    0x00000004 + -- Request Target
    0x00000200 + -- Negotiate NTLM
    0x00008000 + -- Negotiate Always Sign
    0x00080000 + -- Negotiate NTLM2 Key
    0x02000000 + -- Unknown
    0x20000000 + -- Negotiate 128
    0x80000000 -- Negotiate 56
    ) ..
  string.rep("\x00", 16) .. -- Supplied Domain and Workstation (empty)
  bin.pack("CC<S", -- OS version info
    6, 1, 7601) .. -- 6.1.7601, Win 7 SP1 or Server 2008 R2 SP1
  "\x00\x00\x00\x0f" ..
  "\xff\xf0" -- Sub-option End

portrule = shortport.port_or_service({23}, {"telnet"})
 
action = function(host, port)

  local output = stdnse.output_table()

  local socket = nmap.new_socket()
  socket:set_timeout(10000)
  socket:connect(host.ip, port.number)
  
  socket:send(tnap_login_packet)
  local status, response = socket:receive() 
  if not status then
    return
  end   
  
  -- Server will respond, ignore this message, get next one 
  status, response = socket:receive() 
  if not response then
    return
  end   
  
  socket:close()
  
  -- Continue only if NTLMSSP response is returned.
  -- Verify that the response is terminated with Sub-option End values as various
  -- non Microsoft telnet implementations support NTLM but do not return valid data.
  if string.match(response, "(NTLMSSP.*)\xff\xf0") then
  
    -- Extract NTLMSSP response
    local data = string.match(response, "(NTLMSSP.*)\xff\xf0")

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