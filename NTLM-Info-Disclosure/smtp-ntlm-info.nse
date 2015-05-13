local nmap = require "nmap"
local smtp = require "smtp"
local bin = require "bin"
local shortport = require "shortport"
local stdnse = require "stdnse"
local base64 = require "base64"
local smbauth = require "smbauth"
local sslcert = require "sslcert"
local string = require "string"
local table = require "table"


description = [[
This script enumerates information from remote SMTP services with NTLM
authentication enabled.

Sending a SMTP NTLM authentication request with null credentials will
cause the remote service to respond with a NTLMSSP message disclosing
information to include NetBIOS, DNS, and OS build version.
]]


---
-- @usage
-- nmap -p 25,465,587 --script smtp-ntlm-info --script-args smtp-ntlm-info.domain=domain.com <target> 
--
-- @output
-- 25/tcp   open     smtp
-- | smtp-ntlm-info:
-- |   Target_Name: ACTIVESMTP
-- |   NetBIOS_Domain_Name: ACTIVESMTP
-- |   NetBIOS_Computer_Name: SMTP-TEST2
-- |   DNS_Domain_Name: somedomain.com
-- |   DNS_Computer_Name: smtp-test2.somedomain.com
-- |   DNS_Tree_Name: somedomain.com
-- |_  Product_Version: 6.1 (Build 7601)
--
--@xmloutput
-- <elem key="Target_Name">ACTIVESMTP</elem>
-- <elem key="NetBIOS_Domain_Name">ACTIVESMTP</elem>
-- <elem key="NetBIOS_Computer_Name">SMTP-TEST2</elem>
-- <elem key="DNS_Domain_Name">somedomain.com</elem>
-- <elem key="DNS_Computer_Name">smtp-test2.somedomain.com</elem>
-- <elem key="DNS_Tree_Name">somedomain.com</elem>
-- <elem key="Product_Version">6.1 (Build 7601)</elem>


author = "Justin Cacak"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


--
-- TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
-- Ref: http://davenport.sourceforge.net/ntlm.html#appendixB
local ntlm_auth_blob = base64.enc(
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
  "\x00\x00\x00\x0f" -- OS version info end (static 0x0000000f)
  )

portrule = shortport.port_or_service({ 25, 465, 587 }, { "smtp", "smtps", "submission" })

action = function(host, port)

  local output = stdnse.output_table()

  -- Select domain name.  Typically has no implication for this purpose.
  local domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain") or host.name 
  if domain == "" then 
    -- Fall back to IP
	domain = host.ip
  end
  
  local options = {
    timeout = 10000,
    recv_before = true,
    ssl = true,
  }
  
  local status
  local socket, response = smtp.connect(host, port, options)
  if not socket then
    return
  end
  
  -- Required to send EHLO
  status, response = smtp.ehlo(socket, domain)
  if not status then
    return
  end
  
  -- Per RFC, do not attempt to upgrade to a TLS connection if already over TLS
  if ( sslcert.isPortSupported(port) == false ) then
    -- After EHLO, attempt to upgrade to a TLS connection (may not be advertised)
    -- Various implementations *require* this before accepting authentication requests
    socket:send("STARTTLS\r\n")
    local status, response = socket:receive()
    if not status then
      return
    end    
    -- Upgrade the connection if STARTTLS permitted, else continue without
    if string.match(response, "220 .*") then
	  status, response = socket:reconnect_ssl()
      if not status then
	    return
      end 
	  -- Read line after upgrading the connection or timeout trying. 
	  -- This may induce a delay, however, appears required under rare conditions
	  -- since reconnect_ssl does not support recv_before.
	  status, response = socket:receive_lines(1)
      -- Per RFC, must EHLO again after connection upgrade
	  status, response = smtp.ehlo(socket, domain)
      if not status then
        return
      end 
    end
  end
  
  socket:send("AUTH NTLM\r\n")
  status, response = socket:receive()
  if not response then
    return
  end  
  
  socket:send(ntlm_auth_blob .. "\r\n")
  status, response = socket:receive()
  if not response then
    return
  end  
  
  socket:close()

  -- Continue only if a 334 response code is returned
  if not string.match(response, "334 .*") then
    return
  end
  
  local response_decoded = base64.dec(string.match(response, "334 (.*)"))
  
  -- Continue only if NTLMSSP response is returned
  if string.match(response_decoded, "(NTLMSSP.*)") then

    -- Extract NTLMSSP response
    local data = string.match(response_decoded, "(NTLMSSP.*)")

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