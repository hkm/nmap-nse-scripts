local nmap = require "nmap"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local shortport = require "shortport"

description = [[
The Belkin Wemo Switch is a network enabled power outlet. This scripts obtains
information from Belkin Wemo Switch including nearby wireless networks and the
current switch state (ON/OFF).

There is a separate NSE script that may be used for changing the switch state.
No authentication is required.

Valid on Belkin Wemo Switch version WeMo_WW_2.00.10966.PVT-OWRT-SNS on 6/22/17

References:
* http://websec.ca/blog/view/Belkin-Wemo-Switch-NMap-Scripts
* https://www.tripwire.com/state-of-security/featured/my-sector-story-root-shell-on-the-belkin-wemo-switch/
* https://www.exploitee.rs/index.php/Belkin_Wemo
]]

---
-- @usage nmap -p49152,49153,49154 --script wemo-info <target>
-- @usage nmap -p49152,49153,49154 --script info <target>
--
-- @output
-- | wemo-info:
-- |   friendlyName: : Wemo Switch
-- |   deviceType: urn:Belkin:device:controllee:1
-- |   manufacturer: Belkin International Inc.
-- |   manufacturerURL: http://www.belkin.com
-- |   modelDescription: Belkin Plugin Socket 1.0
-- |   modelName: Socket
-- |   modelNumber: 1.0
-- |   modelURL: http://www.belkin.com/plugin/
-- |   serialNumber: 220333K0203A4E
-- |   UDN: uuid:Socket-1_0-220333K0203A4E
-- |   UPC: 123456789
-- |   macAddress: EC1A59EE48E3
-- |   firmwareVersion: WeMo_WW_2.00.10966.PVT-OWRT-SNS
-- |   iconVersion: 0|49154
-- |   binaryState: 1
-- |   Switch is currently turned: ON
-- |   Nearby wireless networks: Page:1/1/8$
-- | INFINITUMewld|3|10|WPA1PSKWPA2PSK/TKIPAES,
-- | INFINITUMuefg|5|39|WPA1PSKWPA2PSK/TKIPAES,
-- | Visita Cozumel FTW|5|0|OPEN/NONE,
-- | PVGP-2|6|0|WPA1PSKWPA2PSK/TKIPAES,
-- | INFINITUMD9E758|8|65|WPA2PSK/AES,
-- | INFINITUMu8dn|10|0|WPA1PSKWPA2PSK/TKIPAES,
-- | INFINITUM9043|11|100|WPA2PSK/AES,
-- |_INFINITUM082E37|11|0|WPA1PSKWPA2PSK/TKIPAES,
--
---

author = "Pedro Joaquin <pjoaquin()websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"info", "safe"}

portrule = shortport.portnumber({49152,49153,49154})

local function GetInformation(host, port)
  local uri = '/setup.xml'
  local response = http.get(host, port, uri)

  if response['status-line'] and response['status-line']:match("200 OK") then
    --Verify parsing of XML from /setup.xml
    local deviceType = response['body']:match("<deviceType>([^<]*)</deviceType>")
    if not deviceType then
      stdnse.debug1("Problem with XML parsing")
      return nil,"Problem with XML parsing"
    end
	
    --Parse information from /setup.xml
    local output = stdnse.output_table()
    local keylist = {"friendlyName","deviceType","manufacturer","manufacturerURL","modelDescription", "modelName","modelName","modelNumber","modelURL","serialNumber","UDN","UPC","macAddress","firmwareVersion","iconVersion","binaryState"}
    for _,key in ipairs(keylist) do
      stdnse.debug1("Looking for : "..key)
      output[key] = response['body']:match("<"..key..">([^<]*)</"..key..">")
    end
	
    --Identify current Switch state
    local bstate="Switch is currently turned"
    if output["binaryState"] == "1" then
      output[bstate] = "ON"
    else
      output[bstate] = "OFF"
    end

    --Post request to obtain nearby wireless network information
    local req = '<?xml ?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetApList xmlns:u="urn:Belkin:service:WiFiSetup1:1"></u:GetApList></s:Body></s:Envelope>'
    local path = "/upnp/control/WiFiSetup1"
	local options = {header={["SOAPACTION"]='"urn:Belkin:service:WiFiSetup1:1#GetApList"', ["Content-Type"]="text/xml"}}
	local result = http.post( host, port, path, options, nil, req)
	stdnse.debug1("Status : %s", result['status-line'] or "No Response")
    if(result['status'] ~= 200 or result['content-length'] == 0) then
	  stdnse.debug1("Status : %s", result['status-line'] or "No Response")
      return false, "Couldn't download file: " .. path
	else
	  output["Nearby wireless networks"] = result['body']:match("<ApList>([^<]*)</ApList>")
    end

    return output

  else
    stdnse.debug1("Could not open '%s'", uri)
    return false, "Could not open "..uri
  end
end

action = function(host,port)
  return GetInformation(host, port)
end
