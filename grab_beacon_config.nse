-- Head
local shortport = require "shortport"
local http = require "http"
local string = require "string"
local rand = require "rand"
local openssl = require "openssl"
local stdnse = require "stdnse"
local json = require "json"
local stringaux = require "stringaux"

description = [[ 
	Simple PoC script to scan and acquire CobaltStrike Beacon configurations.
	Based on :
		JPCERT :: cobaltstrikescan.py
		Sentinel-One :: parse_beacon_config.py
		Didier Stevens :: 1768.py
		Roman Emelynaov :: L8_get_beacon.py
]] 

categories = {"safe"}
author = "Wade Hickey, Zach Stanford, Allie Roblee"

-- Rule
portrule = shortport.http

-- Action
local function generate_checksum(input)
--	92 and 93 are options
	local trial = ""
	local total = 0
	local i = 1
	while (total ~= input) do
		total = 0
		trial = rand.random_string(4,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
		for i = 1, 4 do
			total = (total + string.byte(string.sub(trial,i,i))) % 256
			i = i + 1
		end
	end
	return "/" .. trial

end

local function xor_finder()

end

local function extract_value(key_name, format, hex_identifier, content)
	local port_index = string.find(content,"\x00\x02\x00\x01\x00\x02",1,true)
	if (port_index) then
		local port = string.unpack(">H",content,port_index + 6)
		return port
	end


end

local function parse_field(key_name,contents,hex_flag,format)
	local index = ""

	local beacon_types = {}
	beacon_types[0] = "0 (HTTP)"
	beacon_types[1] = "1 (Hybrid HTTP DNS)"
	beacon_types[2] = "2 (SMB)"
	beacon_types[3] = "3 (Unknown)"
	beacon_types[4] = "4 (TCP)"
	beacon_types[5] = "5 (Unknown)"
	beacon_types[6] = "6 (Unknown)"
	beacon_types[7] = "7 (Unknown)"
	beacon_types[8] = "8 (HTTPS)"
	beacon_types[9] = "9 (Unkown)"
	beacon_types[10] = "10 (Bind TCP)"

	local access_types = {}
	access_types[0] = "0 (Unknown)"
	access_types[1] = "1 (Use direct connection)"
	access_types[2] = "2 (Use IE settings)"
	access_types[3] = "3 (Unknown)"
	access_types[4] = "4 (Use proxy server)"

	if key_name == "Beacon Type" then
		index = string.find(contents,hex_flag,1,true)
		if index == nil then
			return nil
		end
		return beacon_types[string.unpack(format,contents,index + string.len(hex_flag))]

	elseif key_name == "Proxy Access Type" then
		index = string.find(contents,hex_flag,1,true)

		if index == nil then
			return nil
		end
		return access_types[string.unpack(format,contents,index + string.len(hex_flag))]
	
	elseif key_name == "DNS Idle" then
		index = string.find(contents,hex_flag,1,true)
		
		if index == nil then
			return nil
		end

		local address = ""
		address = address .. string.unpack(format,contents,index + string.len(hex_flag) + 0) .. "."
		address = address .. string.unpack(format,contents,index + string.len(hex_flag) + 1) .. "."
		address = address .. string.unpack(format,contents,index + string.len(hex_flag) + 2) .. "."
		address = address .. string.unpack(format,contents,index + string.len(hex_flag) + 3)
		return address
	
	else
		index = string.find(contents,hex_flag,1,true)

		if index == nil then
			return nil
		end
		return string.unpack(format,contents,index + string.len(hex_flag))
	end
end


local function grab_beacon(response, output, prefix)

	local test_string = string.char(0xFF) .. string.char(0xFF) .. string.char(0xFF)
	local return_string = ""
	if (response.status == 200) then
		if (http.response_contains(response, test_string, true)) then
			local offset = string.find(response.rawbody, test_string) + 3
			local endian = "<I"
			local key = string.unpack(endian,response.rawbody,offset)
			local size = string.unpack(endian,response.rawbody,offset+4) ~ key
			local c = string.unpack(endian,response.rawbody,offset+8) ~ key
			local mz = c & 0xffff
			local x = math.floor(2 + (offset / 4))
			local y = math.floor((string.len(response.rawbody)/4)-4)
			local repacked  = ""
			local repacked2 = ""
			for var=x,y do
				a = string.unpack(endian,response.rawbody,var*4)
				b = string.unpack(endian,response.rawbody,var*4+4)
				z = tonumber(a) ~ tonumber(b) 
				repacked = repacked .. string.pack(endian,z ~ 0x2e2e2e2e) --version 4
				repacked2 = repacked2 .. string.pack(endian,z ~ 0x69696969) --version 3
			end

			output[prefix .. "beacon_type"] = parse_field("Beacon Type",repacked,"\x00\x01\x00\x01\x00\x02",">H")
			if not output[prefix .. "beacon_type"] then
				output[prefix .. "beacon_type"] = parse_field("Beacon Type",repacked2,"\x00\x01\x00\x01\x00\x02",">H")
				repacked = repacked2
			end

			output[prefix .. "port"] = parse_field("Port",repacked,"\x00\x02\x00\x01\x00\x02",">H")
			output[prefix .. "polling"] = parse_field("Polling",repacked,"\x00\x03\x00\x02\x00\x04",">I")
			output[prefix .. "jitter"] = parse_field("Jitter",repacked,"\x00\x05\x00\x01\x00\x02",">H")
			output[prefix .. "max_dns"] = parse_field("Max DNS",repacked,"\x00\x06\x00\x01\x00\x02",">H")
			output[prefix .. "c2_server"] = parse_field("C2 Server",repacked,"\x00\x08\x00\x03\x01\x00","z")
			local tmp = stringaux.strsplit(",%s*", parse_field("C2 Server",repacked,"\x00\x08\x00\x03\x01\x00","z"))
			output[prefix .. "c2_host"] = tmp[1]
			output[prefix .. "c2_path"] = tmp[2]
			output[prefix .. "user_agent"] = parse_field("User Agent",repacked,"\x00\x09\x00\x03\x00\x80","z")
			output[prefix .. "http_method_path_2"] = parse_field("HTTP Method Path 2",repacked,"\x00\x0a\x00\x03\x00\x40","z")
			output[prefix .. "header_1"] = parse_field("Header 1",repacked,"\x00\x0c\x00\x03\x01\x00","z")
			output[prefix .. "header_2"] = parse_field("Header 2",repacked,"\x00\x0d\x00\x03\x01\x00","z")
			output[prefix .. "injection_process"] = parse_field("Injection Process",repacked,"\x00\x0e\x00\x03\x00\x40","z")
			output[prefix .. "pipe_name"] = parse_field("Pipe Name",repacked,"\x00\x0f\x00\x03\x00\x80","z")
			output[prefix .. "year"] = parse_field("Year",repacked,"\x00\x10\x00\x01\x00\x02",">H")
			output[prefix .. "month"] = parse_field("Month",repacked,"\x00\x11\x00\x01\x00\x02",">H")
			output[prefix .. "day"] = parse_field("Day",repacked,"\x00\x12\x00\x01\x00\x02",">H")
			output[prefix .. "dns_idle"] = parse_field("DNS Idle",repacked,"\x00\x13\x00\x02\x00\x04","B")
			output[prefix .. "dns_sleep"] = parse_field("DNS Sleep",repacked,"\x00\x14\x00\x02\x00\x04",">H")
			output[prefix .. "method_1"] = parse_field("Method 1",repacked,"\x00\x1a\x00\x03\x00\x10","z")
			output[prefix .. "method_2"] = parse_field("Method 2",repacked,"\x00\x1b\x00\x03\x00\x10","z")
			output[prefix .. "spawn_to_x86"] = parse_field("Spawn To x86",repacked,"\x00\x1d\x00\x03\x00\x40","z")
			output[prefix .. "spawn_to_x64"] = parse_field("Spawn To x64",repacked,"\x00\x1e\x00\x03\x00\x40","z")
			output[prefix .. "proxy_hostname"] = parse_field("Proxy Hostname",repacked,"\x00\x20\x00\x03\x00\x80","z")
			output[prefix .. "proxy_username"] = parse_field("Proxy Username",repacked,"\x00\x21\x00\x03\x00\x40","z")
			output[prefix .. "proxy_password"] = parse_field("Proxy Password",repacked,"\x00\x22\x00\x03\x00\x40","z")
			output[prefix .. "proxy_access_type"] = parse_field("Proxy Access Type",repacked,"\x00\x23\x00\x01\x00\x02","z")
			output[prefix .. "create_remote_thread"] = parse_field("CreateRemoteThread",repacked,"\x00\x24\x00\x01\x00\x02","z")
			output[prefix .. "watermark"] = parse_field("Watermark",repacked,"\x00\x25\x00\x02\x00\x04",">I")
			output[prefix .. "c2_host_header"] = parse_field("C2 Host Header",repacked,"\x00\x36\x00\x03\x00\x80","z")

			if (stdnse.get_script_args("save")) == "true" then
				local write_out = io.open(stdnse.tohex(openssl.digest("sha256",response.body)) .. ".bin","w")
				io.output(write_out)
				io.write(response.body)
			end
		end	
	end
end


action = function(host,port)
	local json_output = {}

	local uri_x86 = generate_checksum(92)
	local uri_x64 = generate_checksum(93)

	local http_options = {}
	http_options["header"] = {}
	http_options["header"]["User-Agent"] = ""

	local response_x86 = http.get(host,port,uri_x86,http_options)
	if response_x86.body == nil then
		return "No Valid Response"
	end

	json_output['x86_uri_queried'] = uri_x86
	json_output['x86_sha256'] = stdnse.tohex(openssl.digest("sha256",response_x86.body))
	json_output['x86_sha1'] = stdnse.tohex(openssl.digest("sha1",response_x86.body))
	json_output['x86_md5'] = stdnse.tohex(openssl.digest("md5",response_x86.body))
	json_output['x86_time'] = stdnse.clock_ms()
	grab_beacon(response_x86, json_output, 'x86_')

	local response_x64 = http.get(host,port,uri_x64,http_options)

	if response_x64.body == nil then
		return "No Valid Response"
	end

	json_output['x64_uri_queried'] = uri_x64
	json_output['x64_sha256'] = stdnse.tohex(openssl.digest("sha256",response_x64.body))
	json_output['x64_sha1'] = stdnse.tohex(openssl.digest("sha1",response_x64.body))
	json_output['x64_md5'] = stdnse.tohex(openssl.digest("md5",response_x64.body))
	json_output['x64_time'] = stdnse.clock_ms()
	grab_beacon(response_x64, json_output, 'x64_')

	json_output = json.generate(json_output)
	return json_output
end