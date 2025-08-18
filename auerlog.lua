--[[
auerlog.lua
Copyright (C) 2017-2023  Auerswald GmbH & Co. KG

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
--]]

local p_auerlog_legacy = Proto("auerlog_legacy","Auerswald Log Old");
local p_auerlog = Proto("auerlog","Auerswald Log");

local OUTPUT_OFF      = 0
local OUTPUT_DEBUG    = 1
local OUTPUT_INFO     = 2
local OUTPUT_WARN     = 3
local OUTPUT_ERROR    = 4

local AUERLOG_LEVEL_NONE    = 0
local AUERLOG_LEVEL_ERROR   = 1
local AUERLOG_LEVEL_WARNING = 2
local AUERLOG_LEVEL_INFO    = 3
local AUERLOG_LEVEL_DEBUG   = 4
local AUERLOG_LEVEL_EDEBUG  = 5
local AUERLOG_LEVEL_XDEBUG  = 6

local MSG_TYPE_GENERIC = 0
local MSG_TYPE_SIP     = 1

local level_tab = {
  [0] = "Off",
  [1] = "Error",
  [2] = "Warning",
  [3] = "Info",
  [4] = "Debug",
  [5] = "EDebug",
  [6] = "XDebug"
}

local MAX_STR_LEN = 160

local c2t = {}
local t2c = {}
local c2i = {}
local i2c = {}

-- create the fields for our "protocol"
local pfields = {
  pid = ProtoField.int32("auerlog.Thread_id","Thread_id"),
  tgid = ProtoField.int32("auerlog.Proc_id","Proc_id"),
  procname = ProtoField.string("auerlog.Process","Process"),
  threadname = ProtoField.string("auerlog.Thread","Thread"),
  category = ProtoField.string("auerlog.Category","Category"),
  level = ProtoField.uint32("auerlog.Level","Level",base.DEC,level_tab),
  line = ProtoField.uint32("auerlog.Line","Line"),
  seqno = ProtoField.uint32("auerlog.SeqNo","SeqNo"),
  classname = ProtoField.string("auerlog.Class_or_file","Class_or_file"),
  methodname = ProtoField.string("auerlog.Method_or_func","Method_or_func"),
  msg = ProtoField.string("auerlog.Msg","Msg",base.UNICODE),
  protobuf = ProtoField.string("auerlog.PROTOBUF","PROTOBUF"),
  jsonrpc = ProtoField.string("auerlog.JSON","JSON"),
  src_port = ProtoField.uint16("tcp.srcport","Source Port"),
  dst_port = ProtoField.uint16("tcp.dstport","Destination Port"),
  ip_version = ProtoField.uint16("ip.version","Version"),
  ip_proto = ProtoField.uint8("ip.proto","Protocol"),
  src_ip6 = ProtoField.ipv6("auerlog.src_addr","Source address",base.HEX, nil),
  dst_ip6 = ProtoField.ipv6("auerlog.dst_addr","Destination address",base.HEX, nil),
  src_ip = ProtoField.ipv4("ip.src_addr","Source address", base.DEC, nil),
  dst_ip = ProtoField.ipv4("ip.dst_addr","Destination address", base.DEC, nil),
  crv = ProtoField.string("auerlog.CRV","CRV"),
  task = ProtoField.string("auerlog.TASK","TASK"),
  call_id = ProtoField.string("sip.Call-ID","Call-ID"),
  unused = ProtoField.none("auerlog.unused","(Unused)")
}

local efields = {
  sip_call_id = Field.new("sip.Call-ID")
}

-- load preferences
p_auerlog.prefs.shorten_msg = Pref.bool("Remove redundant information", true,
                                    "Remove redundant information for the Msg part so only relevant parts remain in there e.g. file names, function names, etc")

p_auerlog.prefs.link_calls = Pref.bool("Link CRV, Task and Call-ID", true,
                                    "Enable code to create and track linking Information to follow and distinguish multiple calls more effectively")

p_auerlog.prefs.old_type = Pref.bool("Support old logs", false,
                                    "Register USER0 and USER1. These Protocol IDs were used before before a dedicated ID was assigned. If you need to turn this on to display properly, that system is seriously outdated and needs to be updated! ")

-- add the field to the protocol
p_auerlog.fields = {}
for _,v in pairs(pfields) do
  table.insert(p_auerlog.fields,v);
end

local function splitLines(line,maxlen)
  local res = {}
  local maxlen = maxlen or MAX_STR_LEN
  while line:len() > maxlen do
  local cnt = 1
  local msg_part = maxlen
    while cnt < (maxlen / 4) do
      local ch = line:sub(msg_part-cnt,msg_part-cnt)
      -- check for space, comma and semicolon
      if ch:byte() == 32 or ch:byte() == 44 or ch:byte() == 59 then
        msg_part = msg_part - cnt
        break;
      end
      cnt = cnt + 1
    end
    table.insert(res,line:sub(1,msg_part))
    line = line:sub(msg_part+1)
  end
  table.insert(res,line)
  return res
end

local function tadd(tree,fieldname,data,type)
  tree:add(pfields[fieldname],data,data[type or "string"](data))
end

local function addThreadData(tree,data)
  tadd(tree,"tgid",data:range(4,4),"int")
  tadd(tree,"procname",data:range(8,16))
  thread_id = data:range(0,4):int()
  proc_id = data:range(4,4):int()
  if (proc_id ~= thread_id) then
    tadd(tree,"pid",data:range(0,4),"int")
    tadd(tree,"threadname",data:range(24,16))
  end
end

-- addIPTree(tree, ip_data[, pinfo])
-- ip_data layout (yours): 
--   byte 0:   IP version (4 or 6)
--   bytes 2..: addresses/ports as you described
local function addIPTree(tree, ip_data, pinfo)
  local ip_version = ip_data(0,1):uint()
  local is_v6 = (ip_version == 6)
  local protocol = 6  -- TCP (generated)
  local total_len = 38

  -- create the IP subtree first (use TvbRange, not :tvb())
  local iptree = tree:add(p_auerlog, ip_data:range(0, total_len),
                          is_v6 and "Internet Protocol Version 6" or "Internet Protocol Version 4")

  iptree:add(pfields.ip_version, ip_data(0,1))
  iptree:add(pfields.ip_proto, protocol):set_generated(true)

  local src_txt, dst_txt

  if is_v6 then
    local src_r = ip_data:range(2, 16)
    local dst_r = ip_data:range(20, 16)

    -- Proper IPv6-typed fields
    iptree:add(pfields.src_ip6, src_r)
    iptree:add(pfields.dst_ip6, dst_r)

    -- Optional: inform Wireshark’s plumbing
    if pinfo then
      pinfo.src = src_r:ipv6()
      pinfo.dst = dst_r:ipv6()
    end

    src_txt = tostring(src_r:ipv6())
    dst_txt = tostring(dst_r:ipv6())
  else
    local src_r = ip_data:range(2, 4)
    local dst_r = ip_data:range(20, 4)
	local src_u = ip_data:range(6, 12)
	local dst_u = ip_data:range(24, 12)

    -- Proper IPv4-typed fields
    iptree:add(pfields.src_ip, src_r)
    iptree:add(pfields.unused, src_u):set_hidden()
    iptree:add(pfields.dst_ip, dst_r)
    iptree:add(pfields.unused, dst_u):set_hidden()
    if pinfo then
      pinfo.src = src_r:ipv4()
      pinfo.dst = dst_r:ipv4()
    end

    src_txt = tostring(src_r:ipv4())
    dst_txt = tostring(dst_r:ipv4())
  end

  -- Update the subtree title to show Src/Dst nicely
  iptree:set_text(string.format("Internet Protocol Version %d, Src: %s, Dst: %s",
                                ip_version, src_txt or "", dst_txt or ""))

  -- TCP subtree (your ports are at 18 and 36 in both v4/v6 layouts)
  local sport = ip_data:range(18, 2):uint()
  local dport = ip_data:range(36, 2):uint()
  local tcptree = tree:add(p_auerlog, ip_data:range(18, 20), "Transmission Control Protocol")
  if sport and dport then
  tcptree:set_text(string.format("Transmission Control Protocol, SrcPort: %u, DstPort: %u",
                                sport, dport))
  end
  tcptree:add(pfields.src_port, ip_data:range(18, 2))
  tcptree:add(pfields.dst_port, ip_data:range(36, 2))
  if pinfo then
	pinfo.src_port = sport
	pinfo.dst_port = dport
  end

end

local function addSIPTree(tree,sip_data,pinfo)
  Dissector.get("sip"):call(sip_data:tvb(),pinfo,tree) 
end

function p_auerlog.dissector(buf,pinfo,tree)
  pinfo.cols.protocol = "AUERLOG"
  
  local subtree = tree:add(p_auerlog,buf,"Data")
  subtree:set_len(buf:len())
  local sadd = function(fieldname,start,len,type)
    local data = buf(start,len)
    subtree:add(pfields[fieldname],data,data[type or "string"](data))
  end
  
  local msg_start = 150 
  local msg_len = buf:len() - msg_start - 1
  local base = 38
  local offset = 0
  local msg_type = buf(0,2):uint()
  subtree:add(pfields.unused, buf(0,2)):set_hidden() -- Message Type can be identified by protocol displayed

  sadd("level",2,4,"uint")
  sadd("category",6,32,"string")
  local msg_category = buf(6,32):string()
  
  if (msg_type == MSG_TYPE_SIP) then
    local crv
    addIPTree(tree,buf(base+offset,38),pinfo)
    addThreadData(subtree,buf(base+38,40))
	-- unused padding
	local offset = base+38+40
	subtree:add(pfields.unused, buf(offset,msg_start-offset )):set_hidden()
    -- pass rest to sip	
    subtree:add(pfields["methodname"],"SIP"):set_generated(true)
    local sip_data = buf(msg_start,msg_len)
    addSIPTree(tree,sip_data,pinfo)
    local call_id = efields.sip_call_id.list()    
    -- print( "SIP-Call-ID: " .. tostring(call_id) )
	if p_auerlog.prefs.link_calls then
		if i2c[efields.call_id] then 
		  crv = i2c[efields.call_id]
		  subtree:add(pfields.crv,crv):set_generated(true)
		end
		if crv and c2t[crv] then
		  subtree:add(pfields.task,c2t[crv]):set_generated(true)
		end
	end

    return
  end
 
  if (msg_type ~= MSG_TYPE_GENERIC) then
    pinfo.cols.info:append("Unknown Type")
    return
  end

  if (buf(base+40,1):uint() ~= 0) then
    sadd("classname",base+40,32)
  end

  sadd("methodname",base+72,32)
  sadd("line",base+104,4,"uint")
  sadd("seqno",base+108,4,"uint")

  local methodname = buf(base+72,32):string()
  methodname = methodname:match("[^%z]*")
    
  -- local message,proto_start,proto_len,json_start,json_len
  local message = buf(msg_start,msg_len):string(ENC_UTF_8)
  
  if msg_category:match("SYSLOG_DAEMON") then 
    -- Msg part is formated as "process_name[process_id]: Msg"
    local my_proc_name 
    local my_process_len = 0
    local my_proc_id = "0"
    local my_skip_len = 0
    local rest = ""
    my_proc_name, my_process_len, my_proc_id, my_skip_len, rest = message:match("^(%w+)()%[(%d+)%]:%s()(.*)")
    -- print ("->" .. my_proc_name .."<- len(" .. my_process_len .. ") ID:" .. my_proc_id .. " Total_len:" .. my_skip_len )
    if my_skip_len then
      sadd("procname", msg_start, my_process_len-1, "string")
      subtree:add(pfields.tgid,math.floor(tonumber(my_proc_id)))
      msg_start = msg_start + (my_skip_len -1)
      msg_len = msg_len - (my_skip_len -1)
      message = buf(msg_start,msg_len):string(ENC_UTF_8)
    end
  else
    addThreadData(subtree,buf(base+0,40))
  end

  -- check for #proto prefix, if found, replace it with a tag
  local protobuf_data = message:match("#proto(.*)")
  if protobuf_data then
    message = message:gsub("(.*)(#proto.*)","%1<<PROTOBUF>>")

    -- add protobuf field, if it exists
    for s in protobuf_data:gmatch("[^\r\n]+") do
      for _,line in ipairs(splitLines(s)) do
        subtree:add(pfields.protobuf,line)
      end
    end
  end

  --check for #json prefix // json data, if found, replace it with a tag
  local json_data = message:match("#json({.*}).*")
  if json_data then
    message = message:gsub("(.*)(#json{.*})(.*)","%1<<JSON>> %3")
    
    -- add json field, if it exists
    for s in json_data:gmatch("[^\r\n]+") do
      for _,line in ipairs(splitLines(s)) do
        subtree:add(pfields.jsonrpc,line)
      end
    end
  end

  if p_auerlog.prefs.link_calls then
	  --check for "CRV[Oxabcd]:"
	  local crv
	  local crv_pos = message:find("CRV%[.*%]") or -1
	  -- subtree:add(pfields["crv"],crv_pos):set_generated(true)
	  if crv_pos and crv_pos > 0 then
		local crv_end = message:find("%]",crv_pos+4)
		local crv_data = string.sub(message, crv_pos+4,crv_end-1)
		crv = crv_data;
		-- subtree:add(pfields["crv"],crv_pos ,crv_data ):set_generated(true)
		sadd("crv",msg_start+crv_pos+3,crv_end-(crv_pos+4),"string")
		if p_auerlog.prefs.shorten_msg then
		  message = message:gsub("CRV%[..%x*]","",1)
		end
	  end

	  -- check for "TASK[Oxabc]:"
	  local task_data = message:match(".*TASK%[(..%x*)].*")
	  local task
	  if task_data then
		if p_auerlog.prefs.shorten_msg then
		  message = message:gsub("TASK%[..%x*]","",1)
		end
		subtree:add(pfields.task,task_data)
		task = task_data
		if crv then
		  c2t[crv] = task
		  t2c[task] = crv
		else
		  if t2c[task] then
			subtree:add(pfields.crv,t2c[task]):set_generated(true)
		  end
		end
	  else
		if crv and c2t[crv] then
		  subtree:add(pfields.task,c2t[crv]):set_generated(true)
		end
	  end

	  -- check for call_id
	  local call_id = message:match(".*call_id%[(.-)%].*")
	  if call_id then
		if crv then
		  c2i[crv] = call_id
		  i2c[call_id] = crv
		else
		  if i2c[call_id] then 
			subtree:add(pfields.crv,i2c[call_id]):set_generated(true)
		  end
		end
	  else
		if crv and c2i[crv] then
		  subtree:add(pfields.call_id,c2i[crv]):set_generated(true)
		end
	  end

	  if msg_category:match("RESIPROCATE") then 
		for my_id, my_crv in pairs(i2c) do
		  print (my_id, my_crv, message)
		  if string.find( message, my_id ) then
			subtree:add(pfields.call_id,my_id):set_generated(true)
			subtree:add(pfields.crv,my_crv):set_generated(true)
		  end
		end
	  end
  end

  -- remove redundant methodname from Msg
  local replace_with
  if p_auerlog.prefs.shorten_msg then
    replace_with = ""
  else
    replace_with = "(f)"
  end

  if methodname:len() >= 3 then
    message = message:gsub( "" .. methodname .. "%(%d+%)[%s%:]+",replace_with)
    message = message:gsub( "" .. methodname .. "[%s%:]?%d+%s",replace_with)
    message = message:gsub( "" .. methodname .. "[%s%:]+",replace_with)
  end

  -- clean surplus junk at start of line
  message = message:gsub("^[ :]+","")
  
  -- add remaining message fields
  local infoline=""
  local cnt=0
  for s in message:gmatch("[^\r\n]+") do
    for _,line in ipairs(splitLines(s)) do
      if infoline == "" then
        infoline = s
      end
      cnt=cnt+1
      subtree:add(pfields.msg,line)
    end
  end
  if cnt > 1 then
    infoline = infoline .. "..."
  end
  --add info line
  pinfo.cols.info:append(infoline)
end


function p_auerlog_legacy.dissector(buf,pinfo,tree)
  pinfo.cols.protocol = "AUERLOG"
  
  local subtree = tree:add(p_auerlog,buf,"General Data (Old)")
  subtree:set_len(buf:len())
  local sadd = function(fieldname,start,len,type)
    local data = buf(start,len)
    subtree:add(pfields[fieldname],data,data[type or "string"](data))
  end
  
  sadd("category",112,32) 
  sadd("level",144,4,"uint")

  local msg_start = 150 
  local msg_len = buf:len() - msg_start - 1

  if (buf(148,2):uint() == MSG_TYPE_SIP) then
    addIPTree(tree,buf(0,38))
    addThreadData(subtree,buf(38,40))
    subtree:add(pfields["methodname"],"SIP")
    local sip_data = buf(msg_start,msg_len)
    addSIPTree(tree,sip_data,pinfo)
    -- TODO set crv by Call-ID and TASK by CRV
    return
  end
 
  if (buf(148,2):uint() ~= MSG_TYPE_GENERIC) then
    pinfo.cols.info:append("Unknown Type")
    return
  end

  addThreadData(subtree,buf(0,40))

  if (buf(40,1):uint() ~= 0) then
    sadd("classname",40,32)
  end

  sadd("methodname",72,32)
  sadd("line",104,4,"uint")
  sadd("seqno",108,4,"uint")
    
  local methodname = buf(72,32):string()
  methodname = methodname:match("[^%z]*")

-- local message,proto_start,proto_len,json_start,json_len
  local message = buf(msg_start,msg_len):string(ENC_UTF_8)
  -- check for #proto prefix, if found, replace it with a tag
  local protobuf_data = message:match("#proto(.*)")
  if protobuf_data then
    message = message:gsub("(.*)(#proto.*)","%1<<PROTOBUF>>")

    -- add protobuf field, if it exists
    for s in protobuf_data:gmatch("[^\r\n]+") do
      for _,line in ipairs(splitLines(s)) do
        subtree:add(pfields.protobuf,line)
      end
    end
  end
  
  --check for #json prefix // json data, if found, replace it with a tag
  local json_data = message:match("#json({.*}).*")
  if json_data then
    message = message:gsub("(.*)(#json{.*})(.*)","%1<<JSON>> %3")
    
    -- add json field, if it exists
    for s in json_data:gmatch("[^\r\n]+") do
      for _,line in ipairs(splitLines(s)) do
        subtree:add(pfields.jsonrpc,line)
      end
    end
  end

  --check for "CRV[Oxabcd]:"
  local crv
  local crv_pos = message:find("CRV%[.*%]") or -1
  -- subtree:add(pfields["crv"],crv_pos):set_generated(true)
  if crv_pos and crv_pos > 0 then
    local crv_end = message:find("%]",crv_pos+4)
    local crv_data = string.sub(message, crv_pos+4,crv_end-1)
    crv = crv_data;
    -- subtree:add(pfields["crv"],crv_pos ,crv_data ):set_generated(true)
    sadd("crv",msg_start+crv_pos+3,crv_end-(crv_pos+4),"string")
    message = message:gsub("CRV%[..%x*]","",1)
  end

  -- check for "TASK[Oxabc]:"
  local task_data = message:match(".*TASK%[(..%x*)].*")
  local task
  if task_data then
    -- message = message:gsub("TASK%[..%x*]","",1)
    subtree:add(pfields.task,task_data)
    task = task_data
    if crv then
      c2t[crv] = task
      t2c[task] = crv
    else
      if t2c[task] then
        subtree:add(pfields["CRV"],t2c[task]):set_generated(true)
      end
    end
  else
    if crv and c2t[crv] then
      subtree:add(pfields.task,c2t[crv]):set_generated(true)
    end
  end

  -- check for call_id
  local call_id = message:match(".*call_id%[(.-)%].*")
  if call_id then
    if crv then
      c2i[crv] = call_id
      i2c[call_id] = crv
    else
      if i2c[call_id] then 
        subtree:add(pfields.crv,i2c[call_id]):set_generated(true)
      end
    end
  else
    if crv and c2i[crv] then
      subtree:add(pfields.call_id,c2i[crv]):set_generated(true)
    end
  end

  -- remove redundant methodname from Msg
  local replace_with
  if p_auerlog.prefs.shorten_msg then
    replace_with = ""
  else
    replace_with = "(f)"
  end

  if methodname:len() >= 3 then
    message = message:gsub( "" .. methodname .. "%(%d+%)[%s%:]+",replace_with)
    message = message:gsub( "" .. methodname .. "[%s%:]?%d+%s",replace_with)
    message = message:gsub( "" .. methodname .. "[%s%:]+",replace_with)
  end
 
  -- clean surplus junk at start of line
  message = message:gsub("^[ :]+","")

  -- add remaining message fields
  local infoline=""
  local cnt=0
  for s in message:gmatch("[^\r\n]+") do
    for _,line in ipairs(splitLines(s)) do
      if infoline == "" then
      infoline = s
      end
      cnt=cnt+1
      subtree:add(pfields.msg,line)
    end
  end
  if cnt > 1 then
    infoline = infoline .. "..."
  end
   
  --add info line
  pinfo.cols.info:append(infoline)
end

local tcp_port = DissectorTable.get("tcp.port")
  tcp_port:add(42231,p_auerlog_legacy)

-- one-time warning guard (module-global)
local warned_missing_auerswald = false

local function register_encaps()
  local encap = DissectorTable.get("wtap_encap")

  if wtap and wtap.AUERSWALD_LOG then
    encap:add(wtap.AUERSWALD_LOG, p_auerlog)   -- native type supported
  else
    -- Native type missing
    if not p_auerlog.prefs.old_type and not warned_missing_auerswald then
      warned_missing_auerswald = true
      local msg =
        "This Wireshark build does not define wtap.AUERSWALD_LOG.\n" ..
        "Enable 'Support old logs' in Protocol Preferences → Auerlog, " ..
        "or upgrade Wireshark to a build that includes AUERSWALD_LOG.\n" ..
		"You will not be able to display current logs!"

      if gui_enabled and gui_enabled() then
        report_failure(msg)           -- modal dialog in Wireshark GUI
      else
        io.stderr:write("[auerlog] "..msg.."\n")  -- tshark / non-GUI
      end
    end

    -- If user opted in, register the legacy mapping
    if p_auerlog.prefs.old_type then
      encap:add(wtap.USER0, p_auerlog_legacy)
      encap:add(wtap.USER1, p_auerlog)
    end
  end
end

-- call now (script load)
register_encaps()

-- and re-run after prefs are changed (e.g., user toggles the checkbox)
function p_auerlog.prefs_changed()
  register_encaps()
end


