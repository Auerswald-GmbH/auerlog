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

local shorten_msg     = 1

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
  src_ip6 = ProtoField.ipv6("auerlog.src_addr","Source Address"),
  dst_ip6 = ProtoField.ipv6("auerlog.dst_addr","Destination Address"),
  src_ip = ProtoField.ipv4("ip.src_addr","Source", base.DEC, nil, "Source Address", "none", nil, "ip.src"),
  dst_ip = ProtoField.ipv4("ip.dst_addr","Destination", base.DEC, nil, "Destination Address", "none", nil, "ip.dst"),
  crv = ProtoField.string("auerlog.CRV","CRV"),
  task = ProtoField.string("auerlog.TASK","TASK"),
  call_id = ProtoField.string("sip.Call-ID","Call-ID"),
  unused_srcip = ProtoField.none("auerlog.unused_srcip","Unused SrcIPv4"),
  unused_dstip = ProtoField.none("auerlog.unused_dstip","Unused DstIPv4"),
  unused_premsg = ProtoField.none("auerlog.unused","Unused")
}

local efields = {
  sip_call_id = Field.new("sip.Call-ID")
}

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

local function addIPTree(tree,ip_data)
  local ip_version = ip_data(0,1):uint()
  local protocol = 6 -- TCP
  local iptree = nil
  if (ip_version == 6) then
  iptree = tree:add(p_auerlog,ip_data:tvb(0,38),"Internet Protocol Version 6, Src: ,Dst: ")
--	iptree = tree:get("ip")
    iptree:add(pfields["ip_version"],ip_data(0,1))
	iptree:add(pfields["ip_proto"],protocol):set_generated(true)
    iptree:add(pfields["src_ip6"],ip_data:range(2,16))
    tadd(iptree,"src_port",ip_data:range(18,2),"uint")
    iptree:add(pfields["dst_ip6"],ip_data:range(20,16))
    tadd(iptree,"dst_port",ip_data:range(36,2),"uint")
  else
    -- local bin_ip = ip_data
    -- local disp_src_ip = ""
    -- local disp_dst_ip = ""
    -- disp_src_ip = string.format("%u.%u.%u.%u",bin_ip(2):uint8(),bin_ip(3):uint8(),bin_ip(4):uint8(),bin_ip(5):uint8())
    -- bin_ip = ip_data:range(20,4):string()
    -- disp_dst_ip = string.format("%u.%u.%u.%u",string.byte(bin_ip,1),string.byte(bin_ip,2),string.byte(bin_ip,3),string.byte(bin_ip,4))
  	-- iptree = tree:add(p_auerlog,ip_data:tvb(0,38),"Internet Protocol Version 4, Src:".. disp_src_ip .." ,Dst:" )
    iptree = tree:add(p_auerlog,ip_data:tvb(0,38),"Internet Protocol Version 4, Src:".." ,Dst:")
	tcptree = tree:add(p_auerlog,ip_data:tvb(0,38),"Transmission Control Protocol")
    iptree:add(pfields["ip_version"],ip_data(0,1))
	iptree:add(pfields["ip_proto"],protocol):set_generated(true)
    iptree:add(pfields["src_ip"],ip_data:range(2,4))
    iptree:add(pfields["unused_srcip"],ip_data:range(6,12))
    iptree:add(pfields["dst_ip"],ip_data:range(20,4))
    iptree:add(pfields["unused_dstip"],ip_data:range(24,12))

    tcptree:add(pfields["src_port"],ip_data:range(18,2))
    tcptree:add(pfields["dst_port"],ip_data:range(36,2))

--    tadd(iptree,"ip_version",ip_data(0,1))
--    tadd(iptree,"ip_proto",protocol):set_generated(true)
--    tadd(iptree,"src_ip",ip_data:range(2,4),"ipv4")
--    tadd(iptree,"unused_srcip",ip_data:range(6,12))
--    tadd(iptree,"dst_ip",ip_data:range(20,4),"ipv4")
--    tadd(iptree,"unused_dstip",ip_data:range(24,12))

--    tadd(tcptree,"src_port",ip_data:range(18,2),"uint")
--    tadd(tcptree,"dst_port",ip_data:range(36,2),"uint")
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

  local msg_type = buf(0,2):uint()
  sadd("level",2,4,"uint")
  sadd("category",6,32) 
  
  local base = 38
  
  

  if (msg_type == MSG_TYPE_SIP) then
    local crv
    addIPTree(tree,buf(base+0,38))
    addThreadData(subtree,buf(base+38,40))
    subtree:add(pfields["methodname"],"SIP"):set_generated(true)
    local sip_data = buf(msg_start,msg_len)
    addSIPTree(tree,sip_data,pinfo)
    local call_id = efields.sip_call_id.list()    
    print( "SIP-Call-ID: " .. tostring(call_id) )
    if i2c[efields.call_id] then 
      crv = i2c[efields.call_id]
      subtree:add(pfields.crv,crv):set_generated(true)
    end
    if crv and c2t[crv] then
      subtree:add(pfields.task,c2t[crv]):set_generated(true)
    end

    return
  end
 
  if (msg_type ~= MSG_TYPE_GENERIC) then
    pinfo.cols.info:append("Unknown Type")
    return
  end

  addThreadData(subtree,buf(base+0,40))

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
    if shorten_msg then
      message = message:gsub("CRV%[..%x*]","",1)
    end
  end

  -- check for "TASK[Oxabc]:"
  local task_data = message:match(".*TASK%[(..%x*)].*")
  local task
  if task_data then
    if shorten_msg then
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

  -- TODO if Category is RESIPROCATE scan Msg for all entries of Call_id in i2c 
  --      if match is found set CRV and TASK accordingly

  -- remove redundant methodname from Msg
  local replace_with
  if shorten_msg then
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
  if shorten_msg then
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

local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER0,p_auerlog_legacy)
wtap_encap_table:add(wtap.USER1,p_auerlog)
if wtap.AUERSWALD_LOG then
  wtap_encap_table:add(wtap.AUERSWALD_LOG,p_auerlog)
end
