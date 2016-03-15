module(..., package.seeall)

-- connection timeout in micro seconds
TIMEOUT = 30000
-- default port for document retrieval
PORT = 80
-- user agent
USERAGENT = "myhttp 0.1"

function escape(s)
	return string.gsub(s, "([^A-Za-z0-9_])", function(c) return string.format("%%%02x", string.byte(c)) end)
end

function unescape(s)
	return string.gsub(s, "%%(%x%x)", function(hex) return string.char(tonumber(hex, 16)) end)
end

-----------------------------------------------------------------------------
-- <url> ::= <scheme>://<authority>/<path>;<params>?<query>#<fragment>
-- <authority> ::= <userinfo>@<host>:<port>
-- <userinfo> ::= <user>[:<password>]
-- <path> :: = {<segment>/}<segment>
-----------------------------------------------------------------------------

function parse_url(req)

	if not req.url or req.url == "" then return nil end

	local url = req.url
	-- get fragment
	url = string.gsub(url, "#(.*)$", function(f) req.fragment = f return "" end)
	-- get scheme
	url = string.gsub(url, "^([%w][%w%+%-%.]*)%:", function(s) req.scheme = s; return "" end)
	-- get authority
	url = string.gsub(url, "^//([^/]*)", function(n) req.authority = n return "" end)
	-- get query stringing
	url = string.gsub(url, "%?(.*)", function(q) req.query = q return "" end)
	-- get params
	url = string.gsub(url, "%;(.*)", function(p) req.params = p return "" end)
	-- path is whatever was left
	if url ~= "" then req.path = url end

	local authority = req.authority
	if not authority then return req end

	-- get userinfo
	authority = string.gsub(authority,"^([^@]*)@", function(u) req.userinfo = u; return "" end)
	-- get port
	authority = string.gsub(authority, ":([^:]*)$", function(p) req.port = p; return "" end)
	-- host is whatever was left
	if authority ~= "" then req.host = authority end

	local userinfo = req.userinfo
	if not userinfo then return req end

	userinfo = string.gsub(userinfo, ":([^:]*)$", function(p) req.password = p; return "" end)
	req.user = userinfo

	return req
end

local function adjusturi(req)
	local uri = req.path 
	if req.params then uri = uri .. ";" .. req.params end
	if req.query then uri = uri .. "?" .. req.query end

	local authority = req.authority
	if req.host then
		authority = req.host
		if req.port then authority = authority .. ":" .. req.port end
		local userinfo = req.userinfo
		if req.user then
			userinfo = req.user
			if req.password then
				userinfo = userinfo .. ":" .. req.password
			end
		end
		if userinfo then authority = userinfo .. "@" .. authority end
	end	

	if authority then uri = "//" .. authority .. uri end
	if req.scheme then uri = req.scheme .. ":" .. uri end
	if req.fragment then uri = uri .. "#" .. req.fragment end

	return uri
end

local function adjustheaders(req)
	-- default headers
	local lower = {
		["user-agent"] = USERAGENT,
		["host"] = req.host,
		["connection"] = "close, TE",
		["te"] = "trailers"
	}

	-- override with user headers
	for k, v in pairs(req.headers or {}) do
		lower[string.lower(k)] = v
	end

	return lower
end

local function adjustrequest(req)
	-- compute uri if user hasn't overriden
	req.uri = req.uri or adjusturi(req)
	-- adjust headers in request
	req.headers = adjustheaders(req)
end

local function init_req(req)
	req.port = req.port or PORT
	req.headers = req.headers or {}
	req.method = req.method or "GET"

	if req.body then
		req.headers["content-length"] = string.len(req.body)
		req.headers["content-type"] = "application/x-www-form-urlencoded"
		req.method = "POST"	
	end
end

local function sendrequestline(sock, method, uri)
	local reqline = string.format("%s %s HTTP/1.1\r\n", method or "GET", uri)
	sock:send(reqline)
end

local function sendheaders(sock, headers)
	local h = "\r\n"
	for k, v in pairs(headers) do
		h = k .. ": " .. v .. "\r\n" .. h
	end
	sock:send(h)
end

local function sendbody(sock, body)
	if body then sock:send(body) end
end

local function receivestatusline(sock)

	local status = sock:receive(5)

	if status ~= "HTTP/" then return nil, status end

	status = status .. sock:receive("*l")

	local _, _, code = string.find(status, "HTTP/%d*%.%d* (%d%d%d)")

	return tonumber(code), status
end

local function receiveheaders(sock)

	local line, name, value, err

	local headers = headers or {}

	line, err = sock:receive()
	if err then return nil, err end

	while line ~= "" do
		-- get field-name and value
		_, _, name, value = string.find(line, "^(.-):%s*(.*)")
		if not (name and value) then return nil, "malformed reponse headers" end
		name = string.lower(name)

		line, err  = sock:receive()
		if err then return nil, err end
		while string.find(line, "^%s") do
			value = value .. line
			line = sock:receive()
			if err then return nil, err end
		end

		-- save pair in table
		if headers[name] then headers[name] = headers[name] .. ", " .. value
		else headers[name] = value end
	end
	return headers
end

local function receivebody(sock, headers)
	local n, err
	local body = ""

	if headers["transfer-encoding"] == "chunked" then

		while true do
			n, err = sock:receive("*l")

			if tonumber(n) == 0 then
				break;
			end

			if not n then return nil, err end
		
			local b
			b, err = sock:receive(tonumber(n, 16))

			if not b then return nil, err end

			body = body..b
			n, err = sock:receive()
		end
	else
		body = sock:receive("*a")
	end

	return body
end

function request(req)
	if type(req) ~= "table" then
		return nil, "req must be a table"
	end

	init_req(req)

	if not parse_url(req) then
		return nil, "parse url error : " .. tostring(url)
	end

	adjustrequest(req)

	local sock = ngx.socket.tcp()
	sock:settimeout(TIMEOUT)
	local ok, err = sock:connect(req.host, req.port)

	if not ok then
		sock:close()
		return nil, "failed to connect :" .. tostring(host) .. ":" .. tostring(port)
	end

	sendrequestline(sock, req.method, req.uri)
	sendheaders(sock, req.headers)
	sendbody(sock, req.body)

	local code, status = receivestatusline(sock)

	if not code then
		sock:close()
		return nil, "no code return"
	end	

	local headers, err = receiveheaders(sock)	

	if not headers then 
		sock:close()
		return nil, err
	end

	local body, err = receivebody(sock, headers)

	if not body then
		sock:close()
		body = ""
	end	

	return { body = body, headers = headers, code = code, status = status } 
end
