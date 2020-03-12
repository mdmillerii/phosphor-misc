#!/usr/bin/awk -f

# minimal HTTP/1.1 server
# mostly redirects to HTTPS

BEGIN {
	CRLF = "\r\n"

	methods["GET"] = 1
	methods["HEAD"] = 1

	errors[400] = "400 Bad Request"
	errors[500] = "500 Internal Server Error"
	errors[500] = "501 Not Implented"
	errors[505] = "505 HTTP Version Not Supported"
	msgtxt[505] = "HTTP/1.1 only"

	# Only forward these resources to https
	https_resources["/"] = "/"
}

function respond_error(num)
{
	if (num in errors)
		if (num in msgtxt)
			respond_and_exit(errors[num], msgtxt[num] CRLF)
		else
			respond_and_exit(errors[num], errors[num] CRLF)
	else
		respond_and_exit(errors[500], "bad error" num CRLF)
}

# strip trailing CR(\r) before LF(\n)  RFC2616 19.3
/\r$/ { sub(/\r$/, "") }

# The first line is the HTTP request type
method == "" {
	if ($0 == "")
		next

	method = $1
	request_uri = $2
	version = $3

	if (version !~ /HTTP\/0*1[.][0-9]$/)	# support leading 0s, but
		respond_error(505)		# version not supported
	if (bad_uric(request_uri))
		respond_error(400)		# Bad Request (bogus encoding)
	split_url_components(request_uri, split_uri)
print_split_url(split_uri)
	if (!is_http_request_uri(split_url))
		respond_error(400)		# Bad Request (didn't parse)
	if (!method in methods)
		respond_error(501)		# not implimented

	# headers start on the next line
	next
}

# a header continuation RFC2616 4.2
/^[ \t]+/ {
	headers[header] = headers[header] $0
	next
}

# header lines start with a token and have a : seperator
# implied LWS is allowed around the : seperator; lws at beginning and end
# can be removed

match($0, /[ \t]*:[ \t]*/) {
	header = substr($0, 1, RSTART - 1)

	# field names are a single token.  
	# LWS is impled allowed at the : seperator.  Any beginning or trailing
	# LWS is not significant
	if (!is_token(header))
		respond_error(400)

	# headers are case insensitive, so normalize to upper case
	header = toupper(header)

	# RFC2616 4.2 multiple instances of a headers is only valid for for 
	# comma separated lists.
	# Remove any trailing LWS, add ", " seperator.
	prior = ""
	if (header in headers)
		prior = sub(/[ \t]*$/, "", headers[header]) ", "
	headers[header] = prior substr($0, RSTART + RLENGTH)

	# print "found header >"header"< with content >"headers[header]"<"
}

# end of headers
/^$/ {
	# would read request body here but we don't care

	# if we have a syntax error on the headers
	for (header in headers)
		if (!is_token(header))
			respond_error(400)

	# RFC2616 5.2
	if (!("HOST" in headers))
		respond_error(400)

	host = headers["HOST"]
	if ("host" in split_uri)
		host = split_uri("host")

	# a very relaxed check for domainlabel or IPv4
	if (host !~ /^[0-9a-zA-Z.-]*$/)
		respond_error(400)

	# uris must be unescaped before compare, but forwareded unmodified
	uri = unescape(split_uri("path"))

	# translate our whitelisted URI
	if (uri in https_resources) {
		uri = https_resources[uri]
		response = "308 Permanent Redirect"
		content = response CRLF CRLF "Access with a https:// URL" CRLF
		respond_and_exit(response, content, URI)
	}

	# Rather than be an open redirector, resource not found
	respond_error(404)

	# get noisy response if we didn't exit above
	exit 3
}

function is_token(token)
{
  # us ascii (0-127) excluding CTL (000-037, 177, SP (040), seperators
  if (match(token, /[^\041-\176]/) || match(header, /[()<>@,;:\\/[]?=\{\}" \t/))
	return 0

  return 1
}

# nreserved, reserverd, or endcoded.
function bad_uric(URI)
{
	# hide encoded
	gsub(/%[0-9a-fA-F][0-9a-fA-F]/,"",URI)

	# check uri characters:  mark alphanuma reserved
	if (URI ~ /[^-_.!~*'()a-zA-Z0-9";\/?:@&=+$,]/)
		return 1
	return 0
}

# with eues from RFC2396 appendix B etal
function split_url_components(url, components)
{
	if (match(url, /#/)) {
		components["frag"] = substr(url, RLENGTH + 1)
		url = substr(url, 1, RLENGTH - 1)
	}

	if (match(url, /\?/)) {
		components["query"] = substr(url, RLENGTH + 1)
		url = substr(url, 1, RLENGTH - 1)
	}

	if (match(url, /^[^:\/?#]+:/)) {
		components["scheme"] = substr(url, 1, RLENGTH - 1) ;
		url = substr(url, RLENGTH + 1)
	}

	# maybe early return
	if (substr(url, 1, 2) != "//") {
		components["path"] = url;
		return
	} else if (match(substr(url, 3), "/")) {
		components["path"] = substr(url, 3 + RSTART) # include the /
		url = substr(url, 3, 3 + RSTART - 1)
	} else {
		url = substr(url, 3)
	}

	if (match(url, /@/)) {
		userinfo = substr(url, 1, RLENGTH - 1)
		url = substr(url, RLENGTH + 1)

		components["userinfo"] = userinfo
		if (match(userinfo, ":")) {
			# NOT RECOMMENDED
			components["password"] = substr(userinfo, RSTART + 1)
			userinfo = substr(userinfo, RSTART - 1)
		}
		components["user"] = userinfo;
	}
	if (match(":", url)) {
		components["port"] = substr(url, RSTART + 1)
		url = substr(url, 1, RSTART - 1)
	}
	if (url)
		components["host"] = url
}

function print_if_present(key, array, format)
{
	if (key in array):
		printf (format, array[key])
}

function dump_field(key, array)
{
	print_if_present(key, array, dquote key dquote ": " dquote "%s" dquote)
}

function print_split_url(components)
{
    print "split_url = {"
    dump_field("scheme", components)
    dump_field("userinfo", components)
    dump_field("host", components)
    dump_field("path", components)
    dump_field("query", components)
    dump_field("frag", components)
    print "}"
}

# fixme : do % hex hex -> code replacement
function unescape(url_seg)
{
	return url_seg
}

# RFC2616 3.2.2
function is_http_request_uri(split_url)
{
	# fragments are handled by the client, user info is not on the wire
	if (("frag" in split_url) || ("userinfo" in split_url))
		return 0

	# if absoluteURI, it will have both, if abs_path neither
	if (("scheme" in split_url) != ("host" in split_url))
		return 0

	if ("scheme" in split_url) {
		scheme = unescape(split_url["scheme"])
		if (tolower(scheme) != "http")
			return 0

		# https always has a net_url host authority, host not empty
		if (!("host" in split_url))
			return 0

		# authority name not empty
		if (split_url["host"] = "")
			return 0

		# sole fixup: scheme://hostport
		if (split_url["path"] == "")
			split_url["path"] = "/"
	}

	# The path must be absolute
	return substr(split_url[path], 1, 1) == "/"
}

function add_location_header(prefix, URI, error)
{
	# all returned locations shall be https
	if (substr(URI, 1, 8) != "https://")
		return error

	if (bad_uric(URI))
		return error

	return prefix "Location: " URI
}

function respond_and_exit(response, content, URI) {
	if ((response !~ /^3/) && (response !~ /^201/))
		location = ""
        else 
		location = add_location_header(CRLF, URI, "")

        if (response !~ /^[1-5][0-9][0-9] .*$/) {
		print "DEBUG: response '" response "'" CRLF "DEBUG: content: '" content"'" CRLF
		response = "500 Internal Server Error" 
		content = response CRLF
	}

	# Separate output fields (lines) with CRLF but after body add nothing
	OFS = CRLF
	ORS = ""

	content_length = sprintf("Content-Length: %d", length(content))

	print( "HTTP/1.1 " response location,
		content_length,
		"Content-Type: text/plain; charset=UTF-8",
		"X_Frame_Options: DENY",
		"Pragma: no-cache",
		"Cache_Control: no-Store,no-Cache",
		"X-XSS-Protection: 1; mode=block",
		"X-Content-Type-Options: nosniff",
		"Connection: close",
		"",
		content)
	exit 0
}



BEGIN {
# Helper, so we don't have to count backslashes
dquote="\""


# rfc 2396
reserved = ";/?:@&=+$,"
mark = "-_.!~*'()"
digit = "0123456789"
lower = "abcdefghijklmnopqrstuvwxyz"
upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
unreserved = lower upper digit mark
# control = 00-1F, 7F
# space = " "
# delims = "<>#%" dquote
# unwise = "{}|\^[]`"

}

function shquote(string)
{
	gsub(/\\/, "\\\\", string);
	gsub(/'/, "\\'", string)
	return "'" string "'"
}

function generate_hex_codes(codes, string,        cmd, chr, hex)
{
	dquote="\""

	# Tell the shell to write our "string", then pipe to od to print
	# out octal file offset and then hex char code for each byte
	# of input, 1 pair per char The final line will be the length
	# in octal

	cmd = "printf '%s'" shquotte(string) "| od -tx1d"

	for (i = 1 ;  i <= length(unreserved) ; i += 1) {
		cmd | getline
		if (NF != 2 || $2 !~ /^[0-9a-fA-F][0-9a-fA-F]$/ )
			{ print "Error: od for " chr " read " $0 "." ; exit 2 }
		hex = ($2)
		chr = substr(string, i, 1)
		codes[toupper(hex)] = chr
		codes[toupper(hex)] = chr
		# print "hex[" dquote hex dquote "] = " dquote chr dquote ";"
	}
	cmd | getline
	if (NF != 1)
		{ print "Error generating hex code table" ; exit 2 }
	close(cmd)
}

function dump_table(table, name,        i)
{
	for (i in table)
	  print name "[" dquote i dquote "] = " dquote chr[i] dquote ";"
}
