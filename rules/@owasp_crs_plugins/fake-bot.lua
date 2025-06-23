-- -----------------------------------------------------------------------
-- OWASP CRS Plugin
-- Copyright (c) 2022-2024 CRS project. All rights reserved.
--
-- The OWASP CRS plugins are distributed under
-- Apache Software License (ASL) version 2
-- Please see the enclosed LICENSE file for full details.
-- -----------------------------------------------------------------------

-- Code inspired by http://lua-users.org/wiki/StringRecipes .
function ends_with(str, ending)
	str = str:lower()
	ending = ending:lower()
	return ending == "" or str:sub(-#ending) == ending
end
function check_ip(ip)
	if type(ip) ~= "string" then
		return false
	end
	-- IPv4
	local chunks = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
	if #chunks == 4 then
		for _, chunk in pairs(chunks) do
			if tonumber(chunk) > 255 then
				return false
			end
		end
		return true
	end
	-- IPv6
	local chunks = {ip:match("^"..(("([a-fA-F0-9]*):"):rep(8):gsub(":$", "$")))}
	if #chunks == 8 or (#chunks < 8 and ip:match("::") and not ip:gsub("::", "", 1):match("::")) then
		for _, chunk in pairs(chunks) do
			if #chunk > 0 and tonumber(chunk, 16) > 65535 then
				return false
			end
		end
		return true
	end
	return false
end
function main(matched_bot)
	pcall(require, "m")
	local ok, socket = pcall(require, "socket")
	if not ok then
		m.log(2, "Fake Bot Plugin ERROR: LuaSocket library not installed, please install it or disable this plugin.")
		return nil
	end
	if matched_bot == "googlebot" then
		-- https://developers.google.com/search/docs/advanced/crawling/verifying-googlebot
		bot_domains = {".googlebot.com", ".google.com"}
		bot_name = "Googlebot"
	elseif matched_bot == "facebookexternalhit" or matched_bot == "facebookcatalog" or matched_bot == "facebookbot" then
		-- https://developers.facebook.com/docs/sharing/webmasters/crawler/
		-- https://developers.facebook.com/docs/sharing/bot/
		bot_domains = {".facebook.com", ".fbsv.net"}
		bot_name = "Facebookbot"
	elseif matched_bot == "bingbot" then
		-- https://blogs.bing.com/webmaster/2012/08/31/how-to-verify-that-bingbot-is-bingbot
		bot_domains = {".search.msn.com"}
		bot_name = "Bingbot"
	elseif matched_bot == "twitterbot" then
		-- https://developer.twitter.com/en/docs/twitter-for-websites/cards/guides/troubleshooting-cards#validate_twitterbot
		bot_domains = {".twitter.com", ".twttr.com"}
		bot_name = "Twitterbot"
	elseif matched_bot == "applebot" then
		-- https://support.apple.com/en-us/HT204683
		bot_domains = {".applebot.apple.com"}
		bot_name = "Applebot"
	elseif matched_bot == "linkedinbot" then
		-- https://udger.com/resources/ua-list/bot-detail?bot=LinkedInBot
		bot_domains = {".fwd.linkedin.com"}
		bot_name = "LinkedInBot"
	elseif matched_bot == "amazonbot" then
		-- https://developer.amazon.com/support/amazonbot
		bot_domains = {".crawl.amazonbot.amazon"}
		bot_name = "Amazonbot"
	else
		return nil
	end
	local remote_addr = m.getvar("REMOTE_ADDR", "none")
	local remote_host = m.getvar("REMOTE_HOST", "none")
	-- If Apache HostnameLookups is On, we can do one less DNS lookup.
	if not check_ip(remote_host) then
		hosts = { [1] = remote_host }
	else
		hosts = socket.dns.getnameinfo(remote_addr)
	end
	for k1, host in pairs(hosts) do
		for k2, domain in pairs(bot_domains) do
			if ends_with(host, domain) then
				addrinfo = socket.dns.getaddrinfo(host)
				if addrinfo ~= nil then
					for k3, ips in pairs(addrinfo) do
						for k4, ip in pairs(ips) do
							if remote_addr == ip then
								return nil
							end
						end
					end
				end
			end
		end
	end
	m.setvar("tx.fake-bot-plugin_bot_name", bot_name)
	return string.format("Fake Bot Plugin: Detected fake %s.", bot_name)
end
