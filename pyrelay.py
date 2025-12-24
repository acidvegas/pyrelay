#!/usr/bin/env python
# IRC Relay Bot - developed by acidvegas in python (https://git.acid.vegas/pyrelay)

import asyncio
import logging
import logging.handlers
import ssl
import time

try:
	import aiohttp
except ImportError:
	raise ImportError('missing \'aiohttp\' library (pip install aiohttp)')

try:
	from python_socks.async_.asyncio import Proxy
	from python_socks                import ProxyType
except ImportError:
	raise ImportError('missing \'python-socks\' library (pip install python-socks[asyncio])')

import config

# Formatting Control Characters / Color Codes
bold        = '\x02'
italic      = '\x1D'
underline   = '\x1F'
reverse     = '\x16'
reset       = '\x0f'
white       = '00'
black       = '01'
blue        = '02'
green       = '03'
red         = '04'
brown       = '05'
purple      = '06'
orange      = '07'
yellow      = '08'
light_green = '09'
cyan        = '10'
light_cyan  = '11'
light_blue  = '12'
pink        = '13'
grey        = '14'
light_grey  = '15'


def color(msg: str, foreground: str, background: str = None) -> str:
	'''
	Color a string with the specified foreground and background colors.

	:param msg: The string to color.
	:param foreground: The foreground color to use.
	:param background: The background color to use.
	'''
	return f'\x03{foreground},{background}{msg}{reset}' if background else f'\x03{foreground}{msg}{reset}'


def has_irc_colors(text: str) -> bool:
	'''
	Check if text contains IRC color codes or formatting.

	:param text: The text to check.
	'''
	# IRC formatting codes
	formatting_codes = [
		'\x02',  # Bold
		'\x03',  # Color
		'\x04',  # Hex color
		'\x0f',  # Reset
		'\x16',  # Reverse
		'\x1d',  # Italic
		'\x1e',  # Strikethrough
		'\x1f',  # Underline
		'\x11',  # Monospace
	]
	return any(code in text for code in formatting_codes)


def parse_irc_line(line: str) -> str:
	'''
	Parse and colorize an IRC protocol line.
	Preserves existing IRC colors/formatting if present.

	:param line: The raw IRC line to parse and colorize.
	'''
	if not line:
		return ''

	# Check if the message content has IRC colors/formatting
	# If so, do minimal colorization to preserve the original formatting
	if has_irc_colors(line):
		parts = line.split(' ')
		result = []
		idx = 0

		# Parse prefix (if exists) - colorize this part
		if parts[0].startswith(':'):
			prefix = parts[0][1:]
			idx = 1

			# Check if it's a nick!user@host or server
			if '!' in prefix:
				nick, rest = prefix.split('!', 1)
				if '@' in rest:
					user, host = rest.split('@', 1)
					result.append(color(':', grey))
					result.append(color(nick, light_cyan))
					result.append(color('!', grey))
					result.append(color(user, cyan))
					result.append(color('@', grey))
					result.append(color(host, cyan))
				else:
					result.append(color(':' + prefix, cyan))
			else:
				# Server name
				result.append(color(':' + prefix, light_blue))

			result.append(' ')

		# Parse command - colorize this part
		if idx < len(parts):
			command = parts[idx]
			idx += 1

			# Numeric replies
			if command.isdigit():
				result.append(color(command, pink))
			# Common commands with specific colors
			elif command.upper() in ('PRIVMSG', 'NOTICE'):
				result.append(color(command, green))
			elif command.upper() in ('JOIN', 'PART', 'QUIT', 'KICK'):
				result.append(color(command, yellow))
			elif command.upper() in ('MODE', 'TOPIC'):
				result.append(color(command, orange))
			elif command.upper() in ('NICK'):
				result.append(color(command, light_green))
			elif command.upper() in ('PING', 'PONG'):
				result.append(color(command, cyan))
			elif command.upper() in ('ERROR'):
				result.append(color(command, red))
			else:
				result.append(color(command, light_grey))

			result.append(' ')

		# For parameters, preserve original formatting if colors are present
		if idx < len(parts):
			remaining = ' '.join(parts[idx:])
			# Check if this part has colors
			if has_irc_colors(remaining):
				# Just append as-is to preserve colors
				result.append(remaining)
			else:
				# No colors in remaining, colorize normally
				while idx < len(parts):
					part = parts[idx]

					# Trailing parameter (starts with :)
					if part.startswith(':'):
						trailing = ' '.join(parts[idx:])[1:]
						result.append(color(':', grey))
						result.append(color(trailing, white))
						break
					# Channel
					elif part.startswith('#') or part.startswith('&'):
						result.append(color(part, light_green))
					# Looks like a nickname (no special chars except allowed ones)
					elif part and not any(c in part for c in '!@.:'):
						result.append(color(part, light_cyan))
					else:
						result.append(color(part, light_grey))

					result.append(' ')
					idx += 1

		return ''.join(result).rstrip()

	# No IRC colors detected, use full colorization
	parts = line.split(' ')
	result = []
	idx = 0

	# Parse prefix (if exists)
	if parts[0].startswith(':'):
		prefix = parts[0][1:]
		idx = 1

		# Check if it's a nick!user@host or server
		if '!' in prefix:
			nick, rest = prefix.split('!', 1)
			if '@' in rest:
				user, host = rest.split('@', 1)
				result.append(color(':', grey))
				result.append(color(nick, light_cyan))
				result.append(color('!', grey))
				result.append(color(user, cyan))
				result.append(color('@', grey))
				result.append(color(host, cyan))
			else:
				result.append(color(':' + prefix, cyan))
		else:
			# Server name
			result.append(color(':' + prefix, light_blue))

		result.append(' ')

	# Parse command
	if idx < len(parts):
		command = parts[idx]
		idx += 1

		# Numeric replies
		if command.isdigit():
			result.append(color(command, pink))
		# Common commands with specific colors
		elif command.upper() in ('PRIVMSG', 'NOTICE'):
			result.append(color(command, green))
		elif command.upper() in ('JOIN', 'PART', 'QUIT', 'KICK'):
			result.append(color(command, yellow))
		elif command.upper() in ('MODE', 'TOPIC'):
			result.append(color(command, orange))
		elif command.upper() in ('NICK'):
			result.append(color(command, light_green))
		elif command.upper() in ('PING', 'PONG'):
			result.append(color(command, cyan))
		elif command.upper() in ('ERROR'):
			result.append(color(command, red))
		else:
			result.append(color(command, light_grey))

		result.append(' ')

	# Parse parameters
	while idx < len(parts):
		part = parts[idx]

		# Trailing parameter (starts with :)
		if part.startswith(':'):
			trailing = ' '.join(parts[idx:])[1:]
			result.append(color(':', grey))
			result.append(color(trailing, white))
			break
		# Channel
		elif part.startswith('#') or part.startswith('&'):
			result.append(color(part, light_green))
		# Looks like a nickname (no special chars except allowed ones)
		elif part and not any(c in part for c in '!@.:'):
			result.append(color(part, light_cyan))
		else:
			result.append(color(part, light_grey))

		result.append(' ')
		idx += 1

	return ''.join(result).rstrip()


def parse_proxy(proxy_string: str) -> dict:
	'''
	Parse proxy string in format user:pass@host:port or host:port.

	:param proxy_string: The proxy string to parse.
	'''
	if not proxy_string:
		return None

	username = None
	password = None
	host     = None
	port     = None

	# Check if authentication is included
	if '@' in proxy_string:
		auth, server = proxy_string.rsplit('@', 1)
		if ':' in auth:
			username, password = auth.split(':', 1)
	else:
		server = proxy_string

	# Parse host and port
	if ':' in server:
		host, port_str = server.rsplit(':', 1)
		try:
			port = int(port_str)
		except ValueError:
			raise ValueError(f'Invalid proxy port: {port_str}')
	else:
		raise ValueError('Proxy must include port (host:port)')

	return {
		'host'     : host,
		'port'     : port,
		'username' : username,
		'password' : password
	}


def extract_ip_from_host(host: str) -> str:
	'''
	Extract IP address from hostname (handles dash-separated IPs in hostnames).

	:param host: The hostname to extract IP from.
	'''
	# Check if it's already an IP
	if is_ip_address(host):
		return host
	
	# Check for dash-separated IP in hostname (e.g., 45-239-214-241.example.com)
	parts = host.split('.')
	if parts and '-' in parts[0]:
		potential_ip = parts[0].replace('-', '.')
		if is_ip_address(potential_ip):
			return potential_ip
	
	return None


def is_ip_address(host: str) -> bool:
	'''
	Check if a string looks like an IP address.

	:param host: The hostname to check.
	'''
	# Remove common separators and check if only hex/digits remain
	cleaned = host.replace('.', '').replace(':', '').replace('[', '').replace(']', '')
	return cleaned and all(c in '0123456789abcdefABCDEF' for c in cleaned)


async def get_geoip_info(ip: str) -> dict:
	'''
	Get GeoIP information from maxmind.supernets.org.

	:param ip: The IP address to lookup.
	'''
	try:
		async with aiohttp.ClientSession() as session:
			async with session.get(f'http://maxmind.supernets.org/{ip}', timeout=aiohttp.ClientTimeout(total=10)) as response:
				if response.status == 200:
					data = await response.json()
					return data
	except Exception as ex:
		logging.error(f'GeoIP lookup failed: {ex}')
	return None


class RelayConnection():
	def __init__(self, server: str, port: int, use_ssl: bool, use_proxy: bool = False):
		self.server    = server
		self.port      = port
		self.use_ssl   = use_ssl
		self.use_proxy = use_proxy
		self.reader    = None
		self.writer    = None
		self.connected = False
		self.registered = False
		self.visible_host = None


	async def connect(self):
		'''Connect to the relay IRC server.'''
		try:
			# Use proxy only if requested and configured
			if self.use_proxy and config.proxy:
				proxy_info = parse_proxy(config.proxy)
				proxy_type_map = {
					'socks5' : ProxyType.SOCKS5,
					'socks4' : ProxyType.SOCKS4,
					'http'   : ProxyType.HTTP
				}
				
				proxy_type_enum = proxy_type_map.get(config.proxy_type.lower(), ProxyType.SOCKS5)
				
				proxy = Proxy(
					proxy_type = proxy_type_enum,
					host       = proxy_info['host'],
					port       = proxy_info['port'],
					username   = proxy_info['username'],
					password   = proxy_info['password']
				)
				
				sock = await proxy.connect(
					dest_host = self.server,
					dest_port = self.port,
					timeout   = 15
				)
				
				options = {
					'limit'          : 1024,
					'ssl'            : ssl._create_unverified_context() if self.use_ssl else None,
					'server_hostname': self.server if self.use_ssl else None
				}
				
				self.reader, self.writer = await asyncio.open_connection(sock=sock, **options)
				logging.info(f'Relay connected to {self.server}:{self.port} via proxy')
			else:
				options = {
					'host'  : self.server,
					'port'  : self.port,
					'limit' : 1024,
					'ssl'   : ssl._create_unverified_context() if self.use_ssl else None
				}
				self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(**options), 15)
				logging.info(f'Relay connected to {self.server}:{self.port}')
			
			self.connected = True
		except Exception as ex:
			logging.error(f'Relay connection failed: {ex}')
			raise


	async def disconnect(self):
		'''Disconnect from the relay IRC server.'''
		if self.writer:
			try:
				self.writer.close()
				await self.writer.wait_closed()
			except Exception:
				pass
		self.connected = False
		self.registered = False
		self.visible_host = None
		logging.info(f'Relay disconnected from {self.server}:{self.port}')


	async def raw(self, data: str):
		'''
		Send raw data to the relay IRC server.

		:param data: The raw data to send to the IRC server.
		'''
		if self.connected and self.writer:
			self.writer.write(data[:510].encode('utf-8') + b'\r\n')
			await self.writer.drain()


class Bot():
	def __init__(self):
		self.nickname = config.nickname
		self.username = config.username
		self.realname = config.realname
		self.reader   = None
		self.writer   = None
		self.last     = time.time()
		self.slow     = False
		self.relay    = None
		self.relay_task = None


	async def action(self, chan: str, msg: str):
		'''
		Send an ACTION to the IRC server.

		:param chan: The channel to send the ACTION to.
		:param msg: The message to send to the channel.
		'''
		await self.sendmsg(chan, f'\x01ACTION {msg}\x01')


	async def raw(self, data: str):
		'''
		Send raw data to the IRC server.

		:param data: The raw data to send to the IRC server. (512 bytes max including crlf)
		'''
		self.writer.write(data[:510].encode('utf-8') + b'\r\n')


	async def sendmsg(self, target: str, msg: str):
		'''
		Send a PRIVMSG to the IRC server.

		:param target: The target to send the PRIVMSG to. (channel or user)
		:param msg: The message to send to the target.
		'''
		await self.raw(f'PRIVMSG {target} :{msg}')


	async def connect(self):
		'''Connect to the IRC server.'''
		while True:
			try:
				options = {
					'host'       : config.server,
					'port'       : config.port,
					'limit'      : 1024,
					'ssl'        : ssl_ctx() if config.use_ssl else None,
					'family'     : 10 if config.use_ipv6 else 2,
					'local_addr' : config.vhost if config.vhost else None
				}
				self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(**options), 15)
				
				if config.password:
					await self.raw('PASS ' + config.password)
				await self.raw(f'USER {self.username} 0 * :{self.realname}')
				await self.raw('NICK ' + self.nickname)
				while not self.reader.at_eof():
					data = await asyncio.wait_for(self.reader.readuntil(b'\r\n'), 300)
					await self.handle(data.decode('utf-8').strip())
			except Exception as ex:
				logging.error(f'failed to connect to {config.server} ({str(ex)})')
			finally:
				await asyncio.sleep(30)


	async def eventPRIVMSG(self, data: str):
		'''
		Handle the PRIVMSG event.

		:param data: The data received from the IRC server.
		'''
		parts  = data.split()
		ident  = parts[0][1:]
		nick   = parts[0].split('!')[0][1:]
		target = parts[2]
		msg    = ' '.join(parts[3:])[1:]

		if target == self.nickname:
			if ident == config.admin_ident:
				if msg.startswith('!raw') and len(msg.split()) > 1:
					option = ' '.join(msg.split()[1:])
					await self.raw(option)
			else:
				await self.sendmsg(nick, 'Do NOT message me!')

		if target.startswith('#'):
			if msg.startswith('.relay'):
				if time.time() - self.last < config.cmd_flood:
					if not self.slow:
						self.slow = True
						await self.sendmsg(target, color('Slow down!', red))
				else:
					self.slow = False
					await self.handle_relay_command(target, nick, msg)
					self.last = time.time()


	async def display_geoip_info(self, channel: str, geo_info: dict):
		'''
		Display GeoIP information in a colorful format with emojis.

		:param channel: The channel to send the info to.
		:param geo_info: The GeoIP data dictionary.
		'''
		try:
			# Country code to flag emoji mapping
			def get_flag_emoji(iso_code: str) -> str:
				'''Convert ISO country code to flag emoji.'''
				if not iso_code or len(iso_code) != 2:
					return '🌍'
				# Convert ISO code to regional indicator symbols
				return ''.join(chr(127397 + ord(c)) for c in iso_code.upper())
			
			# Build the info message with colors
			parts = []
			
			# Country with flag emoji
			country_name = None
			country_iso = None
			if geo_info.get('country'):
				country_data = geo_info['country']
				if isinstance(country_data, dict):
					country_name = country_data.get('name')
					country_iso = country_data.get('iso_code')
				else:
					country_name = str(country_data)
			
			if country_name:
				flag = get_flag_emoji(country_iso) if country_iso else '🌍'
				parts.append(flag + ' ' + color(country_name, white))
			
			# Region/State
			if geo_info.get('region'):
				region_data = geo_info['region']
				region_name = region_data.get('name') if isinstance(region_data, dict) else str(region_data)
				parts.append(color('Region:', light_blue) + ' ' + color(region_name, white))
			
			# City
			if geo_info.get('city'):
				city_data = geo_info['city']
				city_name = city_data.get('name') if isinstance(city_data, dict) else str(city_data)
				parts.append(color('🏙️', white) + ' ' + color(city_name, white))
			
			# Coordinates
			location = geo_info.get('location', {})
			if isinstance(location, dict):
				lat = location.get('latitude')
				lon = location.get('longitude')
				if lat and lon:
					parts.append(color('📍', white) + ' ' + color(f'{lat}, {lon}', light_grey))
			
			# ASN - handle various formats
			asn_displayed = False
			if geo_info.get('asn'):
				asn_data = geo_info['asn']
				if isinstance(asn_data, dict):
					asn_num = asn_data.get('asn') or asn_data.get('number') or asn_data.get('autonomous_system_number')
					asn_org = asn_data.get('org') or asn_data.get('organization') or asn_data.get('autonomous_system_organization')
					if asn_num and asn_org:
						parts.append(color('ASN:', light_blue) + ' ' + color(str(asn_num), yellow) + ' ' + color('🏢', white) + ' ' + color(asn_org, cyan))
						asn_displayed = True
					elif asn_num:
						parts.append(color('ASN:', light_blue) + ' ' + color(str(asn_num), yellow))
					elif asn_org:
						parts.append(color('🏢', white) + ' ' + color(asn_org, cyan))
						asn_displayed = True
				else:
					parts.append(color('ASN:', light_blue) + ' ' + color(str(asn_data), yellow))
			
			# Check for autonomous_system_number and autonomous_system_organization at top level
			if not asn_displayed:
				asn_num = geo_info.get('autonomous_system_number')
				asn_org = geo_info.get('autonomous_system_organization')
				if asn_num and asn_org:
					parts.append(color('ASN:', light_blue) + ' ' + color(f'AS{asn_num}', yellow) + ' ' + color('🏢', white) + ' ' + color(asn_org, cyan))
					asn_displayed = True
				elif asn_num:
					parts.append(color('ASN:', light_blue) + ' ' + color(f'AS{asn_num}', yellow))
				elif asn_org and not asn_displayed:
					parts.append(color('🏢', white) + ' ' + color(asn_org, cyan))
					asn_displayed = True
			
			# ISP/Organization (if not already shown from ASN)
			if not asn_displayed and geo_info.get('org'):
				org = geo_info['org']
				parts.append(color('🏢', white) + ' ' + color(org, cyan))
			elif not asn_displayed and geo_info.get('isp'):
				isp = geo_info['isp']
				parts.append(color('🏢', white) + ' ' + color(isp, cyan))
			
			# Timezone
			if geo_info.get('timezone'):
				tz_data = geo_info['timezone']
				tz_name = tz_data.get('name') if isinstance(tz_data, dict) else str(tz_data)
				parts.append(color('🕐', white) + ' ' + color(tz_name, light_grey))
			
			if parts:
				# Format with separators
				formatted_parts = (color(' │ ', grey)).join(parts)
				msg = color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('🌐 GeoIP:', green) + ' ' + formatted_parts
				await self.sendmsg(channel, msg)
		except Exception as ex:
			logging.error(f'Error displaying GeoIP info: {ex}')


	async def handle_relay_command(self, channel: str, nick: str, msg: str):
		'''
		Handle relay commands.

		:param channel: The channel where the command was issued.
		:param nick: The nickname of the user who issued the command.
		:param msg: The full message containing the command.
		'''
		parts = msg.split()
		if len(parts) < 2:
			await self.sendmsg(channel, color('Usage: ', cyan) + '.relay ' + color('/help', yellow) + ' | ' + color('/connect', yellow) + ' <server> <port> [ssl] [--proxy] | ' + color('/disconnect', yellow) + ' | ' + color('/info', yellow) + ' | ' + color('<IRC_COMMAND>', yellow))
			return

		cmd = parts[1].lower()

		if cmd == '/help':
			# Display help information
			help_lines = [
				color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('📖 PyRelay Commands:', green),
				'',
				color('  /connect', yellow) + ' ' + color('<server> <port> [ssl] [--proxy] [nick] [user] [realname]', light_grey),
				'    ' + color('→', grey) + ' Connect to an IRC network through the relay',
				'    ' + color('Flags:', cyan) + ' ' + color('ssl', yellow) + ' = use SSL/TLS, ' + color('--proxy', yellow) + ' = route through proxy',
				'    ' + color('Examples:', cyan),
				'      ' + color('.relay /connect irc.example.com 6697 ssl', white),
				'      ' + color('.relay /connect irc.example.com 6697 ssl --proxy', white),
				'      ' + color('.relay /connect irc.example.com 6667 MyBot myuser My Bot', white),
				'',
				color('  /info', yellow),
				'    ' + color('→', grey) + ' Show current relay connection status and details',
				'',
				color('  /disconnect', yellow),
				'    ' + color('→', grey) + ' Disconnect from the current relay network',
				'',
				color('  <IRC_COMMAND>', yellow),
				'    ' + color('→', grey) + ' Send raw IRC commands to the relay network',
				'    ' + color('Examples:', cyan),
				'      ' + color('.relay JOIN #channel', white),
				'      ' + color('.relay PRIVMSG #channel :Hello!', white),
				'      ' + color('.relay NICK newnick', white),
				'      ' + color('.relay MODE #channel +o user', white),
				'',
				color('Note:', light_blue) + ' Protocol data is colorized and IP/location shown automatically!'
			]
			
			for line in help_lines:
				await self.sendmsg(channel, line)
		
		elif cmd == '/connect':
			if len(parts) < 4:
				await self.sendmsg(channel, color('Usage: ', cyan) + '.relay /connect ' + color('<server> <port> [ssl] [--proxy] [nick] [user] [realname]', yellow))
				return

			# Check for existing connection
			if self.relay and self.relay.connected:
				await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' Already connected to ' + color(self.relay.server, cyan) + ' - use ' + color('.relay /disconnect', yellow) + ' first')
				return
			
			# Clean up any stale relay objects
			if self.relay:
				try:
					await self.relay.disconnect()
				except Exception:
					pass
				self.relay = None
			
			if self.relay_task and not self.relay_task.done():
				self.relay_task.cancel()
				try:
					await self.relay_task
				except asyncio.CancelledError:
					pass
				self.relay_task = None

			server = parts[2].lower()
			try:
				port = int(parts[3])
			except ValueError:
				await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' Invalid port number')
				return

			# Prevent connecting to the same network
			if server == config.server.lower() and port == config.port:
				await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('Error:', red) + ' Cannot relay to the same network the bot is connected to')
				return

			# Parse optional arguments
			idx = 4
			use_ssl = False
			use_proxy = False
			relay_nick = None
			relay_user = None
			relay_realname = None

			# Parse flags and arguments
			while idx < len(parts):
				arg = parts[idx]
				
				if arg.lower() == 'ssl':
					use_ssl = True
					idx += 1
				elif arg.lower() == '--proxy':
					use_proxy = True
					idx += 1
				elif not relay_nick:
					relay_nick = arg
					idx += 1
				elif not relay_user:
					relay_user = arg
					idx += 1
				else:
					# Everything else is realname
					relay_realname = ' '.join(parts[idx:])
					break

			# Use config defaults if not provided
			if not relay_nick:
				relay_nick = f'{config.relay_nickname}{str(int(time.time()))[-4:]}'
			if not relay_user:
				relay_user = config.relay_username
			if not relay_realname:
				relay_realname = config.relay_realname

			# Build connection message
			conn_msg = color('[', grey) + color('RELAY', pink) + color(']', grey) + ' Connecting to ' + color(server, cyan) + ':' + color(str(port), cyan)
			if use_ssl:
				conn_msg += ' ' + color('[SSL]', green)
			if use_proxy:
				conn_msg += ' ' + color('[PROXY]', yellow)
			await self.sendmsg(channel, conn_msg)

			try:
				self.relay = RelayConnection(server, port, use_ssl, use_proxy)
				await self.relay.connect()
				self.relay_task = asyncio.create_task(self.relay_reader(channel))
				
				# Auto-register with provided or default credentials
				await asyncio.sleep(0.5)
				await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('Connected!', green) + ' Registering as ' + color(relay_nick, yellow) + color('!', grey) + color(relay_user, yellow))
				await self.relay.raw(f'NICK {relay_nick}')
				await self.relay.raw(f'USER {relay_user} 0 * :{relay_realname}')
			except Exception as ex:
				await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('Connection failed:', red) + f' {ex}')
				self.relay = None

		elif cmd == '/info':
			if not self.relay or not self.relay.connected:
				await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' Not connected to any server')
				return
			
			# Display current relay connection info
			info_parts = []
			info_parts.append(color('Server:', light_blue) + ' ' + color(f'{self.relay.server}:{self.relay.port}', cyan))
			if self.relay.use_ssl:
				info_parts.append(color('[SSL]', green))
			
			if self.relay.registered:
				info_parts.append(color('Status:', light_blue) + ' ' + color('Registered', green))
			else:
				info_parts.append(color('Status:', light_blue) + ' ' + color('Connecting...', yellow))
			
			if self.relay.visible_host:
				info_parts.append(color('Host:', light_blue) + ' ' + color(self.relay.visible_host, cyan))
			
			formatted_info = (color(' │ ', grey)).join(info_parts)
			await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('ℹ️  Info:', green) + ' ' + formatted_info)
		
		elif cmd == '/disconnect':
			if not self.relay or not self.relay.connected:
				await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' Not connected to any server')
				return

			server_name = self.relay.server
			await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' Disconnecting from ' + color(server_name, cyan) + '...')
			
			# Send QUIT to the relay server
			try:
				await self.relay.raw('QUIT :Relay closed')
				await asyncio.sleep(0.5)
			except Exception:
				pass
			
			# Cancel the reader task (this will trigger cleanup in finally block)
			if self.relay_task and not self.relay_task.done():
				self.relay_task.cancel()
				try:
					await self.relay_task
				except asyncio.CancelledError:
					pass
			
			self.relay_task = None

		else:
			if not self.relay or not self.relay.connected:
				await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' Not connected. Use ' + color('.relay connect', yellow))
				return

			# Send the raw IRC command
			try:
				raw_command = ' '.join(parts[1:])
				colorized_command = parse_irc_line(raw_command)
				await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color('] ', grey) + color('>>>', green) + ' ' + colorized_command)
				await self.relay.raw(raw_command)
			except Exception as ex:
				await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('Error sending command:', red) + f' {ex}')
				logging.error(f'Error sending relay command: {ex}')


	async def relay_reader(self, channel: str):
		'''
		Read data from the relay connection and display it in the channel.

		:param channel: The channel to send relay data to.
		'''
		disconnect_reason = None
		
		try:
			while self.relay and self.relay.connected and self.relay.reader:
				data = await asyncio.wait_for(self.relay.reader.readuntil(b'\r\n'), 300)
				line = data.decode('utf-8').strip()
				
				if not line:
					continue
				
				parts = line.split()
				
				# Detect ERROR messages (server disconnecting us)
				if line.startswith('ERROR :'):
					colorized_line = parse_irc_line(line)
					await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color('] ', grey) + color('<<<', cyan) + ' ' + colorized_line)
					disconnect_reason = 'Server sent ERROR'
					break
				
				# Detect K-Line/G-Line/Z-Line bans
				elif len(parts) > 1 and parts[1] in ('465', '466', '520', '550'):
					colorized_line = parse_irc_line(line)
					await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color('] ', grey) + color('<<<', cyan) + ' ' + colorized_line)
					disconnect_reason = 'Banned from server'
					break
				
				# Detect MODE from self (contains our visible host)
				elif len(parts) > 1 and parts[1] == 'MODE' and parts[0].startswith(':'):
					colorized_line = parse_irc_line(line)
					await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color('] ', grey) + color('<<<', cyan) + ' ' + colorized_line)
					
					# Extract host from :nick!user@host MODE nick :+modes
					try:
						prefix = parts[0][1:]  # Remove leading :
						if '!' in prefix and '@' in prefix:
							nick = prefix.split('!')[0]
							host = prefix.split('@')[1]
							target = parts[2] if len(parts) > 2 else ''
							
							# Check if it's a MODE for the nick itself (self-mode)
							if target == nick and not self.relay.visible_host:
								self.relay.visible_host = host
								await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('Host:', light_blue) + ' ' + color(self.relay.visible_host, cyan))
								
								# Lookup GeoIP - extract IP from hostname if needed
								ip_to_lookup = extract_ip_from_host(host)
								if ip_to_lookup:
									geo_info = await get_geoip_info(ip_to_lookup)
									if geo_info:
										await self.display_geoip_info(channel, geo_info)
					except Exception as ex:
						logging.debug(f'Error parsing MODE for host: {ex}')
				
				# Auto-respond to PING
				elif parts and parts[0] == 'PING':
					await self.relay.raw('PONG ' + parts[1])
					colorized_line = parse_irc_line(line)
					await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color('] ', grey) + color('<<<', cyan) + ' ' + colorized_line)
				
				# Detect successful registration
				elif len(parts) > 1 and parts[1] == '001' and not self.relay.registered:
					self.relay.registered = True
					colorized_line = parse_irc_line(line)
					await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color('] ', grey) + color('<<<', cyan) + ' ' + colorized_line)
					
					# Try to extract visible host from welcome message
					# Format: :server 001 nick :Welcome message nick!user@host
					try:
						welcome_msg = ' '.join(parts[3:])[1:]
						if '!' in welcome_msg and '@' in welcome_msg:
							# Extract the nick!user@host from the message
							for word in welcome_msg.split():
								if '!' in word and '@' in word:
									self.relay.visible_host = word.split('@', 1)[1]
									break
					except Exception:
						pass
					
					if self.relay.visible_host:
						await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('✓', green) + ' ' + color('Registered!', green) + ' Visible host: ' + color(self.relay.visible_host, cyan))
						
						# Lookup GeoIP - extract IP from hostname if needed
						host_to_lookup = self.relay.visible_host
						# Strip port if present
						if ':' in host_to_lookup and not host_to_lookup.count(':') > 1:  # IPv4 with port
							host_to_lookup = host_to_lookup.split(':')[0]
						
						# Extract IP and lookup
						ip_to_lookup = extract_ip_from_host(host_to_lookup)
						if ip_to_lookup:
							geo_info = await get_geoip_info(ip_to_lookup)
							if geo_info:
								await self.display_geoip_info(channel, geo_info)
					else:
						await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('✓', green) + ' ' + color('Registered!', green) + ' You can now send commands')
				
				# Detect hostname reveals (numeric 396, 042, 378, etc.)
				elif len(parts) > 1 and parts[1] in ('396', '042', '378'):
					colorized_line = parse_irc_line(line)
					await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color('] ', grey) + color('<<<', cyan) + ' ' + colorized_line)
					
					# Extract visible host from these numerics
					# 396: :server 396 nick host :message (IRCd host change notification)
					# 042: :server 042 nick unique_id :your unique ID
					# 378: :server 378 nick :is connecting from *@host (some IRCds)
					try:
						if parts[1] == '396' and len(parts) >= 4:
							self.relay.visible_host = parts[3]
							await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('Host:', light_blue) + ' ' + color(self.relay.visible_host, cyan))
							
							# Lookup GeoIP - extract IP from hostname if needed
							host_to_lookup = self.relay.visible_host
							if ':' in host_to_lookup and not host_to_lookup.count(':') > 1:
								host_to_lookup = host_to_lookup.split(':')[0]
							
							ip_to_lookup = extract_ip_from_host(host_to_lookup)
							if ip_to_lookup:
								geo_info = await get_geoip_info(ip_to_lookup)
								if geo_info:
									await self.display_geoip_info(channel, geo_info)
						
						elif parts[1] == '378' and len(parts) >= 4:
							# Extract from "is connecting from *@host" or similar
							msg = ' '.join(parts[4:])
							if '@' in msg:
								potential_host = msg.split('@')[-1].strip()
								# Clean up any trailing text
								potential_host = potential_host.split()[0]
								self.relay.visible_host = potential_host
								await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('Host:', light_blue) + ' ' + color(self.relay.visible_host, cyan))
								
								# Lookup GeoIP - extract IP from hostname if needed
								host_to_lookup = potential_host
								if ':' in host_to_lookup and not host_to_lookup.count(':') > 1:
									host_to_lookup = host_to_lookup.split(':')[0]
								
								ip_to_lookup = extract_ip_from_host(host_to_lookup)
								if ip_to_lookup:
									geo_info = await get_geoip_info(ip_to_lookup)
									if geo_info:
										await self.display_geoip_info(channel, geo_info)
					except Exception:
						pass
				
				else:
					colorized_line = parse_irc_line(line)
					await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color('] ', grey) + color('<<<', cyan) + ' ' + colorized_line)

		except asyncio.CancelledError:
			disconnect_reason = 'Disconnected by user'
		except asyncio.TimeoutError:
			disconnect_reason = 'Ping timeout'
		except asyncio.IncompleteReadError:
			disconnect_reason = 'Connection closed by remote host'
		except ConnectionResetError:
			disconnect_reason = 'Connection reset'
		except Exception as ex:
			disconnect_reason = f'Error: {ex}'
		finally:
			# Clean up the relay connection
			if self.relay:
				await self.relay.disconnect()
				self.relay = None
			
			# Notify channel of disconnect
			if disconnect_reason:
				await self.sendmsg(channel, color('[', grey) + color('RELAY', pink) + color(']', grey) + ' ' + color('✗', red) + ' ' + color('Disconnected:', red) + f' {disconnect_reason}')
				logging.info(f'Relay disconnected: {disconnect_reason}')


	async def handle(self, data: str):
		'''
		Handle the data received from the IRC server.

		:param data: The data received from the IRC server.
		'''
		logging.info(data)
		try:
			parts = data.split()
			if data.startswith('ERROR :Closing Link:'):
				raise Exception('BANNED')
			if parts[0] == 'PING':
				await self.raw('PONG ' + parts[1]) # Respond to the server's PING request with a PONG to prevent ping timeout
			elif parts[1] == '001': # RPL_WELCOME
				await self.raw(f'MODE {self.nickname} +B')
				await asyncio.sleep(3)
				if config.key:
					await self.raw(f'JOIN {config.channel} {config.key}')
				else:
					await self.raw(f'JOIN {config.channel}')
			elif parts[1] == '433': # ERR_NICKNAMEINUSE
				self.nickname += '_' # If the nickname is already in use, append an underscore to the end of it
				await self.raw('NICK ' + self.nickname) # Send the new nickname to the server
			elif parts[1] == 'INVITE':
				target = parts[2]
				chan = parts[3][1:]
				if target == self.nickname: # If we were invited to a channel, join it
					await self.raw(f'JOIN {chan}')
			elif parts[1] == 'KICK':
				chan   = parts[2]
				kicked = parts[3]
				if kicked == self.nickname: # If we were kicked from the channel, rejoin it after 3 seconds
					await asyncio.sleep(3)
					await self.raw(f'JOIN {chan}')
			elif parts[1] == 'PRIVMSG':
				await self.eventPRIVMSG(data) # We put this in a separate function since it will likely be the most used/handled event
		except (UnicodeDecodeError, UnicodeEncodeError):
			pass # Some IRCds allow invalid UTF-8 characters, this is a very important exception to catch
		except Exception as ex:
			logging.exception(f'Unknown error has occured! ({ex})')


def setup_logger(log_filename: str, to_file: bool = False):
	'''
	Set up logging to console & optionally to file.

	:param log_filename: The filename of the log file
	:param to_file: Whether or not to log to a file
	'''
	sh = logging.StreamHandler()
	sh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)9s | %(message)s', '%I:%M %p'))
	if to_file:
		fh = logging.handlers.RotatingFileHandler(log_filename+'.log', maxBytes=250000, backupCount=3, encoding='utf-8') # Max size of 250KB, 3 backups
		fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)9s | %(filename)s.%(funcName)s.%(lineno)d | %(message)s', '%Y-%m-%d %I:%M %p')) # We can be more verbose in the log file
		logging.basicConfig(level=logging.NOTSET, handlers=(sh,fh))
	else:
		logging.basicConfig(level=logging.NOTSET, handlers=(sh,))



if __name__ == '__main__':
	print(f'Connecting to {config.server}:{config.port} (SSL: {config.use_ssl}) and joining {config.channel}')

	setup_logger('pyrelay', to_file=True)

	bot = Bot()

	asyncio.run(bot.connect())
