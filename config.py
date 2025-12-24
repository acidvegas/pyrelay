#!/usr/bin/env python
# IRC Relay Bot Configuration - developed by acidvegas in python (https://git.acid.vegas/pyrelay)

# Bot Configuration
nickname       = 'pyrelay'
username       = 'relay'
realname       = 'IRC Relay Bot'

# Relay Connection Defaults
relay_nickname = 'relay'
relay_username = 'relay'
relay_realname = 'IRC Relay Bot'

# IRC Server Configuration
server   = 'irc.supernets.org'
port     = 6697
channel  = '#superbowl'
password = None
key      = None

# Connection Options
use_ssl  = True
use_ipv6 = False
vhost    = None

# Proxy Configuration (optional - only used when --proxy flag is specified in /connect command)
proxy      = None # Example: 'user:pass@127.0.0.1:1080'
proxy_type = 'socks5'              # Options: 'socks5', 'socks4', 'http'

# Bot Settings
cmd_flood   = 3
admin_ident = 'nick!user@host'