#!/usr/bin/python

from ConfigParser import RawConfigParser
from email.mime.base import MIMEBase
import email
import email.message
import re
import GnuPG
import smtplib
import sys

def appendLog(msg):
	if cfg.has_key('logging') and cfg['logging'].has_key('file'):
		log = open(cfg['logging']['file'], 'a')
		log.write(msg + "\n")
		log.close()

# Read configuration from /etc/gpg-mailgate.conf
_cfg = RawConfigParser()
_cfg.read('/etc/gpg-mailgate.conf')
cfg = dict()
for sect in _cfg.sections():
	cfg[sect] = dict()
	for (name, value) in _cfg.items(sect):
		cfg[sect][name] = value

# Read e-mail from stdin
raw = sys.stdin.read()
raw_message = email.message_from_string( raw )
from_addr = raw_message['From']
to_addrs = sys.argv[1:]

encrypted_to_addrs = list()
if raw_message.has_key('X-GPG-Encrypt-Cc'):
	encrypted_to_addrs.extend( [e[1] for e in email.utils.getaddresses([raw_message['X-GPG-Encrypt-Cc']])] )
	del raw_message['X-GPG-Encrypt-Cc']

def send_msg( message, recipients = None ):
	if recipients == None:
		recipients = to_addrs
	appendLog("Sending email to: <%s>" % '> <'.join( recipients ))
	relay = (cfg['relay']['host'], int(cfg['relay']['port']))
	smtp = smtplib.SMTP(relay[0], relay[1])
	smtp.sendmail( from_addr, recipients, message.as_string() )

def encrypt_payload( payload, gpg_to_cmdline ):
	raw_payload = payload.get_payload(decode=True)
	if "-----BEGIN PGP MESSAGE-----" in raw_payload and "-----END PGP MESSAGE-----" in raw_payload:
		return payload
	gpg = GnuPG.GPGEncryptor( cfg['gpg']['keyhome'], gpg_to_cmdline, payload.get_content_charset() )
	gpg.update( raw_payload )
	payload.set_payload( gpg.encrypt() )
	
	isAttachment = payload.get_param( 'attachment', None, 'Content-Disposition' ) is not None
	
	if isAttachment:
		filename = payload.get_filename()
	
		if filename:
			pgpFilename = filename + ".pgp"
			
			if payload.get('Content-Disposition') is not None:
				payload.set_param( 'filename', pgpFilename, 'Content-Disposition' )
			if payload.get('Content-Type') is not None:
				if payload.get_param( 'name' ) is not None:
					payload.set_param( 'name', pgpFilename )

				payload.set_payload( "\n".join( filter( lambda x:re.search(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$',x), payload.get_payload().split("\n") ) ) )

	if payload.get('Content-Transfer-Encoding') is not None:
		payload.replace_header( 'Content-Transfer-Encoding', "quoted-printable" )

	return payload

def encrypt_all_payloads( message, gpg_to_cmdline ):
	encrypted_payloads = list()
	if type( message.get_payload() ) == str:
		return encrypt_payload( message, gpg_to_cmdline ).get_payload()
	for payload in message.get_payload():
		if( type( payload.get_payload() ) == list ):
			encrypted_payloads.append( encrypt_all_payloads( payload, gpg_to_cmdline ) )
		else:
			encrypted_payloads.append( encrypt_payload( payload, gpg_to_cmdline ) )
	return encrypted_payloads

def get_msg( message ):
	if not message.is_multipart():
		return message.get_payload()
	return '\n\n'.join( [str(m) for m in message.get_payload()] )

keys = GnuPG.public_keys( cfg['gpg']['keyhome'] )
gpg_to = list()
ungpg_to = list()
for enc in encrypted_to_addrs:
	domain = enc.split('@')[1]
	if domain in cfg['default']['domains'].split(','):
		if enc in keys:
			gpg_to.append( (enc, enc) )
		elif cfg.has_key('keymap') and cfg['keymap'].has_key(enc):
			gpg_to.append( (enc, cfg['keymap'][enc]) )
		else:
			ungpg_to.append(enc);
			
for to in to_addrs:
	domain = to.split('@')[1]
	if domain in cfg['default']['domains'].split(','):
		if to in keys:
			gpg_to.append( (to, to) )
		elif cfg.has_key('keymap') and cfg['keymap'].has_key(to):
			gpg_to.append( (to, cfg['keymap'][to]) )
		else:
			ungpg_to.append(to);
	else:
		ungpg_to.append(to)

if gpg_to == list():
	if cfg['default'].has_key('add_header') and cfg['default']['add_header'] == 'yes':
		raw_message['X-GPG-Mailgate'] = 'Not encrypted, public key not found'
	send_msg( raw_message )
	exit()

if ungpg_to != list():
	send_msg( raw_message, ungpg_to )

appendLog("Encrypting email to: %s" % ' '.join( map(lambda x: x[0], gpg_to) ))

if cfg['default'].has_key('add_header') and cfg['default']['add_header'] == 'yes':
	raw_message['X-GPG-Mailgate'] = 'Encrypted by GPG Mailgate'

gpg_to_cmdline = list()
gpg_to_smtp = list()
for rcpt in gpg_to:
	gpg_to_smtp.append(rcpt[0])
	gpg_to_cmdline.extend(rcpt[1].split(','))

encrypted_payloads = encrypt_all_payloads( raw_message, gpg_to_cmdline )
raw_message.set_payload( encrypted_payloads )

send_msg( raw_message, gpg_to_smtp )
