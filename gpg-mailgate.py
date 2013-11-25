#!/usr/bin/python

from ConfigParser import RawConfigParser
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
import email
import email.message
import re
import GnuPG
import smtplib
import sys
import syslog

# Read configuration from /etc/gpg-mailgate.conf
_cfg = RawConfigParser()
_cfg.read('/etc/gpg-mailgate.conf')
cfg = dict()
for sect in _cfg.sections():
	cfg[sect] = dict()
	for (name, value) in _cfg.items(sect):
		cfg[sect][name] = value

def log(msg):
	if cfg.has_key('logging') and cfg['logging'].has_key('file'):
		if cfg['logging']['file'] == "syslog":
			syslog.syslog(syslog.LOG_INFO | syslog.LOG_MAIL, msg)
		else:
			logfile = open(cfg['logging']['file'], 'a')
			logfile.write(msg + "\n")
			logfile.close()

verbose=cfg.has_key('logging') and cfg['logging'].has_key('verbose') and cfg['logging']['verbose'] == 'yes'

# Read e-mail from stdin
raw = sys.stdin.read()
raw_message = email.message_from_string( raw )
from_addr = raw_message['From']
to_addrs = sys.argv[1:]

if verbose:
	log("")
	log("gpg-mailgate starting.  Recipient list: <%s>" % '> <'.join( to_addrs ))

def send_msg( message, recipients = None ):
	if recipients == None:
		recipients = to_addrs
	if cfg.has_key('default') and cfg['default'].has_key('extra_recipient'):
		recipients.append(cfg['default']['extra_recipient'])
	log("Sending email to: <%s>" % '> <'.join( recipients ))
	relay = (cfg['relay']['host'], int(cfg['relay']['port']))
	smtp = smtplib.SMTP(relay[0], relay[1])
	smtp.sendmail( from_addr, recipients, message.as_string() )

def encrypt_payload( payload, gpg_to_cmdline ):
	if verbose:
		log("Encrypting payload to recipients: %s" % ', '.join( gpg_to_cmdline ))
	raw_payload = payload.get_payload(decode=True)
	if re.search(r'^-----BEGIN PGP MESSAGE-----', raw_payload, re.M) and re.search(r'^-----END PGP MESSAGE-----', raw_payload, re.M):
		if verbose:
			log("Declining to encrypt payload containing inline PGP markers.")
		return payload
	gpg = GnuPG.GPGEncryptor( cfg['gpg']['keyhome'], gpg_to_cmdline, payload.get_content_charset() )
	gpg.update( raw_payload )
	encrypted_data, returncode =gpg.encrypt()
	if verbose:
		log("Return code from encryption=%d (0 indicates success)." % returncode)
	payload.set_payload( encrypted_data )
	
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

	if payload.get('Content-Transfer-Encoding') is not None:
		payload.replace_header( 'Content-Transfer-Encoding', "7bit" )

	return payload

def encrypt_all_payloads( message, gpg_to_cmdline ):
	encrypted_payloads = list()
	if type( message.get_payload() ) == str:
		if cfg.has_key('default') and cfg['default'].has_key('mime_conversion') and cfg['default']['mime_conversion'] == 'yes':
			# Convert a plain text email into PGP/MIME attachment style.  Modeled after enigmail.
			submsg1=email.message.Message()
			submsg1.set_payload("Version: 1\n")
			submsg1.set_type("application/pgp-encrypted")
			submsg1.set_param('PGP/MIME version identification', "", 'Content-Description' )
			
			submsg2=email.message.Message()
			submsg2.set_type("application/octet-stream")
			submsg2.set_param('name', "encrypted.asc")
			submsg2.set_param('OpenPGP encrypted message', "", 'Content-Description' )
			submsg2.set_param('inline', "",                'Content-Disposition' )
			submsg2.set_param('filename', "encrypted.asc", 'Content-Disposition' )
			
			# WTF!  It seems to swallow the first line.  Not sure why.  Perhaps
			# it's skipping an imaginary blank line someplace. (ie skipping a header)
			# Workaround it here by prepending a blank line.
			submsg2.set_payload("\n"+message.get_payload())

			message.preamble="This is an OpenPGP/MIME encrypted message (RFC 2440 and 3156)"
			
			# Use this just to generate a MIME boundary string.
			junk_msg = MIMEMultipart()
			junk_str=junk_msg.as_string()  # WTF!  Without this, get_boundary() will return 'None'!
			boundary=junk_msg.get_boundary()

		        # This also modifies the boundary in the body of the message, ie it gets parsed.
			if message.has_key('Content-Type'):
				message.replace_header('Content-Type', "multipart/encrypted; protocol=\"application/pgp-encrypted\";\nboundary=\"%s\"\n" % boundary)
			else:
				message['Content-Type']="multipart/encrypted; protocol=\"application/pgp-encrypted\";\nboundary=\"%s\"\n" % boundary

			return [ submsg1, encrypt_payload( submsg2, gpg_to_cmdline) ]
		else:
			# Do a simple in-line PGP conversion of a plain text email.
			return encrypt_payload( message, gpg_to_cmdline ).get_payload()


	for payload in message.get_payload():
		if( type( payload.get_payload() ) == list ):
			encrypted_payloads.extend( encrypt_all_payloads( payload, gpg_to_cmdline ) )
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

for to in to_addrs:
	if to in keys.values() and not ( cfg['default'].has_key('keymap_only') and cfg['default']['keymap_only'] == 'yes'  ):
		gpg_to.append( (to, to) )
	elif cfg.has_key('keymap') and cfg['keymap'].has_key(to):
		log("Keymap has key '%s'" % cfg['keymap'][to] )
		# Check we've got a matching key!  If not, decline to attempt encryption.
		if not keys.has_key(cfg['keymap'][to]):
			log("Key '%s' in keymap not found in keyring for email address '%s'.  Won't encrypt." % (cfg['keymap'][to], to))
			ungpg_to.append(to)
		else:
			gpg_to.append( (to, cfg['keymap'][to]) )
	else:
		if verbose:
			log("Recipient (%s) not in keymap list." % to)
		ungpg_to.append(to)

if gpg_to == list():
	if cfg['default'].has_key('add_header') and cfg['default']['add_header'] == 'yes':
		raw_message['X-GPG-Mailgate'] = 'Not encrypted, public key not found'
	if verbose:
		log("No encrypted recipients.")
	send_msg( raw_message )
	exit()

if ungpg_to != list():
	send_msg( raw_message, ungpg_to )

log("Encrypting email to: %s" % ' '.join( map(lambda x: x[0], gpg_to) ))

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
