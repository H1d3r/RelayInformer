import binascii
import random
import string
from impacket import tds, ntlm

from relayinformer.logger import logger


class MSSQLExtended(tds.MSSQL):
    """Extended MSSQL class that supports channel binding and custom service parameters"""
    
    def getErrorMessages(self):
        """Return error messages from MSSQL replies"""
        if not hasattr(self, 'replies') or not self.replies:
            return ""
            
        error_messages = []
        for keys in list(self.replies.keys()):
            for i, key in enumerate(self.replies[keys]):
                if key['TokenType'] == tds.TDS_ERROR_TOKEN:
                    error_msg = "(%s) %s" % (
                        key['ServerName'].decode('utf-16le'), 
                        key['MsgText'].decode('utf-16le')
                    )
                    error_messages.append(error_msg)
        
        return " ".join(error_messages)
 
        
    def login(self, database, username, password='', domain='', hashes=None, useWindowsAuth=False, 
              channel_binding_value=None, service='MSSQLSvc', strip_target_service=False):
        
        if hashes is not None:
            lmhash, nthash = hashes.split(':')
            lmhash = binascii.a2b_hex(lmhash)
            nthash = binascii.a2b_hex(nthash)
        else:
            lmhash = ''
            nthash = ''

        resp = self.preLogin()

        # Use new in-memory TLS for both REQ and OFF
        if resp['Encryption'] == tds.TDS_ENCRYPT_REQ or resp['Encryption'] == tds.TDS_ENCRYPT_OFF:
            self.set_tls_context()
        else:
            error_msg = f"Unsupported encryption setting: {resp['Encryption']}. Only TDS_ENCRYPT_REQ and TDS_ENCRYPT_OFF are supported."
            logger.error(error_msg)
            raise Exception(error_msg)

        login = tds.TDS_LOGIN()

        login['HostName'] = (''.join([random.choice(string.ascii_letters) for i in range(8)])).encode('utf-16le')
        login['AppName']  = (''.join([random.choice(string.ascii_letters) for i in range(8)])).encode('utf-16le')
        login['ServerName'] = self.remoteName.encode('utf-16le')
        login['CltIntName']  = login['AppName']
        login['ClientPID'] = random.randint(0,1024)
        login['PacketSize'] = self.packetSize
        if database is not None:
            login['Database'] = database.encode('utf-16le')
        login['OptionFlags2'] = tds.TDS_INIT_LANG_FATAL | tds.TDS_ODBC_ON

        if useWindowsAuth is True:
            login['OptionFlags2'] |= tds.TDS_INTEGRATED_SECURITY_ON
            # Prepare NTLMv2 with version and send Negotiate
            self.version = ntlm.VERSION()
            self.version["ProductMajorVersion"], self.version["ProductMinorVersion"], self.version["ProductBuild"] = 10, 0, 20348
            auth = ntlm.getNTLMSSPType1('', '', use_ntlmv2=True, version=self.version)
            login['SSPI'] = auth.getData()
        else:
            login['UserName'] = username.encode('utf-16le')
            login['Password'] = self.encryptPassword(password.encode('utf-16le'))
            login['SSPI'] = ''

        login['Length'] = len(login.getData())

        # Send the NTLMSSP Negotiate or SQL Auth Packet
        self.sendTDS(tds.TDS_LOGIN7, login.getData())

        # According to the specs, if encryption is not required (TDS_ENCRYPT_OFF), 
        # we must encrypt just the first Login packet then switch back to unencrypted
        if resp['Encryption'] == tds.TDS_ENCRYPT_OFF:
            self.tlsSocket = None

        tds_data = self.recvTDS()

        if useWindowsAuth is True:
            serverChallenge = tds_data['Data'][3:]

            # Save original TEST_CASE value and modify if needed
            original_test_case = ntlm.TEST_CASE
            if strip_target_service:
                ntlm.TEST_CASE = True

            try:
                # @Defte_  https://github.com/fortra/impacket/pull/1986
                # Determine CBT value: if None and TLS active, compute via tls-unique; else empty
                effective_cb = channel_binding_value
                if effective_cb is None:
                    if hasattr(self, 'tlsSocket') and self.tlsSocket:
                        effective_cb = self.generate_cbt_from_tls_unique()
                    else:
                        effective_cb = b''

                # Generate the NTLM ChallengeResponse AUTH with NTLMv2, CBT and service binding
                type3, exportedSessionKey = ntlm.getNTLMSSPType3(
                    auth,
                    serverChallenge,
                    username,
                    password,
                    domain,
                    lmhash,
                    nthash,
                    service=service,
                    use_ntlmv2=True,
                    channel_binding_value=effective_cb,
                    version=self.version,
                )

                # Compute and set MIC over the three NTLM messages
                type3["MIC"] = b"\x00" * 16
                ntlm_negotiate_data = auth.getData()
                ntlm_challenge_data = ntlm.NTLMAuthChallenge(serverChallenge).getData()
                ntlm_authenticate_data = type3.getData()
                new_mic = ntlm.hmac_md5(
                    exportedSessionKey,
                    ntlm_negotiate_data + ntlm_challenge_data + ntlm_authenticate_data,
                )
                type3["MIC"] = new_mic
            finally:
                # Restore original TEST_CASE value
                ntlm.TEST_CASE = original_test_case

            self.sendTDS(tds.TDS_SSPI, type3.getData())
            tds_data = self.recvTDS()

        self.replies = self.parseReply(tds_data['Data'])

        if tds.TDS_LOGINACK_TOKEN in self.replies:
            return True
        else:
            return False