#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
OTP Token Web UI Tests
"""

import base64
import hashlib
import hmac
import struct
import re
import time
from urlparse import urlparse

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_user as user

ENTITY = 'otptoken'
TOKEN_RE = r'otpauth://(hotp|totp)/.*:(?P<tokenid>.*)\?'

USER_ID = u'tuser1'
USER_PW = u'Secret123'
USER_ADD_DATA = {
    'givenname': u'test',
    'sn': u'user1',
    'userpassword': USER_PW
}


class Token(dict):
    '''
    Simplified Copy & Pasted class from OTP API CI tests. Works as Soft Token.

    Initialized from otptoken_add command result
    '''

    @property
    def type(self):
        return self[u'type'].upper()

    @property
    def tokenid(self):
        return self[u'ipatokenuniqueid']

    def otp(self, at=0):
        # I first attempted implementing this with pyotp. However, pyotp has
        # a critical bug which appeared in testing. I fixed this bug and
        # submitted it upstream: https://github.com/nathforge/pyotp/pull/9
        #
        # However, upstream pyotp appears to be dead. For now, I have
        # implemented the algorithm myself. In the future, it would be nice
        # to use python-cryptography here.

        # If the token is time-based, calculate the counter from the time.
        if self.type == u"TOTP":
            intrvl = self[u'ipatokentotptimestep']
            offset = self.get(u'ipatokentotpclockoffset', 0)
            at = (time.time() + offset + intrvl * at) / intrvl

        # Otherwise, just account for the specified counter offset.
        elif self.type == u"HOTP":
            if at < 0:  # Skip invalid test offsets.
                raise Exception('Invalid HOTP counter offset (at)')
            at += self.get(u'ipatokenhotpcounter', 0)

        # Create the HMAC of the current counter
        countr = struct.pack("!Q", at)
        hasher = getattr(hashlib, self[u'ipatokenotpalgorithm'])
        digest = hmac.HMAC(self[u'ipatokenotpkey'], countr, hasher).digest()

        # Get the number of digits
        digits = self[u'ipatokenotpdigits']

        # Truncate the digest
        offset = ord(digest[-1]) & 0xf
        binary = (ord(digest[offset + 0]) & 0x7f) << 0x18
        binary |= (ord(digest[offset + 1]) & 0xff) << 0x10
        binary |= (ord(digest[offset + 2]) & 0xff) << 0x08
        binary |= (ord(digest[offset + 3]) & 0xff) << 0x00
        binary = binary % (10 ** digits)

        return str(binary).rjust(digits, '0')

    def __init__(self, token_result):

        for key, val in token_result.iteritems():
            if key == 'uri':
                secret = urlparse(val).query.split(u'&')[1].split(u'=')[1]
                secret = base64.b32decode(secret)
                self['ipatokenotpkey'] = secret
            elif key in ('ipatokenotpdigits', 'ipatokentotptimestep',
                         'ipatokentotpclockoffset'):
                self[key] = int(val[0])
            elif isinstance(val, (list, tuple)):
                self[key] = val[0]
            else:
                self[key] = val


class test_otptoken(UI_driver):

    def check_visible_fields(self, user=True, totp=True):
        '''
        Check if admin interface contains all fields and self-service only
        type and description.
        '''
        admin = not user
        self.assert_visible("[name='description']")
        self.assert_visible("[name='ipatokenuniqueid']", negative=user, present=admin)
        self.assert_visible("[name='ipatokenowner']", negative=user, present=admin)
        self.assert_visible("[name='ipatokennotbefore']", negative=user, present=admin)
        self.assert_visible("[name='ipatokennotafter']", negative=user, present=admin)
        self.assert_visible("[name='ipatokenvendor']", negative=user, present=admin)
        self.assert_visible("[name='ipatokenmodel']", negative=user, present=admin)
        self.assert_visible("[name='ipatokenserial']", negative=user, present=admin)
        self.assert_visible("[name='ipatokenotpkey']", negative=user, present=admin)
        self.assert_visible("[name='ipatokenotpalgorithm']", negative=user, present=admin)
        self.assert_visible("[name='ipatokenotpdigits']", negative=user, present=admin)
        totp = totp and admin  # visible only in admin interface
        self.assert_visible("[name='ipatokentotptimestep']", negative=(not totp), present=(totp))

    def token_post_add(self, data=None):
        '''
        Check functionality of QR dialog and retrieve configuration url which
        also contains a token name.
        '''
        qr_image_cont = "a[name='qr'] div[name='qr']"
        uri_cont = "div[name='uri-control']"

        self.assert_visible(qr_image_cont)
        self.assert_visible(uri_cont, negative=True)
        self.click_on_link('Show configuration uri')
        self.assert_visible(uri_cont)
        self.assert_visible(qr_image_cont, negative=True)
        config_uri = self.get_text(uri_cont)
        self.click_on_link('Show QR code')
        self.assert_visible(qr_image_cont)
        self.assert_visible(uri_cont, negative=True)
        self.dialog_button_click('ok')

        match = re.match(TOKEN_RE, config_uri)
        assert match, "Unable to fetch token ID"
        tokenid = match.group('tokenid')
        if data:
            data['pkey'] = tokenid

    def create_user(self, userid=USER_ID, pw=USER_PW, adddata=USER_ADD_DATA,
                    logout=True):
        '''
        Create user and reset his password.
        '''
        # add user
        self.delete_user(userid)
        self.api.Command.user_add(userid, **adddata)
        # reset psw
        self.init_app(userid, pw)
        if logout:
            self.logout()

    def delete_user(self, userid=USER_ID):
        '''
        Delete test user
        '''
        self.api.Command.user_del(USER_ID, **{'continue': True})

    def create_tokens(self, userid=USER_ID, pw=USER_PW, totp=True, hotp=True):
        '''
        Create TOTP and HOTP token for user
        '''
        # add tokens
        self.reconnect_api(USER_ID, USER_PW)
        totpt = hotpt = None
        if totp:
            res = self.api.Command.otptoken_add(**{'all': True})['result']
            totpt = Token(res)
        if hotp:
            res = self.api.Command.otptoken_add(
                None, **{'type': u'hotp', 'all': True})['result']
            hotpt = Token(res)
        return (totpt, hotpt)

    def delete_token(self, token):
        self.api.Command.otptoken_del(token.tokenid, **{'continue': True})

    @screenshot
    def test_crud_admin(self):
        """
        Basic CRUD: OTPToken - admin
        """
        self.init_app()
        pkey = 'testkey'
        self.basic_crud(
            ENTITY,
            {
                'pkey': pkey,
                'add': [
                    ('callback', lambda args: self.check_visible_fields(False, True), None),
                    ('textbox', 'ipatokenuniqueid', pkey),
                    ('textbox', 'description', 'testtoken1'),
                    ('radio', 'type', 'hotp'),
                    ('callback', lambda args: self.check_visible_fields(False, False), None),
                ],
                'mod': [
                    ('textbox', 'ipatokenvendor', 'ipa tests'),
                ],
            },
            post_add_action=lambda: self.token_post_add())

    @screenshot
    def test_actions_admin(self):
        """
        Test 'enable', 'disable', 'delete' actions
        """
        token = self.api.Command.otptoken_add()['result']
        self.init_app()
        tokenid = token['ipatokenuniqueid'][0]
        self.navigate_to_record(tokenid, entity=ENTITY)
        self.disable_action('otp_disable')
        self.enable_action('otp_enable')
        self.delete_action(ENTITY, tokenid)

    @screenshot
    def test_crud_selfservice(self):
        """
        Basic CRUD: OTPToken - self-service
        """
        self.create_user(logout=False)

        data = {
            'pkey': 'unknown',
            'add': [
                ('callback', lambda args: self.check_visible_fields(True, True), None),
                ('radio', 'type', 'hotp'),
                ('textbox', 'description', 'testtoken2'),
                ('callback', lambda args: self.check_visible_fields(True, False), None),
            ],
            'mod': [
                ('textarea', 'description', 'foo'),
            ],
        }

        self.basic_crud(
            ENTITY, data,
            post_add_action=lambda: self.token_post_add(data)
        )

        # cleanup
        self.reconnect_api()
        self.delete_user(USER_ID)

    @screenshot
    def test_actions_selfservice(self):
        """
        Test 'delete' action - self-service
        """
        self.create_user(logout=False)
        totp, hotp = self.create_tokens(hotp=False)
        self.navigate_to_record(totp.tokenid, entity=ENTITY)
        self.delete_action(ENTITY, totp.tokenid)

        # cleanup
        self.reconnect_api()
        self.delete_user(USER_ID)

    def login_with_otp(self, token, at, success=True, logout=True):
        password = USER_PW + token.otp(at)
        self.login(USER_ID, password)
        loggedin = self.logged_in()
        if success:
            assert loggedin, '%s: user should be logged-in' % token.type
        else:
            assert not loggedin, '%s: user should not be logged-in' % token.type
        if logout:
            self.logout()

    @screenshot
    def test_login_otp(self):
        """
        Login with TOTP and HOTP tokens
        """

        self.create_user()
        # add tokens
        totp, hotp = self.create_tokens()

        # set auth to tokens
        self.reconnect_api()
        self.api.Command.user_mod(USER_ID, **{'ipauserauthtype': u'otp'})

        self.load()

        # fail just with password
        self.login(USER_ID, USER_PW)
        assert not self.logged_in(), 'Plain password: user incorrectly logged-in'

        # test otp login
        self.login_with_otp(totp, 0)
        self.login_with_otp(hotp, 0)
        hasher = hashlib.sha1

        self.wait(4)

        # cleanup
        self.reconnect_api()
        self.delete_user(USER_ID)

    def synchronize_token(self, token, at, success=True):
        """
        From login pages navigates to synchronize token page, fills the form,
        executes the action and checks result. Then tries to login.
        """

        if self.get_facet_info()["name"] == 'login':
            self._button_click("button[title='Sync OTP Token']", self.get_form())

        self.fill_input('user', USER_ID)
        self.fill_password('password', USER_PW)
        self.fill_password('first_code', token.otp(at))
        self.fill_password('second_code', token.otp(at + 1))
        self._button_click("button[title='Sync OTP Token']", self.get_form())
        self.wait_for_request()
        s = 'div.alert-danger[data-name=sync]'
        self.assert_visible(s, present=False, negative=success)
        if success:
            self.assert_facet(None, 'login')
            self.login_with_otp(token, at + 2)
        else:
            self.assert_facet(None, 'sync-otp')

    @screenshot
    def test_sync_token(self):
        """
        Sync TOTP and HOTP tokens using web ui form.
        """

        self.create_user()
        totp, hotp = self.create_tokens()

        # set auth to tokens
        self.reconnect_api()
        self.api.Command.user_mod(USER_ID, **{'ipauserauthtype': u'otp'})

        self.load()
        self.synchronize_token(totp, 20)
        self.synchronize_token(hotp, 20)

        # check distant future, expect fail, assumes that otp config is not
        # changed
        self.synchronize_token(totp, 1000000, success=False)
        self.synchronize_token(hotp, 2000, success=False)

        # cleanup
        self.reconnect_api()
        self.delete_token(totp)
        self.delete_token(hotp)
        self.delete_user(USER_ID)
