# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import ldap
from ldap.controls import SimplePagedResultsControl
from datetime import datetime
import re

from conpass.user import User
from conpass.gpo import GPO


class LdapConnection:
    def __init__(self, host, domain, username, password, console, port=None, ssl=False, page_size=200, debug=False):
        self.host = host
        self.domain = domain
        self.username = username
        self.password = password
        self.console = console
        self.ssl = ssl
        self.scheme = "ldaps" if self.ssl else "ldap"
        if port is None:
            self.port = 636 if self.ssl else 389
        else:
            self.port = port
        self.page_size = page_size
        self.domain_dn = None
        self._conn = None
        self.domain_threshold = 0
        self.granular_threshold = {}  # keys are policy DNs
        self.domain_dn = self.get_domain_dn()
        if self.domain_dn is None:
            self.console.log(f"Error: Unable to get domain DN from {self.domain}. Please provide full domain name (e.g. example.com)")
            exit(1)
        self.debug = debug

    def get_domain_dn(self):
        if '.' not in self.domain:
            return None
        return ','.join(['DC=' + part for part in self.domain.split('.')])

    def login(self):
        self._get_conn()
        if not self.username or not self.password or not self.domain:
            return None
        try:
            self._conn.simple_bind_s('{}@{}'.format(self.username, self.domain), self.password)
            return True
        except ldap.SERVER_DOWN:
            self.console.log("LDAP service unavailable on {}://{}:{}".format(self.scheme, self.host, self.port))
            if self.debug:
                self.console.print_exception()
            return False
        except ldap.INVALID_CREDENTIALS:
            self.console.log("Invalid LDAP credentials")
            if self.debug:
                self.console.print_exception()
            return False

    def test_credentials(self, username, password):

        self._get_conn()
        try:
            self._conn.simple_bind_s('{}@{}'.format(username, self.domain), password.value)
            return True
        except ldap.SERVER_DOWN:
            self.console.log("Service unavailable on {}://{}:{}".format(self.scheme, self.host, self.port))
            if self.debug:
                self.console.print_exception()
            return False
        except ldap.INVALID_CREDENTIALS:
            return False
        except Exception as e:
            self.console.log("Unexpected error while trying {}:{}".format(username, password.value))
            if self.debug:
                self.console.print_exception()
            return False

    def get_users(self, impacketfile, users=None, disabled=True):
        filters = ["(objectClass=User)"]
        if users:
            if len(users) == 1:
                filters.append("(samAccountName={})".format(users[0].lower()))
            else:
                filters.append("(|")
                filters.append("".join("(samAccountName={})".format(user.lower()) for user in users))
                filters.append(")")
        if not disabled:
            filters.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")

        if len(filters) > 1:
            filters = '(&' + ''.join(filters) + ')'
        else:
            filters = filters[0]
        try:
            ldap_attributes = ['samAccountName', 'badPwdCount', 'badPasswordTime', 'distinguishedName']
            res = self.get_paged_users(filters, ldap_attributes)
            lockout_threshold, lockout_reset = self.get_password_policy(impacketfile)
            results = [
                User(
                    samaccountname=entry['sAMAccountName'][0].decode('utf-8'),
                    bad_password_count=0 if 'badPwdCount' not in entry else int(entry['badPwdCount'][0]),
                    last_password_test=datetime.fromtimestamp(int((int(entry['badPasswordTime'][0].decode('utf-8')) / 10000000 - 11644473600))),
                    lockout_threshold=lockout_threshold,
                    lockout_reset=lockout_reset
                ) for dn, entry in res if isinstance(entry, dict) and entry['sAMAccountName'][0].decode('utf-8')[-1] != '$'
            ]

            return results
        except Exception as e:
            self.console.log("An error occurred while looking for users via LDAP")
            if self.debug:
                self.console.print_exception()
            return False

    def get_password_policy(self, impacketfile):
        filters = "(&(distinguishedName={}))".format(self.domain_dn)
        attributes = ['distinguishedName', 'gPLink', 'gPOptions']

        res = self._conn.search_ext(
            self.domain_dn,
            ldap.SCOPE_SUBTREE,
            filters,
            attributes
        )
        _, rdata, _, _ = self._conn.result3(res)
        dn, entry = rdata[0]

        gpo_distinguished_names = [dn.lower() for dn, options in re.compile(r'\[LDAP://(cn=.*?);(\d+)]').findall(entry['gPLink'][0].decode('utf-8'))]

        gpos = self.get_gpos_filepath(impacketfile, gpo_distinguished_names)
        self.console.log(f"{len(gpo_distinguished_names)} GPOs linked to root domain - {len([gpo for gpo in gpos if gpos[gpo] != (None, None)])} have a password policy")

        if 'gPLink' not in entry:
            return []
        res = [GPO(dn.lower(), int(options), *gpos[dn.lower()]) for dn, options in re.compile(r'\[LDAP://(cn=.*?);(\d+)]').findall(entry['gPLink'][0].decode('utf-8'))]

        lockout_threshold, lockout_reset = None, None
        for gpo in res:
            if gpo.options & GPO.GPLINK_OPT_DISABLE:
                continue
            if gpo.lockout_threshold is not None:
                lockout_threshold = gpo.lockout_threshold
            if gpo.lockout_reset is not None:
                lockout_reset = gpo.lockout_reset

        return lockout_threshold, lockout_reset

    def get_gpos_filepath(self, impacketfile, distinguished_names):
        filters = "(&(objectClass=groupPolicyContainer))"
        attributes = ['distinguishedName', 'gPCFileSysPath']
        res = self._conn.search_ext(
            self.domain_dn,
            ldap.SCOPE_SUBTREE,
            filters,
            attributes
        )
        rtype, rdata, rmsgid, serverctrls = self._conn.result3(res)
        ret = {}
        for dn, entry in rdata:
            if isinstance(entry, dict) and 'gPCFileSysPath' in entry and dn.lower() in distinguished_names:
                ret[dn.lower()] = GPO.get_password_policy(impacketfile, entry['gPCFileSysPath'][0].decode('utf-8'))
        return ret

    def get_paged_users(self, filters, attributes):
        pages = 0
        result = []

        page_control = SimplePagedResultsControl(True, size=self.page_size, cookie='')
        res = self._conn.search_ext(
            self.domain_dn,
            ldap.SCOPE_SUBTREE,
            filters,
            attributes,
            serverctrls=[page_control]
        )

        while True:
            pages += 1
            rtype, rdata, rmsgid, serverctrls = self._conn.result3(res)
            result.extend(rdata)
            controls = [ctrl for ctrl in serverctrls if ctrl.controlType == SimplePagedResultsControl.controlType]
            if not controls:
                self.console.log('The server ignores RFC 2696 control')
                break
            if not controls[0].cookie:
                break
            page_control.cookie = controls[0].cookie
            res = self._conn.search_ext(
                self.domain_dn,
                ldap.SCOPE_SUBTREE,
                filters,
                attributes,
                serverctrls=[page_control]
            )
        return result

    def _get_conn(self):
        if self._conn is not None:
            return True
        self._conn = ldap.initialize('{}://{}:{}'.format(self.scheme, self.host, self.port))
        self._conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 3.0)
        self._conn.protocol_version = 3
        self._conn.set_option(ldap.OPT_REFERRALS, 0)
        return True

