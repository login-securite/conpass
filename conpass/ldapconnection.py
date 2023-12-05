# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import ldap
from ldap.controls import SimplePagedResultsControl
from datetime import datetime
import re

from conpass.pso import PSO
from conpass.user import User
from conpass.gpo import GPO
import struct

def convert(binary):
    version = struct.unpack('B', binary[0:1])[0]
    # I do not know how to treat version != 1 (it does not exist yet)
    assert version == 1, version
    length = struct.unpack('B', binary[1:2])[0]
    authority = struct.unpack(b'>Q', b'\x00\x00' + binary[2:8])[0]
    string = 'S-%d-%d' % (version, authority)
    binary = binary[8:]
    assert len(binary) == 4 * length
    for i in range(length):
        value = struct.unpack('<L', binary[4*i:4*(i+1)])[0]
        string += '-%d' % value
    return string


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
        self.psos = {}
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
            ldap_attributes = ['samAccountName', 'badPwdCount', 'badPasswordTime', 'distinguishedName', 'msDS-PSOApplied']
            res = self.get_paged_objects(filters, ldap_attributes)
            lockout_threshold, lockout_reset = self.get_password_policy(impacketfile)
            results = []

            for dn, entry in res:
                if isinstance(entry, dict) and entry['sAMAccountName'][0].decode('utf-8')[-1] != '$':
                    results.append(User(
                        samaccountname=entry['sAMAccountName'][0].decode('utf-8'),
                        dn=entry['distinguishedName'][0].decode('utf-8'),
                        bad_password_count=0 if 'badPwdCount' not in entry else int(entry['badPwdCount'][0]),
                        last_password_test=datetime(1970, 1, 1, 0, 00) if 'badPasswordTime' not in entry else datetime.fromtimestamp(int((int(entry['badPasswordTime'][0].decode('utf-8')) / 10000000 - 11644473600))),
                        lockout_threshold=lockout_threshold,
                        lockout_reset=lockout_reset,
                        pso=None if 'msDS-PSOApplied' not in entry else entry['msDS-PSOApplied']
                    ))
            groups = self.get_groups_pso([user.dn for user in results])
            return self.apply_pso(results, groups)

        except Exception as e:
            print(e)
            self.console.log("An error occurred while looking for users via LDAP")
            if self.debug:
                self.console.print_exception()
            return False

    def get_user_pso(self, user_dn):
        attributes = ['msDS-PSOApplied']
        res = self._conn.search_ext(
            user_dn,
            ldap.SCOPE_SUBTREE,
            attrlist=attributes
        )

        rtype, rdata, rmsgid, serverctrls = self._conn.result3(res)
        dn, entry = rdata[0]
        if 'msDS-PSOApplied' not in entry:
            return None

    def get_groups_pso(self, users):
        """
        1. Fetch all AD groups
        """
        attributes = ['msDS-PSOApplied', 'member', 'distinguishedName', 'objectSid']
        filters = "(objectClass=Group)"
        all_groups = self.get_paged_objects(filters, attributes)
        dict_groups = {}
        for group in all_groups:
            if 'objectSid' not in group[1]:
                continue
            group[1]['objectSid'][0] = convert(group[1]['objectSid'][0])
            dict_groups[group[0]] = group[1:]

        groups = {}
        """
        2. Check for groups with PSO applied
        """
        for group in all_groups:
            if 'msDS-PSOApplied' in group[1]:
                groups[group[0]] = group[1]

        """
        3. Get all PSO applied group members
        """
        for group in groups:
            groups[group]['user_members'] = self.find_members(groups[group], dict_groups, users)
        return groups

    def update_user(self, users, dn, applied_psos):
        for user in users:
            if user.dn == dn:
                if user.pso is None:
                    user.pso = applied_psos
                else:
                    user.pso = user.pso + applied_psos

    def apply_pso(self, users, groups):
        for group in groups:
            for user in groups[group]['user_members']:
                self.update_user(users, user, groups[group]['msDS-PSOApplied'])

        for user in users:
            user.pso = self.get_policy_from_psos(user.pso)
        return users

    def find_members(self, group, groups, users):
        members = []
        if group['objectSid'][0][-4:] == '-513':
            # Domain Users
            return users
        for member in group.get('member', []):
            if member.decode('utf-8') not in groups:
                members.append(member.decode('utf-8'))
            else:
                members = members + self.find_members(groups[member.decode('utf-8')][0], groups, users)
        return members

    def get_policy_from_psos(self, psos):
        parsed_psos = {}
        if psos is None:
            return parsed_psos
        attributes = ['msDS-LockoutThreshold', 'msDS-PasswordSettingsPrecedence', 'msDS-LockoutObservationWindow', 'msDS-LockoutDuration']
        for pso in psos:
            pso = pso.decode('utf-8')
            if pso in self.psos:
                parsed_psos[self.psos[pso].precedence] = self.psos[pso]
                continue
            res = self._conn.search_ext(
                pso,
                ldap.SCOPE_SUBTREE,
                attrlist=attributes
            )

            try:
                rtype, rdata, rmsgid, serverctrls = self._conn.result3(res)
            except ldap.NO_SUCH_OBJECT as e:
                self.psos[pso] = PSO(dn=pso, readable=False)
                continue
            dn, entry = rdata[0]
            if 'msDS-LockoutThreshold' not in entry:
                self.psos[pso] = PSO(dn=pso, readable=False)
            else:
                self.psos[pso] = PSO(
                    pso,
                    int(entry['msDS-LockoutThreshold'][0].decode('utf-8')),
                    int(entry['msDS-LockoutObservationWindow'][0].decode('utf-8')),
                    int(entry['msDS-LockoutDuration'][0].decode('utf-8')),
                    int(entry['msDS-PasswordSettingsPrecedence'][0].decode('utf-8'))
                )
                parsed_psos[self.psos[pso].precedence] = self.psos[pso]
        return parsed_psos

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

        if lockout_reset is None:
            lockout_reset = 0
        if lockout_threshold is None:
            lockout_threshold = 0

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
                self.debug and self.console.log(f"Trying to fetch {entry['gPCFileSysPath'][0].decode('utf-8')}")
                ret[dn.lower()] = GPO.get_password_policy(impacketfile, entry['gPCFileSysPath'][0].decode('utf-8'))
        return ret

    def get_paged_objects(self, filters, attributes):
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

