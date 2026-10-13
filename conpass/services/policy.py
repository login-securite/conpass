from datetime import timedelta

from rich.console import Console

from conpass.models import PasswordPolicy, User
from conpass.services.ldap import (
    LOCKOUT_ATTRIBUTES,
    LdapService,
    parse_lockout_state,
    raw_attributes,
    raw_str,
)
from conpass.utils import dc_now


class PolicyService:
    """Service for managing password policies and building user lists."""

    def __init__(
        self,
        ldap_service: LdapService,
        security_threshold: int,
        time_delta: timedelta,
        console: Console | None = None
    ):
        self.ldap_service = ldap_service
        self.security_threshold = security_threshold
        self.time_delta = time_delta
        self.console = console

        self._default_policy: PasswordPolicy | None = None
        self._psos: list[PasswordPolicy] = []
        self._pso_user_counts: dict[str, int] = {}

    def load_policies(self) -> None:
        """Load default domain policy and PSOs from LDAP."""
        self._default_policy = self.ldap_service.get_default_domain_policy()
        self._psos = self.ldap_service.get_password_setting_objects()

    def get_default_policy(self) -> PasswordPolicy:
        """Get the default domain password policy."""
        if not self._default_policy:
            raise ValueError("Policies not loaded. Call load_policies() first.")
        return self._default_policy

    def get_psos(self) -> list[PasswordPolicy]:
        """Get all Password Settings Objects."""
        return self._psos

    def get_pso_user_counts(self) -> dict[str, int]:
        """Get dictionary of PSO names to user counts."""
        return self._pso_user_counts

    def can_read_pso(self) -> bool:
        """Check if we can read PSO details."""
        return self.ldap_service.can_read_pso()

    def build_user_list(self, user_filter: list[str] | None = None) -> list[User]:
        """
        Build list of enabled users to spray based on policies.

        Args:
            user_filter: Optional list of usernames to filter (only these users will be returned)

        Returns:
            List of User objects ready for spraying
        """
        if not self._default_policy:
            raise ValueError("Policies not loaded. Call load_policies() first.")

        search_filter = (
            "(&(objectCategory=person)(objectClass=user)(!(sAMAccountName=*$))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        attributes = ['sAMAccountName', 'msDS-ResultantPSO', *LOCKOUT_ATTRIBUTES]
        entries = self.ldap_service.search_users(search_filter, attributes)

        wanted = {name.lower() for name in user_filter} if user_filter else None
        own_account = self.ldap_service.credentials.username.split('\\')[-1].lower()
        skipped_unknown_pso: dict[str, int] = {}
        users = []

        for entry in entries:
            raw = raw_attributes(entry)
            samaccountname = raw_str(raw, 'sAMAccountName')
            pso_dn = raw_str(raw, 'msDS-ResultantPSO')
            pso_name = pso_dn.split(',')[0][3:] if pso_dn else None
            if pso_name:
                self._pso_user_counts[pso_name] = self._pso_user_counts.get(pso_name, 0) + 1

            if not self._is_wanted(samaccountname, wanted, own_account):
                continue
            policy = self._get_user_policy(pso_name)
            if policy is None:
                # Never guess the policy of a PSO we cannot read: it may be stricter
                skipped_unknown_pso[pso_name] = skipped_unknown_pso.get(pso_name, 0) + 1
                continue
            if self._threshold_too_low(samaccountname, policy):
                continue

            users.append(User(
                samaccountname=samaccountname,
                dn=entry['dn'],
                policy=policy,
                security_threshold=self.security_threshold,
                state=parse_lockout_state(raw),
            ))

        if self.console:
            for pso_name, count in skipped_unknown_pso.items():
                self.console.print(
                    f"[yellow]{count} user(s) under PSO '{pso_name}' skipped: PSO details not readable[/yellow]"
                )

        return users

    @staticmethod
    def _is_wanted(samaccountname: str | None, wanted: set[str] | None, own_account: str) -> bool:
        # Authenticating with the sprayed account resets its counter: skip it
        if not samaccountname or samaccountname.lower() == own_account:
            return False
        return wanted is None or samaccountname.lower() in wanted

    def _threshold_too_low(self, samaccountname: str, policy: PasswordPolicy) -> bool:
        if not 0 < policy.lockout_threshold <= self.security_threshold:
            return False
        if self.console:
            self.console.print(
                f"[yellow]{samaccountname} discarded: "
                f"Lockout threshold ({policy.lockout_threshold}) <= "
                f"security threshold ({self.security_threshold})[/yellow]"
            )
        return True

    def _get_user_policy(self, pso_name: str | None) -> PasswordPolicy | None:
        """
        Get the password policy for a user.

        Args:
            pso_name: Name of the PSO applied to the user (None for default policy)

        Returns:
            PasswordPolicy object, None if the user's PSO is unknown
        """
        if not pso_name:
            return self._default_policy
        for pso in self._psos:
            if pso.name == pso_name:
                return pso
        return None

    def print_user_stats(self, users: list[User]) -> None:
        """Print the distribution of effective bad password counts."""
        from rich.table import Table

        if not users or not self.console:
            return
        now = dc_now(self.time_delta)
        counts: dict[str, int] = {}
        for user in users:
            key = 'locked out' if user.lockout_end(now) else str(user.effective_bad_count(now))
            counts[key] = counts.get(key, 0) + 1

        table = Table()
        table.add_column('Effective Bad Password Count')
        table.add_column('Total Users')
        for key in sorted(counts, key=lambda k: (not k.isdigit(), int(k) if k.isdigit() else 0)):
            table.add_row(key, str(counts[key]))
        self.console.print(table)
