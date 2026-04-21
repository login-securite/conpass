from datetime import datetime, timedelta, timezone

from rich.console import Console

from conpass.models import PasswordPolicy, User, UserStatus
from conpass.services.ldap import LdapService


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
        Build list of users to spray based on policies.

        Args:
            user_filter: Optional list of usernames to filter (only these users will be returned)

        Returns:
            List of User objects ready for spraying
        """
        if not self._default_policy:
            raise ValueError("Policies not loaded. Call load_policies() first.")

        search_filter = "(&(objectClass=user)(!(sAMAccountName=*$)))"
        attributes = [
            'samAccountName',
            'badPwdCount',
            'badPasswordTime',
            'lockoutTime',
            'distinguishedName',
            'msDS-ResultantPSO',
            'userAccountControl'
        ]

        entries = self.ldap_service.search_users(search_filter, attributes)
        users = []

        stats = {
            'enabled': 0,
            'disabled': 0,
            'locked': 0,
            'pso_users': {},
            'discarded_low_threshold': 0,
        }

        for entry in entries:
            # Skip disabled accounts
            if (entry.userAccountControl.value or 0) & 2:
                stats['disabled'] += 1
                continue

            stats['enabled'] += 1

            # Skip locked accounts
            if (entry.userAccountControl.value or 0) & 16:
                stats['locked'] += 1
                continue

            samaccountname = entry.samAccountName.value

            # Track PSO users
            pso_name = None
            if entry['msDS-ResultantPSO']:
                pso_name = entry['msDS-ResultantPSO'].value.split(',')[0][3:]
                stats['pso_users'][pso_name] = stats['pso_users'].get(pso_name, 0) + 1

                # Skip if we can't read PSO details
                if not self.ldap_service.can_read_pso():
                    continue

            # Skip current user (the one running the tool)
            if samaccountname.lower() == self.ldap_service.credentials.username.lower():
                continue

            # Apply user filter if provided
            if user_filter and samaccountname not in user_filter:
                continue

            # Determine policy for this user
            policy = self._get_user_policy(pso_name)

            # Skip users with low lockout threshold
            if 0 < policy.lockout_threshold <= self.security_threshold:
                if self.console:
                    self.console.print(
                        f"[yellow]{samaccountname} discarded: "
                        f"Lockout threshold ({policy.lockout_threshold}) <= "
                        f"security threshold ({self.security_threshold})[/yellow]"
                    )
                stats['discarded_low_threshold'] += 1
                continue

            # Create user object
            user = User(
                samaccountname=samaccountname,
                dn=entry.distinguishedName.value,
                policy=policy,
                bad_password_count=entry.badPwdCount.value if entry.badPwdCount.value is not None else 0,
                bad_password_time=entry.badPasswordTime.value if entry.badPasswordTime.value else datetime(1970, 1, 1, tzinfo=timezone.utc),
                time_delta=self.time_delta,
                security_threshold=self.security_threshold,
                lockout_time=entry.lockoutTime.value if entry.lockoutTime and entry.lockoutTime.value else datetime(1970, 1, 1, tzinfo=timezone.utc),
            )

            users.append(user)

        # Store PSO user counts
        self._pso_user_counts = stats['pso_users']

        # Print statistics if console available
        if self.console:
            self._print_user_stats(stats, users)

        return users

    def _get_user_policy(self, pso_name: str | None) -> PasswordPolicy:
        """
        Get the password policy for a user.

        Args:
            pso_name: Name of the PSO applied to the user (None for default policy)

        Returns:
            PasswordPolicy object
        """
        if pso_name:
            for pso in self._psos:
                if pso.name == pso_name:
                    return pso
            if self.console:
                self.console.print(f"[yellow]PSO '{pso_name}' not found, using default policy[/yellow]")

        return self._default_policy

    def _print_user_stats(self, stats: dict, users: list[User]) -> None:
        """Print user statistics to console."""
        from rich.table import Table

        # Bad password count distribution
        badpwd_counts = {}
        for user in users:
            count = user.get_bad_password_count()
            badpwd_counts[count] = badpwd_counts.get(count, 0) + 1

        if badpwd_counts:
            table = Table()
            table.add_column('Bad Password Count')
            table.add_column('Total Users')
            for count in sorted(badpwd_counts.keys()):
                table.add_row(str(count), str(badpwd_counts[count]))
            self.console.print(table)
