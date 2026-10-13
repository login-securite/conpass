"""Build the list of accounts to spray, each with its effective password policy."""

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from conpass.config import SprayConfig
from conpass.lockout import DEFAULT_POLICY_NAME, PasswordPolicy, User
from conpass.output import console, success, warning
from conpass.protocols.ldap import LdapClient, LdapEntry, parse_lockout_state


@dataclass
class Targets:
    """Accounts to spray and the policies that apply to them."""

    users: list[User]
    policies: list[PasswordPolicy]  # default policy first, then the readable PSOs
    # Enabled users per policy name, including PSOs whose settings are not readable
    user_counts: Counter = field(default_factory=Counter)


def read_lines(path: Path) -> list[str]:
    """Non-empty lines of a file, stripped and deduplicated, in file order."""
    with path.open(encoding="utf-8", errors="replace") as file:
        return list(dict.fromkeys(line.strip() for line in file if line.strip()))


def load_from_file(config: SprayConfig) -> Targets:
    """Offline mode: users from --user-file, under the policy given on the command line."""
    policy = config.manual_policy
    users = [User(name, None, policy, config.security_threshold) for name in read_lines(config.user_file)]
    return Targets(users, [policy], Counter({policy.name: len(users)}))


def load_from_ldap(client: LdapClient, config: SprayConfig) -> Targets:
    """
    Online mode: enabled users read over LDAP, with their resultant policy.

    Users whose PSO is not readable are skipped: it may be stricter than the
    default policy. So are users whose lockout threshold leaves no attempt.
    """
    policies = [client.default_policy(), *client.password_settings_objects()]
    with console.status("Loading users over LDAP..."):
        entries = client.enabled_users()
    success(f"✓ {len(entries)} enabled users found")

    wanted = {name.lower() for name in read_lines(config.user_file)} if config.user_file else None
    by_name = {policy.name: policy for policy in policies}
    targets = Targets([], policies)
    skipped: Counter = Counter()
    for entry in entries:
        user = _build_user(entry, by_name, config, targets.user_counts, skipped)
        if user and _is_wanted(user.samaccountname, wanted, config):
            targets.users.append(user)
    for reason, count in skipped.items():
        warning(f"{count} user(s) skipped: {reason}")
    return targets


def _build_user(
    entry: LdapEntry,
    policies: dict[str, PasswordPolicy],
    config: SprayConfig,
    user_counts: Counter,
    skipped: Counter,
) -> User | None:
    """Create the User of an LDAP entry, None if it cannot be sprayed safely."""
    name = entry.get_str("sAMAccountName")
    pso_dn = entry.get_str("msDS-ResultantPSO")
    # CN=<name>,CN=Password Settings Container,...
    policy_name = pso_dn.split(",", 1)[0].removeprefix("CN=") if pso_dn else DEFAULT_POLICY_NAME
    user_counts[policy_name] += 1

    policy = policies.get(policy_name)
    if not name:
        return None
    if policy is None:
        skipped[f"settings of PSO '{policy_name}' not readable"] += 1
        return None
    if policy.has_lockout and policy.lockout_threshold <= config.security_threshold:
        skipped[
            f"lockout threshold of '{policy.name}' ({policy.lockout_threshold}) "
            f"<= security threshold ({config.security_threshold})"
        ] += 1
        return None
    return User(name, entry.dn, policy, config.security_threshold, parse_lockout_state(entry))


def _is_wanted(samaccountname: str, wanted: set[str] | None, config: SprayConfig) -> bool:
    # A failed attempt on the account used for LDAP could lock our own session out
    if samaccountname.lower() == config.credentials.username.lower():
        return False
    return wanted is None or samaccountname.lower() in wanted
