import argparse

from conpass import __version__
from conpass.core import ThreadPool


def main():
    # user = User(samaccountname='Administrator', last_password_test=None, lockout_threshold=0, bad_password_count=0)

    """
    Command line function to call conpass
    """
    version = __version__
    parser = argparse.ArgumentParser(
        prog="conpass",
        description='conpass v{} - Continuous password spraying tool'.format(__version__)
    )

    group_auth = parser.add_argument_group('Authentication')
    group_auth.add_argument('-u', '--username', action='store', help='Username', required=True)
    group_auth.add_argument('-p', '--password', action='store', help='Plaintext password', required=True)
    group_auth.add_argument('-d', '--domain', default="", action='store', help='Domain name', required=True)
    group_auth.add_argument('-dc-ip', action='store', metavar="ip address",
                            help='IP Address of the primary domain controller.')

    group_spray = parser.add_argument_group('Spray')
    group_spray.add_argument('-P', '--password-file', action='store', help='File containing passwords to test',
                            required=True)
    group_auth.add_argument('--threads', default=10, type=int, action='store', help='Threads number (Default 10)')

    group_info = parser.add_argument_group('Info')
    group_info.add_argument('-v', '--verbose', action='store_true', help='Get debug information')
    group_info.add_argument('-V', '--version', action='version', version='%(prog)s (version {})'.format(version))

    args = parser.parse_args()

    ThreadPool(args).run()


if __name__ == "__main__":
    main()
