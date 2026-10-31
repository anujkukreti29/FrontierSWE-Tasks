"""Launch untrusted candidate code after dropping privileges.

A separate launcher avoids preexec_fn's fork-with-threads deadlock in tests
that run several candidates concurrently. Trusted verifier sources remain
root-owned and inaccessible to the launched candidate process.
"""
import os
import resource
import sys


def main():
    if len(sys.argv) < 2:
        raise SystemExit('candidate command required')
    if os.name == 'posix' and os.geteuid() == 0:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.execvpe(sys.argv[1], sys.argv[1:], os.environ)


if __name__ == '__main__':
    main()
