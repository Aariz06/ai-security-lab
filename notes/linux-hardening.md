\# Ubuntu 26.04 Hardening



Changes made to a fresh Ubuntu 22.04 install, with the reasoning for each.



| # | Change | Before | After | Why it matters |

|---|---|---|---|---|

| 1 | Disabled SSH root login | `PermitRootLogin yes` | `PermitRootLogin no` | Removes the single most-targeted account from remote attack; forces an audit trail through named users + sudo |

| 2 | Disabled SSH password auth | `PasswordAuthentication yes` | `PasswordAuthentication no` | Defeats credential stuffing and brute force entirely, keys only |

| 3 | Limited SSH authentication attempts | `MaxAuthTries 6` (OpenSSH default) | `MaxAuthTries 3` | Drops the connection after 3 failed attempts instead of allowing unlimited guesses on one session |

| 4 | Locked an unused test account | `testuser` password hash active in `/etc/shadow` | Hash prefixed with `!` (`passwd -l testuser`) | Disables login without deleting the account, its files, or its group memberships, an audit trail stays intact |

| 5 | Enforced minimum password length | No minimum enforced (`pwquality.conf` default) | `minlen = 14` | Longer passwords resist brute-force and dictionary attacks |

| 6 | Required password character complexity | No character-class requirement | `dcredit = -1`, `ucredit = -1` | Requires at least one digit and one uppercase letter, closes off simple all-lowercase passwords |

| 7 | Enforced password aging policy | `PASS\_MAX\_DAYS 99999`, `PASS\_MIN\_DAYS 0` (Debian/Ubuntu default, passwords effectively never expire and can be changed instantly) | `PASS\_MAX\_DAYS 90`, `PASS\_MIN\_DAYS 1` | Caps how long a compromised password stays valid unnoticed, and the minimum stops someone changing it twice in a row just to cycle straight back to the old one |

| 8 | Enabled the firewall, default-deny incoming | `ufw` inactive | `ufw` active, deny incoming by default, allow outgoing, explicit allow on 22/tcp | \*(Fill in what you actually observed, see note below)\* |

| 9 | Enabled automatic security updates | `unattended-upgrades` not installed | Installed and configured via `dpkg-reconfigure` | Applies known security patches on a schedule without relying on memory, the most common way real servers get compromised is a known, unpatched vulnerability |



