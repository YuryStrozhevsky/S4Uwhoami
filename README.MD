# Basic Information
The project _S4Uwhoami_ is a simple project which intended to show a way how to use S4U2Self in Windows for gathering information about all users in the domain. In order to do this the only function needed is _LsaLogonUser_.

# How To User
Just enter name of a any user or computer (without $ at the end).
```console
C:\> S4Uwhoami.exe Administrator

User:
=====
WDOMAIN\Administrator	S-1-5-21-4188712652-911564600-2864056775-500

Groups:
=======
WDOMAIN\Domain Users                           S-1-5-21-4188712652-911564600-2864056775-513
Everyone                                       S-1-1-0
BUILTIN\Users                                  S-1-5-32-545
BUILTIN\Administrators                         S-1-5-32-544
NT AUTHORITY\NETWORK                           S-1-5-2
NT AUTHORITY\Authenticated Users               S-1-5-11
NT AUTHORITY\This Organization                 S-1-5-15
NT AUTHORITY\LogonSessionId_0_36119956         S-1-5-5-0-36119956
WDOMAIN\Domain Admins                          S-1-5-21-4188712652-911564600-2864056775-512
WDOMAIN\Group Policy Creator Owners            S-1-5-21-4188712652-911564600-2864056775-520
WDOMAIN\Enterprise Admins                      S-1-5-21-4188712652-911564600-2864056775-519
WDOMAIN\Schema Admins                          S-1-5-21-4188712652-911564600-2864056775-518
Service asserted identity                      S-1-18-2
WDOMAIN\Denied RODC Password Replication Group S-1-5-21-4188712652-911564600-2864056775-572
Mandatory Label\High Mandatory Level           S-1-16-12288

Privileges:
===========
SeCreateTokenPrivilege                    Create a token object
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process
SeTcbPrivilege                            Act as part of the operating system
SeSecurityPrivilege                       Manage auditing and security log
SeTakeOwnershipPrivilege                  Take ownership of files or other objects
SeLoadDriverPrivilege                     Load and unload device drivers
SeSystemProfilePrivilege                  Profile system performance
SeSystemtimePrivilege                     Change the system time
SeProfileSingleProcessPrivilege           Profile single process
SeIncreaseBasePriorityPrivilege           Increase scheduling priority
SeCreatePagefilePrivilege                 Create a pagefile
SeBackupPrivilege                         Back up files and directories
SeRestorePrivilege                        Restore files and directories
SeShutdownPrivilege                       Shut down the system
SeDebugPrivilege                          Debug programs
SeSystemEnvironmentPrivilege              Modify firmware environment values
SeChangeNotifyPrivilege                   Bypass traverse checking
SeRemoteShutdownPrivilege                 Force shutdown from a remote system
SeUndockPrivilege                         Remove computer from docking station
SeManageVolumePrivilege                   Perform volume maintenance tasks
SeImpersonatePrivilege                    Impersonate a client after authentication
SeCreateGlobalPrivilege                   Create global objects
SeIncreaseWorkingSetPrivilege             Increase a process working set
SeTimeZonePrivilege                       Change the time zone
SeCreateSymbolicLinkPrivilege             Create symbolic links
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session

```
Also as a result in the current directory will be new file with name "<user_name>_token.xml". The format of the file is defined in my [**other project**](https://github.com/YuryStrozhevsky/XSEC).

# License
(c) 2024, Yury Strozhevsky
[yury@strozhevsky.com](mailto:yury@strozhevsky.com)

Anyone allowed to do whatever he/she want with the code.