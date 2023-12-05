# Check that the device group is enabled
$GroupName = "Allowed Login Users"
$GroupDescription = "Users who can locally login to this device"

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}

# Write prompt to the user to see if we should continue
Write-Warning "This script will make changes to the local device security policy and sets the 'Allowed Log on locally' policy to only permit users within the 'Administrators', 'Backup Operators', 'Guests' and '$GroupName' group." -WarningAction Inquire


# Region Functions
Add-Type -TypeDefinition @'
using System;
namespace PS_LSA
{
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Principal;
    using LSA_HANDLE = IntPtr;

    public enum Rights
    {
        SeTrustedCredManAccessPrivilege,             // Access Credential Manager as a trusted caller
        SeNetworkLogonRight,                         // Access this computer from the network
        SeTcbPrivilege,                              // Act as part of the operating system
        SeMachineAccountPrivilege,                   // Add workstations to domain
        SeIncreaseQuotaPrivilege,                    // Adjust memory quotas for a process
        SeInteractiveLogonRight,                     // Allow log on locally
        SeRemoteInteractiveLogonRight,               // Allow log on through Remote Desktop Services
        SeBackupPrivilege,                           // Back up files and directories
        SeChangeNotifyPrivilege,                     // Bypass traverse checking
        SeSystemtimePrivilege,                       // Change the system time
        SeTimeZonePrivilege,                         // Change the time zone
        SeCreatePagefilePrivilege,                   // Create a pagefile
        SeCreateTokenPrivilege,                      // Create a token object
        SeCreateGlobalPrivilege,                     // Create global objects
        SeCreatePermanentPrivilege,                  // Create permanent shared objects
        SeCreateSymbolicLinkPrivilege,               // Create symbolic links
        SeDebugPrivilege,                            // Debug programs
        SeDenyNetworkLogonRight,                     // Deny access this computer from the network
        SeDenyBatchLogonRight,                       // Deny log on as a batch job
        SeDenyServiceLogonRight,                     // Deny log on as a service
        SeDenyInteractiveLogonRight,                 // Deny log on locally
        SeDenyRemoteInteractiveLogonRight,           // Deny log on through Remote Desktop Services
        SeEnableDelegationPrivilege,                 // Enable computer and user accounts to be trusted for delegation
        SeRemoteShutdownPrivilege,                   // Force shutdown from a remote system
        SeAuditPrivilege,                            // Generate security audits
        SeImpersonatePrivilege,                      // Impersonate a client after authentication
        SeIncreaseWorkingSetPrivilege,               // Increase a process working set
        SeIncreaseBasePriorityPrivilege,             // Increase scheduling priority
        SeLoadDriverPrivilege,                       // Load and unload device drivers
        SeLockMemoryPrivilege,                       // Lock pages in memory
        SeBatchLogonRight,                           // Log on as a batch job
        SeServiceLogonRight,                         // Log on as a service
        SeSecurityPrivilege,                         // Manage auditing and security log
        SeRelabelPrivilege,                          // Modify an object label
        SeSystemEnvironmentPrivilege,                // Modify firmware environment values
        SeDelegateSessionUserImpersonatePrivilege,   // Obtain an impersonation token for another user in the same session
        SeManageVolumePrivilege,                     // Perform volume maintenance tasks
        SeProfileSingleProcessPrivilege,             // Profile single process
        SeSystemProfilePrivilege,                    // Profile system performance
        SeUnsolicitedInputPrivilege,                 // "Read unsolicited input from a terminal device"
        SeUndockPrivilege,                           // Remove computer from docking station
        SeAssignPrimaryTokenPrivilege,               // Replace a process level token
        SeRestorePrivilege,                          // Restore files and directories
        SeShutdownPrivilege,                         // Shut down the system
        SeSyncAgentPrivilege,                        // Synchronize directory service data
        SeTakeOwnershipPrivilege                     // Take ownership of files or other objects
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_ENUMERATION_INFORMATION
    {
        internal IntPtr PSid;
    }

    internal sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaAddAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaRemoveAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            out IntPtr /*LSA_UNICODE_STRING[]*/ UserRights,
            out ulong CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountsWithUserRight(
            LSA_HANDLE PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out ulong CountReturned
        );

        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);
    }

    internal sealed class Sid : IDisposable
    {
        public IntPtr pSid = IntPtr.Zero;
        public SecurityIdentifier sid = null;

        public Sid(string account)
        {
            try { sid = new SecurityIdentifier(account); }
            catch { sid = (SecurityIdentifier)(new NTAccount(account)).Translate(typeof(SecurityIdentifier)); }
            Byte[] buffer = new Byte[sid.BinaryLength];
            sid.GetBinaryForm(buffer, 0);

            pSid = Marshal.AllocHGlobal(sid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, sid.BinaryLength);
        }

        public void Dispose()
        {
            if (pSid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pSid);
                pSid = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~Sid() { Dispose(); }
    }

    public sealed class LsaWrapper : IDisposable
    {
        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034;
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001a;

        IntPtr lsaHandle;

        public LsaWrapper() : this(null) { } // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void AddPrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaAddAccountRights(lsaHandle, sid.pSid, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void RemovePrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaRemoveAccountRights(lsaHandle, sid.pSid, false, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public Rights[] EnumerateAccountPrivileges(string account)
        {
            uint ret = 0;
            ulong count = 0;
            IntPtr privileges = IntPtr.Zero;
            Rights[] rights = null;

            using (Sid sid = new Sid(account))
            {
                ret = Win32Sec.LsaEnumerateAccountRights(lsaHandle, sid.pSid, out privileges, out count);
            }
            if (ret == 0)
            {
                rights = new Rights[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_UNICODE_STRING str = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        IntPtr.Add(privileges, i * Marshal.SizeOf(typeof(LSA_UNICODE_STRING))),
                        typeof(LSA_UNICODE_STRING));
                    rights[i] = (Rights)Enum.Parse(typeof(Rights), str.Buffer);
                }
                Win32Sec.LsaFreeMemory(privileges);
                return rights;
            }
            if (ret == STATUS_OBJECT_NAME_NOT_FOUND) return null;  // No privileges assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public string[] EnumerateAccountsWithUserRight(Rights privilege, bool resolveSid = true)
        {
            uint ret = 0;
            ulong count = 0;
            LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
            rights[0] = InitLsaString(privilege.ToString());
            IntPtr buffer = IntPtr.Zero;
            string[] accounts = null;

            ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, rights, out buffer, out count);
            if (ret == 0)
            {
                accounts = new string[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_ENUMERATION_INFORMATION LsaInfo = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, i * Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION))),
                        typeof(LSA_ENUMERATION_INFORMATION));

                        if (resolveSid) {
                            try {
                                accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).Translate(typeof(NTAccount)).ToString();
                            } catch (System.Security.Principal.IdentityNotMappedException) {
                                accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString();
                            }
                        } else { accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString(); }
                }
                Win32Sec.LsaFreeMemory(buffer);
                return accounts;
            }
            if (ret == STATUS_NO_MORE_ENTRIES) return null;  // No accounts assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper() { Dispose(); }

        // helper functions:
        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe) throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }

    public sealed class TokenManipulator
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        internal sealed class Win32Token
        {
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(
                IntPtr htok,
                bool disall,
                ref TokPriv1Luid newst,
                int len,
                IntPtr prev,
                IntPtr relen
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern IntPtr GetCurrentProcess();

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(
                IntPtr h,
                int acc,
                ref IntPtr phtok
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(
                string host,
                string name,
                ref long pluid
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern bool CloseHandle(
                IntPtr phtok
            );
        }

        public static void AddPrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }

        public static void RemovePrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_DISABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }
    }
}
'@ # This type (PS_LSA) is used by Grant-UserRight, Revoke-UserRight, Get-UserRightsGrantedToAccount, Get-AccountsWithUserRight, Grant-TokenPriviledge, Revoke-TokenPrivilege

function Convert-SIDtoName([String[]] $SIDs, [bool] $OnErrorReturnSID) {
    foreach ($sid in $SIDs) {
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid) 
            $objUser = $objSID.Translate([System.Security.Principal.NTAccount]) 
            $objUser.Value
        } catch { if ($OnErrorReturnSID) { $sid } else { "" } }
    }
}

function Grant-UserRight {
    <#
     .SYNOPSIS
       Assigns user rights to accounts
     .DESCRIPTION
       Assigns one or more user rights (privileges) to one or more accounts. If you specify privileges already granted to the account, they are ignored.
     .PARAMETER Account
       Logon name of the account. More than one account can be listed. If the account is not found on the computer, the default domain is searched. To specify a domain, you may use either "DOMAIN\username" or "username@domain.dns" formats. SIDs may be also be specified.
     .PARAMETER Right
       Name of the right to grant. More than one right may be listed.
   
       Possible values: 
         SeTrustedCredManAccessPrivilege              Access Credential Manager as a trusted caller
         SeNetworkLogonRight                          Access this computer from the network
         SeTcbPrivilege                               Act as part of the operating system
         SeMachineAccountPrivilege                    Add workstations to domain
         SeIncreaseQuotaPrivilege                     Adjust memory quotas for a process
         SeInteractiveLogonRight                      Allow log on locally
         SeRemoteInteractiveLogonRight                Allow log on through Remote Desktop Services
         SeBackupPrivilege                            Back up files and directories
         SeChangeNotifyPrivilege                      Bypass traverse checking
         SeSystemtimePrivilege                        Change the system time
         SeTimeZonePrivilege                          Change the time zone
         SeCreatePagefilePrivilege                    Create a pagefile
         SeCreateTokenPrivilege                       Create a token object
         SeCreateGlobalPrivilege                      Create global objects
         SeCreatePermanentPrivilege                   Create permanent shared objects
         SeCreateSymbolicLinkPrivilege                Create symbolic links
         SeDebugPrivilege                             Debug programs
         SeDenyNetworkLogonRight                      Deny access this computer from the network
         SeDenyBatchLogonRight                        Deny log on as a batch job
         SeDenyServiceLogonRight                      Deny log on as a service
         SeDenyInteractiveLogonRight                  Deny log on locally
         SeDenyRemoteInteractiveLogonRight            Deny log on through Remote Desktop Services
         SeEnableDelegationPrivilege                  Enable computer and user accounts to be trusted for delegation
         SeRemoteShutdownPrivilege                    Force shutdown from a remote system
         SeAuditPrivilege                             Generate security audits
         SeImpersonatePrivilege                       Impersonate a client after authentication
         SeIncreaseWorkingSetPrivilege                Increase a process working set
         SeIncreaseBasePriorityPrivilege              Increase scheduling priority
         SeLoadDriverPrivilege                        Load and unload device drivers
         SeLockMemoryPrivilege                        Lock pages in memory
         SeBatchLogonRight                            Log on as a batch job
         SeServiceLogonRight                          Log on as a service
         SeSecurityPrivilege                          Manage auditing and security log
         SeRelabelPrivilege                           Modify an object label
         SeSystemEnvironmentPrivilege                 Modify firmware environment values
         SeDelegateSessionUserImpersonatePrivilege    Obtain an impersonation token for another user in the same session
         SeManageVolumePrivilege                      Perform volume maintenance tasks
         SeProfileSingleProcessPrivilege              Profile single process
         SeSystemProfilePrivilege                     Profile system performance
         SeUnsolicitedInputPrivilege                  "Read unsolicited input from a terminal device"
         SeUndockPrivilege                            Remove computer from docking station
         SeAssignPrimaryTokenPrivilege                Replace a process level token
         SeRestorePrivilege                           Restore files and directories
         SeShutdownPrivilege                          Shut down the system
         SeSyncAgentPrivilege                         Synchronize directory service data
         SeTakeOwnershipPrivilege                     Take ownership of files or other objects
     .PARAMETER Computer
       Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
     .EXAMPLE
       Grant-UserRight "bilbo.baggins" SeServiceLogonRight
   
       Grants bilbo.baggins the "Logon as a service" right on the local computer.
     .EXAMPLE
       Grant-UserRight -Account "Edward","Karen" -Right SeServiceLogonRight,SeCreateTokenPrivilege -Computer TESTPC
   
       Grants both Edward and Karen, "Logon as a service" and "Create a token object" rights on the TESTPC system.
     .EXAMPLE
       Grant-UserRight -Account "S-1-1-0" -Right SeNetworkLogonRight
   
       Grants "Everyone" the "Access this computer from the network" right on the local computer.
     .INPUTS
       String Account
       PS_LSA.Rights Right
       String Computer
     .OUTPUTS
       None
     .LINK
       http://msdn.microsoft.com/en-us/library/ms721786.aspx
       http://msdn.microsoft.com/en-us/library/bb530716.aspx
    #>
       [CmdletBinding(SupportsShouldProcess=$true)]
       param (
           [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
           [Alias('User','Username','SID')][String[]] $Account,
           [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
           [Alias('Privilege')] [PS_LSA.Rights[]] $Right,
           [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
           [Alias('System','ComputerName','Host')][String] $Computer
       )
       process {
           $lsa = New-Object PS_LSA.LsaWrapper($Computer)
           foreach ($Acct in $Account) {
               foreach ($Priv in $Right) {
                   if ($PSCmdlet.ShouldProcess($Acct, "Grant $Priv right")) { $lsa.AddPrivilege($Acct,$Priv) }
               }
           }
       }
} # Assigns user rights to accounts
   
function Revoke-UserRight {
<#
    .SYNOPSIS
    Removes user rights from accounts
    .DESCRIPTION
    Removes one or more user rights (privileges) from one or more accounts. If you specify privileges not held by the account, they are ignored.
    .PARAMETER Account
    Logon name of the account. More than one account can be listed. If the account is not found on the computer, the default domain is searched. To specify a domain, you may use either "DOMAIN\username" or "username@domain.dns" formats. SIDs may be also be specified.
    .PARAMETER Right
    Name of the right to revoke. More than one right may be listed.

    Possible values: 
        SeTrustedCredManAccessPrivilege              Access Credential Manager as a trusted caller
        SeNetworkLogonRight                          Access this computer from the network
        SeTcbPrivilege                               Act as part of the operating system
        SeMachineAccountPrivilege                    Add workstations to domain
        SeIncreaseQuotaPrivilege                     Adjust memory quotas for a process
        SeInteractiveLogonRight                      Allow log on locally
        SeRemoteInteractiveLogonRight                Allow log on through Remote Desktop Services
        SeBackupPrivilege                            Back up files and directories
        SeChangeNotifyPrivilege                      Bypass traverse checking
        SeSystemtimePrivilege                        Change the system time
        SeTimeZonePrivilege                          Change the time zone
        SeCreatePagefilePrivilege                    Create a pagefile
        SeCreateTokenPrivilege                       Create a token object
        SeCreateGlobalPrivilege                      Create global objects
        SeCreatePermanentPrivilege                   Create permanent shared objects
        SeCreateSymbolicLinkPrivilege                Create symbolic links
        SeDebugPrivilege                             Debug programs
        SeDenyNetworkLogonRight                      Deny access this computer from the network
        SeDenyBatchLogonRight                        Deny log on as a batch job
        SeDenyServiceLogonRight                      Deny log on as a service
        SeDenyInteractiveLogonRight                  Deny log on locally
        SeDenyRemoteInteractiveLogonRight            Deny log on through Remote Desktop Services
        SeEnableDelegationPrivilege                  Enable computer and user accounts to be trusted for delegation
        SeRemoteShutdownPrivilege                    Force shutdown from a remote system
        SeAuditPrivilege                             Generate security audits
        SeImpersonatePrivilege                       Impersonate a client after authentication
        SeIncreaseWorkingSetPrivilege                Increase a process working set
        SeIncreaseBasePriorityPrivilege              Increase scheduling priority
        SeLoadDriverPrivilege                        Load and unload device drivers
        SeLockMemoryPrivilege                        Lock pages in memory
        SeBatchLogonRight                            Log on as a batch job
        SeServiceLogonRight                          Log on as a service
        SeSecurityPrivilege                          Manage auditing and security log
        SeRelabelPrivilege                           Modify an object label
        SeSystemEnvironmentPrivilege                 Modify firmware environment values
        SeDelegateSessionUserImpersonatePrivilege    Obtain an impersonation token for another user in the same session
        SeManageVolumePrivilege                      Perform volume maintenance tasks
        SeProfileSingleProcessPrivilege              Profile single process
        SeSystemProfilePrivilege                     Profile system performance
        SeUnsolicitedInputPrivilege                  "Read unsolicited input from a terminal device"
        SeUndockPrivilege                            Remove computer from docking station
        SeAssignPrimaryTokenPrivilege                Replace a process level token
        SeRestorePrivilege                           Restore files and directories
        SeShutdownPrivilege                          Shut down the system
        SeSyncAgentPrivilege                         Synchronize directory service data
        SeTakeOwnershipPrivilege                     Take ownership of files or other objects
    .PARAMETER Computer
    Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
    .EXAMPLE
    Revoke-UserRight "bilbo.baggins" SeServiceLogonRight

    Removes the "Logon as a service" right from bilbo.baggins on the local computer.
    .EXAMPLE
    Revoke-UserRight "S-1-5-21-3108507890-3520248245-2556081279-1001" SeServiceLogonRight

    Removes the "Logon as a service" right from the specified SID on the local computer.
    .EXAMPLE
    Revoke-UserRight -Account "Edward","Karen" -Right SeServiceLogonRight,SeCreateTokenPrivilege -Computer TESTPC

    Removes the "Logon as a service" and "Create a token object" rights from both Edward and Karen on the TESTPC system.
    .EXAMPLE
    Revoke-UserRight -Account "S-1-1-0" -Right SeNetworkLogonRight

    Removes the "Access this computer from the network" right from "Everyone" on the local computer.
    .INPUTS
    String Account
    PS_LSA.Rights Right
    String Computer
    .OUTPUTS
    None
    .LINK
    http://msdn.microsoft.com/en-us/library/ms721809.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
#>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('User','Username','SID')][String[]] $Account,
        [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('Privilege')] [PS_LSA.Rights[]] $Right,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Acct in $Account) {
            foreach ($Priv in $Right) {
                if ($PSCmdlet.ShouldProcess($Acct, "Revoke $Priv right")) { $lsa.RemovePrivilege($Acct,$Priv) }
            }
        }
    }
} # Removes user rights from accounts

function Get-AccountsWithUserRight {
    <#
     .SYNOPSIS
       Gets all accounts that are assigned a specified privilege
     .DESCRIPTION
       Retrieves a list of all accounts that hold a specified right (privilege). The accounts returned are those that hold the specified privilege directly through the user account, not as part of membership to a group. A list of SIDs and account names is returned. For each SID that cannot be resolved to a name, the Account property is set to an empty string ("").
     .PARAMETER Right
       Name of the right to query. More than one right may be listed.
   
       Possible values: 
         SeTrustedCredManAccessPrivilege              Access Credential Manager as a trusted caller
         SeNetworkLogonRight                          Access this computer from the network
         SeTcbPrivilege                               Act as part of the operating system
         SeMachineAccountPrivilege                    Add workstations to domain
         SeIncreaseQuotaPrivilege                     Adjust memory quotas for a process
         SeInteractiveLogonRight                      Allow log on locally
         SeRemoteInteractiveLogonRight                Allow log on through Remote Desktop Services
         SeBackupPrivilege                            Back up files and directories
         SeChangeNotifyPrivilege                      Bypass traverse checking
         SeSystemtimePrivilege                        Change the system time
         SeTimeZonePrivilege                          Change the time zone
         SeCreatePagefilePrivilege                    Create a pagefile
         SeCreateTokenPrivilege                       Create a token object
         SeCreateGlobalPrivilege                      Create global objects
         SeCreatePermanentPrivilege                   Create permanent shared objects
         SeCreateSymbolicLinkPrivilege                Create symbolic links
         SeDebugPrivilege                             Debug programs
         SeDenyNetworkLogonRight                      Deny access this computer from the network
         SeDenyBatchLogonRight                        Deny log on as a batch job
         SeDenyServiceLogonRight                      Deny log on as a service
         SeDenyInteractiveLogonRight                  Deny log on locally
         SeDenyRemoteInteractiveLogonRight            Deny log on through Remote Desktop Services
         SeEnableDelegationPrivilege                  Enable computer and user accounts to be trusted for delegation
         SeRemoteShutdownPrivilege                    Force shutdown from a remote system
         SeAuditPrivilege                             Generate security audits
         SeImpersonatePrivilege                       Impersonate a client after authentication
         SeIncreaseWorkingSetPrivilege                Increase a process working set
         SeIncreaseBasePriorityPrivilege              Increase scheduling priority
         SeLoadDriverPrivilege                        Load and unload device drivers
         SeLockMemoryPrivilege                        Lock pages in memory
         SeBatchLogonRight                            Log on as a batch job
         SeServiceLogonRight                          Log on as a service
         SeSecurityPrivilege                          Manage auditing and security log
         SeRelabelPrivilege                           Modify an object label
         SeSystemEnvironmentPrivilege                 Modify firmware environment values
         SeDelegateSessionUserImpersonatePrivilege    Obtain an impersonation token for another user in the same session
         SeManageVolumePrivilege                      Perform volume maintenance tasks
         SeProfileSingleProcessPrivilege              Profile single process
         SeSystemProfilePrivilege                     Profile system performance
         SeUnsolicitedInputPrivilege                  "Read unsolicited input from a terminal device"
         SeUndockPrivilege                            Remove computer from docking station
         SeAssignPrimaryTokenPrivilege                Replace a process level token
         SeRestorePrivilege                           Restore files and directories
         SeShutdownPrivilege                          Shut down the system
         SeSyncAgentPrivilege                         Synchronize directory service data
         SeTakeOwnershipPrivilege                     Take ownership of files or other objects
     .PARAMETER Computer
       Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
     .PARAMETER SidForUnresolvedName
       For each SID that cannot be resolved to a name, set the Account property to the SID instead of leaving it blank.
     .EXAMPLE
       Get-AccountsWithUserRight SeServiceLogonRight
   
       Returns a list of all accounts that hold the "Log on as a service" right.
     .EXAMPLE
       Get-AccountsWithUserRight -Right SeServiceLogonRight,SeDebugPrivilege -Computer TESTPC
   
       Returns a list of accounts that hold the "Log on as a service" right, and a list of accounts that hold the "Debug programs" right, on the TESTPC system.
     .INPUTS
       PS_LSA.Rights Right
       String Computer
       Switch SidForUnresolvedName
     .OUTPUTS
       String Account
       String SID
       String Right
     .LINK
       http://msdn.microsoft.com/en-us/library/ms721792.aspx
       http://msdn.microsoft.com/en-us/library/bb530716.aspx
    #>
       [CmdletBinding()]
       param (
           [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
           [Alias('Privilege')] [PS_LSA.Rights[]] $Right,
           [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
           [Alias('System','ComputerName','Host')][String] $Computer,
           [switch] $SidForUnresolvedName
       )
       process {
           $lsa = New-Object PS_LSA.LsaWrapper($Computer)
           foreach ($Priv in $Right) {
               $sids = $lsa.EnumerateAccountsWithUserRight($Priv, $false)
               foreach ($sid in $sids) {
                   $output = @{'Account'=(Convert-SIDtoName $sid $SidForUnresolvedName); 'SID'=$sid; 'Right'=$Priv; }
                   Write-Output (New-Object -Typename PSObject -Prop $output)
               }
           }
       }
} # Gets all accounts that are assigned specified rights

# End Region

# Check that the group name is 256 characters or less
Write-Output "Checking group name length"
if ($GroupName.Length -gt 256) {
    Throw "Group name must be 256 characters or less"
}

# Check that the group description is 48 characters or less
Write-Output "Checking group description length"
if ($GroupDescription.Length -gt 48) {
    Throw "Group description must be 48 characters or less"
}

# Get all local groups
Write-Output "Getting local groups"
$LocalGroups = Get-LocalGroup

# Check if the group exists
Write-Output "Checking if the '$GroupName' group exists"
$Group = $LocalGroups | Where-Object {$_.Name -eq $GroupName}

# If the group does not exist, create it
if (!$Group) {
    Write-Output "Creating the '$GroupName' group"
    New-LocalGroup -Name $GroupName -Description $GroupDescription
    $CreatedGroup = $true
}

# Get the newly created group
Write-Output "Fetching the '$GroupName' group"
$Group = Get-LocalGroup -Name $GroupName

# Get the current interactive logon rights
Write-Output "Getting the current interactive logon rights"
$CurrentInteractiveLogonRights = Get-AccountsWithUserRight -Right 'SeInteractiveLogonRight'

# Check if the group is not in the interactive logon rights, add it
Write-Output "Checking if the '$GroupName' group is in the interactive logon rights"
if (!$($CurrentInteractiveLogonRights | Where-Object {$_.SID -eq $Group.SID})) {
    Write-Output 'Adding the group to the interactive logon rights'
    Grant-UserRight -Account $Group.SID -Right 'SeInteractiveLogonRight'
}

# Check if the users group is in the interactive logon rights, remove it
Write-Output "Checking if the 'Users' group is in the interactive logon rights"
if ($($CurrentInteractiveLogonRights | Where-Object {$_.SID -eq 'S-1-5-32-545'})) {
    Write-Output "Removing the 'Users' group from the interactive logon rights"
    Revoke-UserRight -Account 'S-1-5-32-545' -Right 'SeInteractiveLogonRight'
}

# Check if the administrator group is in the interactive logon rights, add it
Write-Output "Checking if the 'Administrators' group is in the interactive logon rights"
if (!$($CurrentInteractiveLogonRights | Where-Object {$_.SID -eq 'S-1-5-32-544'})) {
    Write-Output "Adding the 'Administrators' group to the interactive logon rights"
    Grant-UserRight -Account 'S-1-5-32-544' -Right 'SeInteractiveLogonRight'
}

# If we havent created the group and it is existing, prompt the user if we should wipe any existing users from the group
if (!$CreatedGroup) {

    # Get the current group members
    Write-Output "Getting the current group members"
    $GroupMembers = Get-LocalGroupMember -Name $GroupName   

    if ($GroupMembers.Count -ge 1) {
        Write-Output "The '$GroupName' group currently has $($GroupMembers.Count) members"
        $WipeExistingUsers = Read-Host "Wipe existing users from the group? (Y/N)"

        # If we should wipe existing users from the group, remove them
        if ($WipeExistingUsers -eq 'Y') {
            Write-Output "Removing $($GroupMembers.Count) members from the '$GroupName' group"
            Remove-LocalGroupMember -Name $GroupName -Member $GroupMembers.Name
        }

    } else {
        Write-Output "The '$GroupName' group currently has 0 members"
    }
}

# Prompt the user if we should add users to the group
$AddUsers = Read-Host "Should we add users to the '$GroupName' group? (Y/N)"

# If we should add users to the group, prompt for the users
if ($AddUsers -eq 'Y') {
    $UsersToAdd = Read-Host "Enter the users to add to the '$GroupName' group (comma separated without spaces)"
    # Add the users to the group
    Write-Output "Adding users to the '$GroupName' group"
    Add-LocalGroupMember -Name $GroupName -Member $UsersToAdd.Split(',')
}

# Script is complete
Write-Output 'Script complete'

# Prompt the user to press any key to continue
Write-Output 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');