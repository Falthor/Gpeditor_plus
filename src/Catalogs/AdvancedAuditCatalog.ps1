<#
    Advanced Audit Policy Configuration catalog (Computer Configuration >
    Windows Settings > Security Settings > Advanced Audit Policy
    Configuration > System Audit Policies - Local Group Policy Object),
    stored in a file separate from GptTmpl.inf:
    C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv

    9 categories / 59 subcategories. Names and GUIDs are Microsoft's
    standard identifiers (stable since Vista/Server 2008); the sequential
    GUID range (0CCE9210-0CCE924A) is a strong trust signal but could not
    be validated via live export (auditpol /backup needs admin rights,
    unavailable at write time) - confirm experimentally via
    `auditpol /backup /file:...` when possible.
#>

Set-StrictMode -Version Latest

# Each subcategory: Guid, En, CategoryKey (grouping for the tree view)
$script:AdvancedAuditSubcategories = @(
    # --- Logon/Logoff ---
    @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Category = 'LogonLogoff'; En = 'Logon' }
    @{ Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Category = 'LogonLogoff'; En = 'Logoff' }
    @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Category = 'LogonLogoff'; En = 'Account Lockout' }
    @{ Guid = '{0CCE9218-69AE-11D9-BED3-505054503030}'; Category = 'LogonLogoff'; En = 'IPsec Main Mode' }
    @{ Guid = '{0CCE9219-69AE-11D9-BED3-505054503030}'; Category = 'LogonLogoff'; En = 'IPsec Quick Mode' }
    @{ Guid = '{0CCE921A-69AE-11D9-BED3-505054503030}'; Category = 'LogonLogoff'; En = 'IPsec Extended Mode' }
    @{ Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Category = 'LogonLogoff'; En = 'Special Logon' }
    @{ Guid = '{0CCE921C-69AE-11D9-BED3-505054503030}'; Category = 'LogonLogoff'; En = 'Other Logon/Logoff Events' }
    @{ Guid = '{0CCE9243-69AE-11D9-BED3-505054503030}'; Category = 'LogonLogoff'; En = 'Network Policy Server' }
    @{ Guid = '{0CCE9247-69AE-11D9-BED3-505054503030}'; Category = 'LogonLogoff'; En = 'User / Device Claims' }
    @{ Guid = '{0CCE9249-69AE-11D9-BED3-505054503030}'; Category = 'LogonLogoff'; En = 'Group Membership' }

    # --- Object Access ---
    @{ Guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'File System' }
    @{ Guid = '{0CCE921E-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'Registry' }
    @{ Guid = '{0CCE921F-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'Kernel Object' }
    @{ Guid = '{0CCE9220-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'SAM' }
    @{ Guid = '{0CCE9221-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'Certification Services' }
    @{ Guid = '{0CCE9222-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'Application Generated' }
    @{ Guid = '{0CCE9223-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'Handle Manipulation' }
    @{ Guid = '{0CCE9224-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'File Share' }
    @{ Guid = '{0CCE9225-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'Filtering Platform Packet Drop' }
    @{ Guid = '{0CCE9226-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'Filtering Platform Connection' }
    @{ Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'Other Object Access Events' }
    @{ Guid = '{0CCE9244-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'Detailed File Share' }
    @{ Guid = '{0CCE9245-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'Removable Storage' }
    @{ Guid = '{0CCE9246-69AE-11D9-BED3-505054503030}'; Category = 'ObjectAccess'; En = 'Central Policy Staging' }

    # --- Privilege Use ---
    @{ Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Category = 'PrivilegeUse'; En = 'Sensitive Privilege Use' }
    @{ Guid = '{0CCE9229-69AE-11D9-BED3-505054503030}'; Category = 'PrivilegeUse'; En = 'Non Sensitive Privilege Use' }
    @{ Guid = '{0CCE922A-69AE-11D9-BED3-505054503030}'; Category = 'PrivilegeUse'; En = 'Other Privilege Use Events' }

    # --- Detailed Tracking ---
    @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Category = 'DetailedTracking'; En = 'Process Creation' }
    @{ Guid = '{0CCE922C-69AE-11D9-BED3-505054503030}'; Category = 'DetailedTracking'; En = 'Process Termination' }
    @{ Guid = '{0CCE922D-69AE-11D9-BED3-505054503030}'; Category = 'DetailedTracking'; En = 'DPAPI Activity' }
    @{ Guid = '{0CCE922E-69AE-11D9-BED3-505054503030}'; Category = 'DetailedTracking'; En = 'RPC Events' }
    @{ Guid = '{0CCE9248-69AE-11D9-BED3-505054503030}'; Category = 'DetailedTracking'; En = 'Plug and Play Events' }
    @{ Guid = '{0CCE924A-69AE-11D9-BED3-505054503030}'; Category = 'DetailedTracking'; En = 'Token Right Adjusted Events' }

    # --- Policy Change ---
    @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Category = 'PolicyChange'; En = 'Audit Policy Change' }
    @{ Guid = '{0CCE9230-69AE-11D9-BED3-505054503030}'; Category = 'PolicyChange'; En = 'Authentication Policy Change' }
    @{ Guid = '{0CCE9231-69AE-11D9-BED3-505054503030}'; Category = 'PolicyChange'; En = 'Authorization Policy Change' }
    @{ Guid = '{0CCE9232-69AE-11D9-BED3-505054503030}'; Category = 'PolicyChange'; En = 'MPSSVC Rule-Level Policy Change' }
    @{ Guid = '{0CCE9233-69AE-11D9-BED3-505054503030}'; Category = 'PolicyChange'; En = 'Filtering Platform Policy Change' }
    @{ Guid = '{0CCE9234-69AE-11D9-BED3-505054503030}'; Category = 'PolicyChange'; En = 'Other Policy Change Events' }

    # --- Account Management ---
    @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Category = 'AccountManagement'; En = 'User Account Management' }
    @{ Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Category = 'AccountManagement'; En = 'Computer Account Management' }
    @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Category = 'AccountManagement'; En = 'Security Group Management' }
    @{ Guid = '{0CCE9238-69AE-11D9-BED3-505054503030}'; Category = 'AccountManagement'; En = 'Distribution Group Management' }
    @{ Guid = '{0CCE9239-69AE-11D9-BED3-505054503030}'; Category = 'AccountManagement'; En = 'Application Group Management' }
    @{ Guid = '{0CCE923A-69AE-11D9-BED3-505054503030}'; Category = 'AccountManagement'; En = 'Other Account Management Events' }

    # --- DS Access ---
    @{ Guid = '{0CCE923B-69AE-11D9-BED3-505054503030}'; Category = 'DSAccess'; En = 'Directory Service Access' }
    @{ Guid = '{0CCE923C-69AE-11D9-BED3-505054503030}'; Category = 'DSAccess'; En = 'Directory Service Changes' }
    @{ Guid = '{0CCE923D-69AE-11D9-BED3-505054503030}'; Category = 'DSAccess'; En = 'Directory Service Replication' }
    @{ Guid = '{0CCE923E-69AE-11D9-BED3-505054503030}'; Category = 'DSAccess'; En = 'Detailed Directory Service Replication' }

    # --- Account Logon ---
    @{ Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Category = 'AccountLogon'; En = 'Credential Validation' }
    @{ Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Category = 'AccountLogon'; En = 'Kerberos Service Ticket Operations' }
    @{ Guid = '{0CCE9241-69AE-11D9-BED3-505054503030}'; Category = 'AccountLogon'; En = 'Other Account Logon Events' }
    @{ Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Category = 'AccountLogon'; En = 'Kerberos Authentication Service' }

    # --- System ---
    @{ Guid = '{0CCE9210-69AE-11D9-BED3-505054503030}'; Category = 'System'; En = 'Security State Change' }
    @{ Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Category = 'System'; En = 'Security System Extension' }
    @{ Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Category = 'System'; En = 'System Integrity' }
    @{ Guid = '{0CCE9213-69AE-11D9-BED3-505054503030}'; Category = 'System'; En = 'IPsec Driver' }
    @{ Guid = '{0CCE9214-69AE-11D9-BED3-505054503030}'; Category = 'System'; En = 'Other System Events' }
)

# Internal category -> UiStrings key for the tree label (UiStrings.ps1: AdvAudit<CategoryKey>)
$script:AdvancedAuditCategoryOrder = @('AccountLogon', 'AccountManagement', 'DetailedTracking', 'DSAccess', 'LogonLogoff', 'ObjectAccess', 'PolicyChange', 'PrivilegeUse', 'System')

function Get-AdvancedAuditCatalogEntry {
    # Flattens the catalog, same shape as Get-SecurityCatalogEntry.
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($sub in $script:AdvancedAuditSubcategories) {
        $list.Add([ordered]@{
            category    = $sub.Category
            guid        = $sub.Guid
            name        = $sub.En
            displayName = $sub.En
            valueType   = 'audit'
        })
    }
    return $list
}
