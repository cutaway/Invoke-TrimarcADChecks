<#
.SYNOPSIS
Performs AD Scan

.DESCRIPTION
This script is designed for a single AD forest and is not designed to capture all data for a multiple domain forest.
Note that if this script is used for a single domain in a multi-domain AD forest, not all elements may be captured.
This script has been updated to include a request for user credentials. This is intented to allow this script to work
on systems that are not joined to the Windows Domain or running in the context of an authenticated user.

.PARAMETER DomainName
Forest Name of your AD

.PARAMETER RootDir
Location to save all output too

.EXAMPLE
PS>.\Invoke-ADChecks.ps1

This is the prefer method of running this script, all data will be store at the following location C:\TM\
.EXAMPLE
PS>.\Invoke-ADChecks.ps1 -DomainName ad.vulndomain.corp -RootDir c:\FOLDERPATH

.EXAMPLE
PS>Set-ExecutionPolicy Bypass -Scope Process -Force 
PS>.\Invoke-ADChecks.ps1

.NOTES
FORK AUTHOR: Don C. Weber (cutaway)
FORK AUTHOR EMAIL: dev@cutawaysecurity.com
FORK COMPANY: Cutaway Security, LLC (cutsec)
FORK COPYRIGHT: 2024 Cutaway Security, LLC (cutsec)
FORK WEBSITE: https://www.cutawaysecurity.com
ORIG AUTHOR: Sean Metcalf
ORIG AUTHOR EMAIL: sean@trimarcsecurity.com
ORIG COMPANY: Trimarc Security, LLC (Trimarc)
ORIG COPYRIGHT: 2020 - 2023 Trimarc Security, LLC (Trimarc)
ORIG WEBSITE: https://www.TrimarcSecurity.com

This script requires the following:
 * PowerShell 5.0 (minimum)
 * Windows 10/2016
 * Active Directory PowerShell Module
 * Group Policy PowerShell Module
If the above requirements are not met, results will be inconsistent.
This script is provided as-is, without support.
#>

Param (
    [string]$DomainName = $env:userdnsdomain,
    # [string]$RootDir = 'C:\TM\'
    [string]$RootDir = $env:TEMP + '\ADChecks\',
    [string]$ReportName = 'ADChecks',
    [pscredential]$creds = (Get-Credentials -Message "Please provide domain credentials in form 'Domain\Username'")
)

function Get-ADForestInfo {
    Param (
        $DomainName
    )

    $ADForestFunctionalLevel = (Get-ADForest -Credential $creds).ForestMode
    $ADDomainFunctionalLevel = (Get-ADDomain -Credential $creds $DomainName).DomainMode

    Write-Host "The AD Forest Functional Level is $ADForestFunctionalLevel"
    Write-Host "The AD Domain Functional Level ($DomainName) is $ADDomainFunctionalLevel"
}

function Get-DomainControllers {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    $DomainDCs = Get-ADDomainController -Credential $creds -Filter * -Server $DomainDC
    $DomainDCs | Select HostName,OperatingSystem | Format-Table -AutoSize

    $DomainDCArray = @()
    foreach ($DomainDCItem in $DomainDCs) {
        $DomainDCItem | Add-Member -MemberType NoteProperty -Name FSMORolesList -Value ($DomainDCItem.OperationMasterRoles -join ';') -Force 
        $DomainDCItem | Add-Member -MemberType NoteProperty -Name PartitionsList -Value ($DomainDCItem.Partitions -join ';') -Force 
        [array]$DomainDCArray += $DomainDCItem
    }

    $DomainDCArray | Sort OperatingSystem | Export-CSV "$ReportDir\$ReportName-DomainDCs-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\$ReportName-DomainDCs-$DomainName.csv"
}

function Get-TombstoneInfo {
    Param (
        $DomainDC
    )

    $ADRootDSE = Get-ADRootDSE -Credential $creds -Server $DomainDC
    $ADConfigurationNamingContext = $ADRootDSE.configurationNamingContext
    
    $TombstoneObjectInfo = Get-ADObject -Credential $creds -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$ADConfigurationNamingContext" -Partition "$ADConfigurationNamingContext" -Properties * 
    [int]$TombstoneLifetime = $TombstoneObjectInfo.tombstoneLifetime

    if ($TombstoneLifetime -eq 0) { 
        $TombstoneLifetime = 60 
    }

    Write-Host "The AD Forest Tombstone lifetime is set to $TombstoneLifetime days."
}

function Get-ADBackups {
    Param (
        $DomainName,
        $DomainDC
    )

    $ContextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
    $Context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($ContextType,(Get-ADDomain -Credential $creds $DomainName).DNSRoot)
    $DomainController = [System.DirectoryServices.ActiveDirectory.DomainController]::findOne($Context)
    
    [string[]]$Partitions = (Get-ADRootDSE -Credential $creds -Server $DomainDC).namingContexts
    foreach ($Partition in $Partitions) {
        $dsaSignature = $DomainController.GetReplicationMetadata($Partition).Item("dsaSignature")
        Write-Host "$Partition was backed up $($dsaSignature.LastOriginatingChangeTime.DateTime)" 
    }
}

function Get-ADTrustInfo {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    $ADTrusts = Get-ADTrust -Credential $creds -Filter * -Server $DomainDC
    
    if ($ADTrusts.Count -gt 0) {
        $ADTrusts | Select Source,Target,Direction,IntraForest,SelectiveAuth,SIDFilteringForestAware,SIDFilteringQuarantined | Format-Table -AutoSize
        $ADTrusts | Export-CSV "$ReportDir\$ReportName-DomainTrustReport-$DomainName.csv" -NoTypeInformation
        Write-Host "File save to $ReportDir\$ReportName-DomainTrustReport-$DomainName.csv" 
    } else {
        Write-Host "No Trust Found"
    }
}

function Get-DomainUsers {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC,
        $UserLogonAge,
        $UserPasswordAge
    )

    $LastLoggedOnDate = $(Get-Date) - $(New-TimeSpan -days $UserLogonAge)  
    $PasswordStaleDate = $(Get-Date) - $(New-TimeSpan -days $UserPasswordAge)

    $ADLimitedProperties = @("Name","Enabled","SAMAccountname","DisplayName","Enabled","LastLogonDate","PasswordLastSet",
        "PasswordNeverExpires","PasswordNotRequired","PasswordExpired","SmartcardLogonRequired","AccountExpirationDate",
        "AdminCount","Created","Modified","LastBadPasswordAttempt","badpwdcount","mail","CanonicalName","DistinguishedName",
        "ServicePrincipalName","SIDHistory","PrimaryGroupID","UserAccountControl","DoesNotRequirePreAuth")

    [array]$DomainUsers = Get-ADUser -Credential $creds -Filter * -Property $ADLimitedProperties -Server $DomainDC
    [array]$DomainEnabledUsers = $DomainUsers | Where {$_.Enabled -eq $True }
    [array]$DomainEnabledInactiveUsers = $DomainEnabledUsers | Where { ($_.LastLogonDate -le $LastLoggedOnDate) -AND ($_.PasswordLastSet -le $PasswordStaleDate) }
    [array]$DomainUsersWithReversibleEncryptionPasswordArray = $DomainUsers | Where { $_.UserAccountControl -band 0x0080 } 
    [array]$DomainUserPasswordNotRequiredArray = $DomainUsers | Where {$_.PasswordNotRequired -eq $True}
    [array]$DomainUserPasswordNeverExpiresArray = $DomainUsers | Where {$_.PasswordNeverExpires -eq $True}
    [array]$DomainKerberosDESUsersArray = $DomainUsers | Where { $_.UserAccountControl -band 0x200000 }
    [array]$DomainUserDoesNotRequirePreAuthArray = $DomainUsers | Where {$_.DoesNotRequirePreAuth -eq $True}
    [array]$DomainUsersWithSIDHistoryArray = $DomainUsers | Where {$_.SIDHistory -like "*"}

    Write-Host "Total Users: $($DomainUsers.Count)"
    Write-Host "Enabled Users: $($DomainEnabledUsers.Count)"
    Write-Host "`nEnabled Users Identified as Inactive: $($DomainEnabledInactiveUsers.Count)"
    Write-Host "Enabled Users With Reversible Encryption Password: $($DomainUsersWithReversibleEncryptionPasswordArray.Count)"
    Write-Host "Enabled Users With Password Not Required: $($DomainUserPasswordNotRequiredArray.Count)"
    Write-Host "Enabled Users With Password Never Expires: $($DomainUserPasswordNeverExpiresArray.Count)"
    Write-Host "Enabled Users With Kerberos DES: $($DomainKerberosDESUsersArray.Count)"
    Write-Host "Enabled Users That Do Not Require Kerberos Pre-Authentication: $($DomainUserDoesNotRequirePreAuthArray.Count)"
    Write-Host "Enabled Users With SID History: $($DomainUsersWithSIDHistoryArray.Count)"
    Write-Host "`nReview & clean up as appropriate"

    $DomainUsers | Export-CSV "$ReportDir\$ReportName-DomainUserReport-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\$ReportName-DomainUserReport-$DomainName.csv" 
}

function Get-DomainPasswordPolicy {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    [array]$DomainPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -Credential $creds -Server $DomainDC
    $DomainPasswordPolicy | Format-List
    $DomainPasswordPolicy | Export-CSV "$ReportDir\$ReportName-DomainPasswordPolicy-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\$ReportName-DomainUserReport-$DomainName.csv" 
}

function Get-DomainAdminUser {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC,
        $ADDomainInfo
    )

    $ADLimitedProperties = @("Name","Enabled","Created","PasswordLastSet","LastLogonDate","ServicePrincipalName","SID")
    $DomainDefaultAdminAccount = Get-ADUser -Credential $creds "$($ADDomainInfo.DomainSID)-500" -Server $DomainDC -Properties $ADLimitedProperties
    $DomainDefaultAdminAccount | Select $ADLimitedProperties | Format-List
    $DomainDefaultAdminAccount | Export-CSV "$ReportDir\$ReportName-DomainDefaultAdminAccount-$DomainName.csv" -NoTypeInformation 
    Write-Host "File save to $ReportDir\$ReportName-DomainDefaultAdminAccount-$DomainName.csv" 
}

function Get-KRBTGT {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    $DomainKRBTGTAccount = Get-ADUser -Credential $creds 'krbtgt' -Server $DomainDC -Properties DistinguishedName,'msds-keyversionnumber',Created,PasswordLastSet    
    $DomainKRBTGTAccount | Select DistinguishedName,Created,PasswordLastSet,'msds-keyversionnumber' | Format-Table -AutoSize
    $DomainKRBTGTAccount | Export-CSV "$ReportDir\$ReportName-DomainKRBTGTAccount-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\$ReportName-DomainKRBTGTAccount-$DomainName.csv" 
}

function Get-ADAdmins {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    $ADAdminArray = @()
    $ADAdminMembers = Get-ADGroupMember -Credential $creds Administrators -Recursive -Server $DomainDC
    foreach ($ADAdminMemberItem in $ADAdminMembers) { 
        try {
            Switch ($ADAdminMemberItem.objectClass) {
                'User' { [array]$ADAdminArray += Get-ADUser -Credential $creds $ADAdminMemberItem -Properties LastLogonDate,PasswordLastSet,ServicePrincipalName -Server $DomainDC }
                'Computer' { [array]$ADAdminArray += Get-ADComputer -Credential $creds $ADAdminMemberItem -Properties LastLogonDate,PasswordLastSet -Server $DomainDC }
                'msDS-GroupManagedServiceAccount' { [array]$ADAdminArray += Get-ADServiceAccount -Credential $creds $ADAdminMemberItem -Properties LastLogonDate,PasswordLastSet -Server $DomainDC}
            }
        } catch {
            Write-Warning "The security principal member ($ADAdminMemberItem) may be in another domain or is unreachable" ; $ADAdminArray += $ADAdminMemberItem
        }
    }

    $ADAdminArray | sort PasswordLastSet | Select name,DistinguishedName,PasswordLastSet,LastLogonDate,ObjectClass | Format-Table -AutoSize
    $ADAdminArray | Export-CSV "$ReportDir\$ReportName-ADAdminAccountReport-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\$ReportName-ADAdminAccountReport-$DomainName.csv" 
}

function Get-SPNs {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    $ADAdminArray = @()
    $ADAdminMembers = Get-ADGroupMember -Credential $creds Administrators -Recursive -Server $DomainDC
    foreach ($ADAdminMemberItem in $ADAdminMembers) { 
        try {
            Switch ($ADAdminMemberItem.objectClass) {
                'User' { [array]$ADAdminArray += Get-ADUser -Credential $creds $ADAdminMemberItem -Properties LastLogonDate,PasswordLastSet,ServicePrincipalName -Server $DomainDC }
                'Computer' { [array]$ADAdminArray += Get-ADComputer -Credential $creds $ADAdminMemberItem -Properties LastLogonDate,PasswordLastSet -Server $DomainDC }
                'msDS-GroupManagedServiceAccount' { [array]$ADAdminArray += Get-ADServiceAccount -Credential $creds $ADAdminMemberItem -Properties LastLogonDate,PasswordLastSet -Server $DomainDC}
            }
        } catch {
            Write-Warning "The security principal member ($ADAdminMemberItem) may be in another domain or is unreachable" ; $ADAdminArray += $ADAdminMemberItem
        }
    }

    $ADAdminArray | Where {$_.ServicePrincipalName} | Select name,DistinguishedName,ServicePrincipalName | Format-Table -AutoSize
    $ADAdminArray | Where {$_.ServicePrincipalName} | Export-CSV "$ReportDir\$ReportName-ADAdminSPNReport-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\$ReportName-ADAdminSPNReport-$DomainName.csv" 
}

function Get-ProtectedUsers {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    $ProtectedUsersGroupMembership = Get-ADGroupMember -Credential $creds 'Protected Users' -Server $DomainDC
    $ProtectedUsersGroupMembership | Select name,DistinguishedName,objectClass | Format-Table
    $ProtectedUsersGroupMembership | Export-CSV "$ReportDir\$ReportName-ProtectedUsersGroupMembershipReport-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\$ReportName-ProtectedUsersGroupMembershipReport-$DomainName.csv" 
}

function Get-UsersFromGroup {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC,
        $GroupName
    )

    $ADPrivGroupItemGroupMembership = @()
    try { 
        Write-Host "`n$GroupName Group:" -Fore Cyan

        $ADPrivGroupItemGroupMembership = Get-ADGroupMember -Credential $creds $GroupName -Server $DomainDC 
        if ($ADPrivGroupItemGroupMembership.count -ge 1) {
            $ADPrivGroupItemGroupMembership | Select name,DistinguishedName,objectClass | Format-Table
            $ADPrivGroupItemGroupMembership | Export-CSV "$ReportDir\$ReportName-PrivGroups-$DomainName-$GroupName.csv" -NoTypeInformation
            Write-Host "File save to $ReportDir\$ReportName-PrivGroups-$DomainName-$GroupName.csv"
         } else { 
             Write-Host "No members"
         }
     } catch { 
         Write-Warning "An error occured when attempting to enumerate group membership"
     }
}

function Get-DomainPrivilegedADGroups {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC
    )

    ## Privileged AD Group Array
    $GroupNames = @(
        'Administrators',
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Account Operators',
        'Server Operators',
        'Group Policy Creator Owners',
        'DNSAdmins',
        'Enterprise Key Admins',
        'Exchange Domain Servers',
        'Exchange Enterprise Servers',
        'Exchange Admins',
        'Organization Management',
        'Exchange Windows Permissions'
    )
   
    foreach ($GroupName in $GroupNames) {
        Get-UsersFromGroup -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC -GroupName $GroupName
    }

    [array]$GroupNames = Get-ADGroup -Credential $creds -filter {Name -like "*VMWare*"}  -Server $DomainDC
    foreach ($GroupName in $GroupNames) {
        Get-UsersFromGroup -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC -GroupName $GroupName
    }
}

function Get-KerberosDelegation {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC,
        $DomainDN
    )

    $ADLimitedProperties = @("Name","ObjectClass","PrimaryGroupID","UserAccountControl","ServicePrincipalName","msDS-AllowedToDelegateTo","msDS-AllowedToActOnBehalfOfOtherIdentity")
    

    $KerberosDelegationArray = @()
    [array]$KerberosDelegationObjects = Get-ADObject -Credential $creds -filter {((UserAccountControl -BAND 0x0080000) -OR (UserAccountControl -BAND 0x1000000) -OR (msDS-AllowedToDelegateTo -like '*') -OR (msDS-AllowedToActOnBehalfOfOtherIdentity -like '*')) -AND (PrimaryGroupID -ne '516') -AND (PrimaryGroupID -ne '521') } -Server $DomainDC -Properties $ADLimitedProperties -SearchBase $DomainDN 

    foreach ($KerberosDelegationObjectItem in $KerberosDelegationObjects) {
        if ($KerberosDelegationObjectItem.UserAccountControl -BAND 0x0080000) { 
            $KerberosDelegationServices = 'All Services'
            $KerberosType = 'Unconstrained' 
        } else { 
            $KerberosDelegationServices = 'Specific Services'
            $KerberosType = 'Constrained' 
        } 

        if ($KerberosDelegationObjectItem.UserAccountControl -BAND 0x1000000) { 
            $KerberosDelegationAllowedProtocols = 'Any (Protocol Transition)'
            $KerberosType = 'Constrained with Protocol Transition'
        } else { 
            $KerberosDelegationAllowedProtocols = 'Kerberos'
        }

        if ($KerberosDelegationObjectItem.'msDS-AllowedToActOnBehalfOfOtherIdentity') { 
            $KerberosType = 'Resource-Based Constrained Delegation'
        } 

        $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name Domain -Value $DomainName -Force
        $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name KerberosDelegationServices -Value $KerberosDelegationServices -Force
        $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name DelegationType -Value $KerberosType -Force
        $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name KerberosDelegationAllowedProtocols -Value $KerberosDelegationAllowedProtocols -Force

        [array]$KerberosDelegationArray += $KerberosDelegationObjectItem
    }

    $KerberosDelegationArray | Sort DelegationType | Select DistinguishedName,DelegationType,Name,ServicePrincipalName | Format-Table -AutoSize
    $KerberosDelegationArray | Sort DelegationType | Export-CSV "$ReportDir\$ReportName-KerberosDelegationReport-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\$ReportName-KerberosDelegationReport-$DomainName.csv" 
}

function Get-NameForGUID{
    # From http://blog.wobl.it/2016/04/active-directory-guid-to-friendly-name-using-just-powershell/
    [CmdletBinding()]
    Param(
        [guid]$guid,
        [string]$ForestDNSName
    )
    Begin{
        if (!$ForestDNSName) { 
            $ForestDNSName = (Get-ADForest -Credential $creds $ForestDNSName).Name 
        }

        if ($ForestDNSName -notlike "*=*") { 
            $ForestDNSNameDN = "DC=$($ForestDNSName.replace(".", ",DC="))" 
        }

        $ExtendedRightGUIDs = "LDAP://cn=Extended-Rights,cn=configuration,$ForestDNSNameDN"
        $PropertyGUIDs = "LDAP://cn=schema,cn=configuration,$ForestDNSNameDN"
    }
    Process{
        if ($guid -eq "00000000-0000-0000-0000-000000000000"){
            Return "All"
        } else {
            $rightsGuid = $guid
            $property = "cn"
            $SearchAdsi = ([ADSISEARCHER]"(rightsGuid=$rightsGuid)")
            $SearchAdsi.SearchRoot = $ExtendedRightGUIDs
            $SearchAdsi.SearchScope = "OneLevel"
            $SearchAdsiRes = $SearchAdsi.FindOne()
            if ($SearchAdsiRes){
                Return $SearchAdsiRes.Properties[$property]
            } else {
                $SchemaGuid = $guid
                $SchemaByteString = "\" + ((([guid]$SchemaGuid).ToByteArray() | %{$_.ToString("x2")}) -Join "\")
                $property = "ldapDisplayName"
                $SearchAdsi = ([ADSISEARCHER]"(schemaIDGUID=$SchemaByteString)")
                $SearchAdsi.SearchRoot = $PropertyGUIDs
                $SearchAdsi.SearchScope = "OneLevel"
                $SearchAdsiRes = $SearchAdsi.FindOne()
                if ($SearchAdsiRes){
                    Return $SearchAdsiRes.Properties[$property]
                } else {
                    Write-Host -f Yellow $guid
                    Return $guid.ToString()
                }
            }
        }
    }
}

function Get-DomainPermissions {
    Param (
        $ReportDir,
        $DomainName,
        $DomainDC,
        $ForestDNSName
    )

    $ForestDomainObjectData = Get-ADObject -Credential $creds $ADDomainInfo.DistinguishedName -Properties * -Server $DomainDC
    $ForestDomainObjectSecurityData = $ForestDomainObjectData.nTSecurityDescriptor.Access
    
    $ForestDomainObjectPermissions = @()

    foreach ($ForestDomainObjectSecurityDataItem in $ForestDomainObjectSecurityData) {
        $ObjectTypeName = Get-NameForGUID -Credential $creds $ForestDomainObjectSecurityDataItem.ObjectType -ForestDNSName $ForestDNSName
        $InheritedObjectTypeName = Get-NameForGUID -Credential $creds $ForestDomainObjectSecurityDataItem.InheritedObjectType -ForestDNSName $ForestDNSName

        $ForestDomainObjectSecurityDataItem | Add-Member -MemberType NoteProperty -Name Domain -Value $DomainName -Force
        $ForestDomainObjectSecurityDataItem | Add-Member -MemberType NoteProperty -Name ObjectTypeName -Value $ObjectTypeName -Force
        $ForestDomainObjectSecurityDataItem | Add-Member -MemberType NoteProperty -Name InheritedObjectTypeName -Value $InheritedObjectTypeName -Force

        [array]$ForestDomainObjectPermissions += $ForestDomainObjectSecurityDataItem
    }

    $ForestDomainObjectPermissions | Sort IdentityReference | Select IdentityReference,ActiveDirectoryRights,InheritedObjectTypeName,ObjectTypeName,`
    InheritanceType,ObjectFlags,AccessControlType,IsInherited,InheritanceFlags,PropagationFlags,ObjectType,InheritedObjectType | `
    Export-CSV "$ReportDir\$ReportName-DomainRootPermissionReport-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\$ReportName-DomainRootPermissionReport-$DomainName.csv" 
}

function Get-DuplicateSPNs {
    Param (
        $ReportDir,
        $DomainName
    )

    $SetSPN = SetSPN -X -F | Where {$_ -notlike "Processing entry*"}
    $SetSPN
    $SetSPN | Out-File "$ReportDir\$ReportName-ADForestDuplicateSPNReport-$DomainName.txt"
    Write-Host "File save to $ReportDir\$ReportName-ADForestDuplicateSPNReport-$DomainName.csv" 
}

function Get-SYSVOLcpassword {
    Param (
        $ReportDir,
        $DomainName
    )

    $GPPPasswordData = findstr /S /I cpassword "\\$DomainName\SYSVOL\$DomainName\Policies\*.xml"
    $GPPPasswordData
    $GPPPasswordData | Out-File "$ReportDir\$ReportName-GPPPasswordDataReport-$DomainName.txt"
    Write-Host "File save to $ReportDir\$ReportName-GPPPasswordDataReport-$DomainName.csv" 
}

function Get-GPOOwners {
    Param (
        $ReportDir,
        $DomainName
    )

    [Array]$DomainGPOs = Get-GPO -Credential $creds -All -Domain $DomainName
    $DomainGPOs | Select DisplayName,Owner | Format-Table -AutoSize
    $DomainGPOs | Out-File "$ReportDir\$ReportName-DomainGPOData-$DomainName.csv"
    Write-Host "File save to $ReportDir\$ReportName-DomainGPOData-$DomainName.csv"
}

function Get-GPOPermissions {
    Param (
        $ReportDir,
        $DomainName
    )

    [Array]$DomainGPOs = Get-GPO -Credential $creds -All -Domain $DomainName
    $GPOPermissions = foreach ($DomainGPO in $DomainGPOs)
    {
        Get-GPPermissions -Credential $creds -Guid $DomainGPO.Id -All | Where {$_.Trustee.SidType.ToString() -ne "WellKnownGroup"} | Select `
        @{n='GPOName';e={$DomainGPO.DisplayName}},
        @{n='AccountName';e={$_.Trustee.Name}},
        @{n='AccountType';e={$_.Trustee.SidType.ToString()}},
        @{n='Permissions';e={$_.Permission}}
    }

    $GPOPermissions | Format-Table
    $GPOPermissions | Export-CSV "$ReportDir\$ReportName-DomainGPOPermissions-$DomainName.csv" -NoTypeInformation
    Write-Host "File save to $ReportDir\$ReportName-DomainGPOPermissions-$DomainName.csv"
}

# Import Modules
Import-Module ActiveDirectory
Import-Module GroupPolicy

# Create Folders
$ReportDir = "$($RootDir)Trimarc-ADReports"
New-Item -Type Directory -Path $RootDir -Force | Out-Null
New-Item -Type Directory -Path $ReportDir -Force | Out-Null

# Default Var
[int]$UserLogonAge = '180'
[int]$UserPasswordAge = '180'

# Log File
$TimeVal = Get-Date -UFormat '%Y-%m-%d-%H-%M'
Start-Transcript "$ReportDir\Invoke$ReportName-LogFile.txt" -Force

if (!$DomainName) { $DomainName = (Get-ADDomain -Credential $creds).DNSRoot } 

## Get AD Forest
$ADForestInfo = Get-ADForest -Credential $creds
$ADDomainInfo = Get-ADDomain -Credential $creds $DomainName
$DomainDC = $ADDomainInfo.PDCEmulator 

Write-Host "Starting AD Discovery & Checks" -Fore Cyan

if (($ADForestInfo.Domains).count -gt 1) { 
    Write-Host "There are $(($ADForestInfo.Domains).count) domains in the AD Forest.
     Only the currently selected domain ($DomainName) is being analyzed." }
else { 
    Write-Host "The AD Forest is a single domain forest and is now being analyzed."
}

## Get AD Forest & Domain Info
$ForestDNSName = $ADForestInfo.Name
$ADForestName = $ADForestInfo.RootDomain
$DomainDN = $ADDomainInfo.DistinguishedName

Write-Host "`nForest Name: $ADForestName" -Fore Cyan
Get-ADForestInfo -Credential $creds -DomainName $DomainName

## Get Domain Controllers 
Write-Host "`nAD Forest Domain Controllers:" -Fore Cyan
Get-DomainControllers -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Tombstone Lifetime
Write-Host "`nThe AD Forest Tombstone lifetime:" -Fore Cyan
Get-TombstoneInfo -Credential $creds -DomainDC $DomainDC

## AD Backups
Write-Host "`nDetermining last supported backup of AD partitions:" -ForegroundColor Cyan
Get-ADBackups -Credential $creds -DomainName $DomainName -DomainDC $DomainDC

## AD Trusts
Write-Host "`nActive Directory Trusts:" -Fore Cyan
Get-ADTrustInfo -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Get Domain User Information
Write-Host "`nDomain User Report:" -ForegroundColor Cyan
Get-DomainUsers -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC -UserLogonAge $UserLogonAge -UserPasswordAge $UserPasswordAge

## Domain Password Policy
Write-Host "`nDomain Password Policy:" -Fore Cyan
Get-DomainPasswordPolicy -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Default Domain Administrator Account 
Write-Host "`nDefault Domain Administrator Account:" -Fore Cyan
Get-DomainAdminUser -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC -ADDomainInfo $ADDomainInfo

## KRBTGT Account Password
Write-Host "`nDomain Kerberos Service Account (KRBTGT):" -Fore Cyan
Get-KRBTGT -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Identify AD Admins
Write-Host "`nAD Admins:" -Fore Cyan
Get-ADAdmins -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Identify AD Admins with SPNs
Write-Host "`nAD Admin Accounts with SPNs:" -Fore Cyan
Get-SPNs -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Protected Users group membership, compare with AD Admins
Write-Host "`nDomain Protected Users Group Membership:" -Fore Cyan
Get-ProtectedUsers -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC

## Discover Default privileged group membership
Get-DomainPrivilegedADGroups -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC
    
## Identify Accounts with Kerberos Delegation
Write-Host "`nDomain Accounts with Kerberos Delegation:" -Fore Cyan
Get-KerberosDelegation -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC -DomainDN $DomainDN

## Get Domain Permissions
Write-Host "`nGathering Domain Permissions:" -Fore Cyan
Get-DomainPermissions -Credential $creds -ReportDir $ReportDir -DomainName $DomainName -DomainDC $DomainDC -ForestDNSName $ForestDNSName

## Duplicate SPNs
Write-Host "`nAD Forest Duplicate SPN Report:" -Fore Cyan
Get-DuplicateSPNs -Credential $creds -ReportDir $ReportDir -DomainName $DomainName

## Scan SYSVOL for Group Policy Preference Passwords
Write-Host "`nSYSVOL Scan for Group Policy Preference Passwords:" -Fore Cyan
Get-SYSVOLcpassword -Credential $creds -ReportDir $ReportDir -DomainName $DomainName

## Get GPO Owners
Write-Host "`nGPO Owners:" -Fore Cyan
Get-GPOOwners -Credential $creds -ReportDir $ReportDir -DomainName $DomainName

## Get GPO Permissions
Write-Host "`nGPO Permissions:" -Fore Cyan
Get-GPOPermissions -Credential $creds -ReportDir $ReportDir -DomainName $DomainName

#####
$EndMessageText = 
@"
Data files generated and saved to $ReportDir

############################################################################################################################################################################
#                                                                                                                                                                          #
# Contact Trimarc to perform a full Active Directory Security Assessment which covers these security items (& many more) and provides detailed actionable recommendations  #
#                                                                                                                                                                          #
#                                                        ----------------------------------------------------------                                                        #
#                                                        |   TrimarcSecurity.com   |   info@TrimarcSecurity.com   |                                                        #
#                                                        ----------------------------------------------------------                                                        #
#                                                                                                                                                                          #
############################################################################################################################################################################
"@
$EndMessageText
Stop-Transcript
