<#
    We can do this interactively like so:
    get-acl <Path> | select -ExpandProperty Access | where-object {$_.filesystemrights -match "FullControl|Write" -and $_.identityreference -notmatch "SYSTEM|Administrators|TrustedInstaller"} 
#>
<# The parameters will be one or more paths, 
   but we will default to C:\Program Files if the user
   does not give us a path.
#>
Param([string[]]$paths="C:\Program Files\")

$executableExtensions = "exe|dll|com|bat|ps1|cmd|vbs|vbe|wsf|wsh"
$permissions = "FullControl|Write"
$excludedUsers = "SYSTEM|Administrators|TrustedInstaller"

foreach($path in $paths)
{
    # -File (introduced in Powershell 3.0) tells powershell only to look for files (as opposed to directories)
    $allFilesInPath = Get-ChildItem -Recurse $path -ErrorAction SilentlyContinue

    foreach($file in $allFilesInPath)
    {
        <#
            We only want to look at files, so if the
            "file" is a directory (container), then
            we will skip it.
        #>
        if (Test-Path $file.FullName -PathType Container)
        {
            continue
        }
        if (!($file.Extension -match $executableExtensions))
        {
            continue
        }
        # Get all ACL information
        # We use $file.FullName because we need the full file path
        $aclInformation = Get-Acl $file.FullName
        #Write-Host("Currently processing $($file.FullName)")

        <#
        We need the System.Security.AccessControl.FileSystemAccessRule
        object from the ACL.  It looks like this:

        FileSystemRights  : Write, ReadAndExecute, Synchronize
        AccessControlType : Allow
        IdentityReference : NT AUTHORITY\Authenticated Users
        IsInherited       : False
        InheritanceFlags  : None
        PropagationFlags  : None

        FileSystemRights  : ReadAndExecute, Synchronize
        AccessControlType : Allow
        IdentityReference : BUILTIN\Users
        IsInherited       : False
        InheritanceFlags  : None
        PropagationFlags  : None

        FileSystemRights  : FullControl
        AccessControlType : Allow
        IdentityReference : NT AUTHORITY\SYSTEM
        IsInherited       : True
        InheritanceFlags  : None
        PropagationFlags  : None

        FileSystemRights  : FullControl
        AccessControlType : Allow
        IdentityReference : BUILTIN\Administrators
        IsInherited       : True
        InheritanceFlags  : None
        PropagationFlags  : None

        FileSystemRights  : FullControl
        AccessControlType : Allow
        IdentityReference : WIN-57TGPOR2ISH\User
        IsInherited       : True
        InheritanceFlags  : None
        PropagationFlags  : None

        #>
        $accessInformation = $aclInformation.Access

        <#
        We want to find files that have Write, Modify, or FullControl.

        If they are owned by SYSTEM, BUILTIN\Administrators or TrustedInstaller, we do not
        need to worry about that file.
        #>
        $warningList = @()
        foreach($accessObject in $accessInformation)
        {
            if ($accessObject.filesystemrights -match $permissions -and $accessObject.identityreference -notmatch $excludedUsers)
            {
                $matchingPermissions = $accessObject.FileSystemRights | Select-String -AllMatches -Pattern $permissions | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value

                # $() around the variable name expands the variable
                $warningList += "User $($accessObject.IdentityReference) has the following permissions: $($matchingPermissions)"
            }
        }
        if ($warningList.Count -gt 0)
        {
            Write-Host "Permission issue(s) in $($file.FullName)"
            foreach ($issue in $warningList)
            {
                Write-Host "`t$($issue)"
            }
        }
    }
}
