# SOC Lab - Enable File Auditing Script
# Run as Administrator on File Server

# Enable audit policies
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable

# Create shares
$Shares = @("Finance", "HR", "IT", "Engineering")
foreach ($Share in $Shares) {
    New-Item -ItemType Directory -Path "C:\Shares\$Share" -Force
    New-SmbShare -Name $Share -Path "C:\Shares\$Share" -ErrorAction SilentlyContinue
    Write-Host "Created share: $Share" -ForegroundColor Green
}

# Apply audit rules
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone","Read,Write,Delete","ContainerInherit,ObjectInherit","None","Success,Failure"
)

foreach ($Share in $Shares) {
    $acl = Get-Acl "C:\Shares\$Share"
    $acl.AddAuditRule($auditRule)
    Set-Acl "C:\Shares\$Share" $acl
    Write-Host "Audit rule applied to: C:\Shares\$Share" -ForegroundColor Green
}
