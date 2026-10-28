# Enterprise On-Prem IAM: Joiner / Mover / Leaver (JML) & PKI Audit Script
# Environment: lab.local (DC 192.168.2.10)

Import-Module ActiveDirectory

Write-Host "=== [1] SETTING UP ENTERPRISE IAM OUs & SECURITY GROUPS ===" -ForegroundColor Cyan
$OUs = @("IAM_HR", "IAM_IT", "IAM_Disabled_Leavers")
foreach ($ou in $OUs) {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou -Path "DC=lab,DC=local" -ProtectedFromAccidentalDeletion $false
        Write-Host "[CREATED OU] OU=$ou,DC=lab,DC=local"
    }
}

$Groups = @("SG_HR_Staff", "SG_IT_Admins")
foreach ($grp in $Groups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$grp'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $grp -GroupScope Global -GroupCategory Security -Path "DC=lab,DC=local"
        Write-Host "[CREATED GROUP] $grp"
    }
}

Write-Host "`n=== [2] JOINER WORKFLOW: Onboarding New Employee (Sarah Connor -> HR) ===" -ForegroundColor Green
$Username = "s.connor"
if (-not (Get-ADUser -Filter "SamAccountName -eq '$Username'" -ErrorAction SilentlyContinue)) {
    $Password = ConvertTo-SecureString "WorkPlace@2026!" -AsPlainText -Force
    New-ADUser -Name "Sarah Connor" -SamAccountName $Username -UserPrincipalName "$Username@lab.local" `
        -Path "OU=IAM_HR,DC=lab,DC=local" -Department "Human Resources" -Title "HR Analyst" `
        -AccountPassword $Password -Enabled $true
}
Add-ADGroupMember -Identity "SG_HR_Staff" -Members $Username -ErrorAction SilentlyContinue
Get-ADUser $Username -Properties Department, Title, MemberOf | Select-Object Name, SamAccountName, Enabled, Department, DistinguishedName, @{N="Groups";E={$_.MemberOf}}

Write-Host "`n=== [3] MOVER WORKFLOW: Role Transfer (HR -> IT) & Removing Old Access ===" -ForegroundColor Yellow
Remove-ADGroupMember -Identity "SG_HR_Staff" -Members $Username -Confirm:$false -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity "SG_IT_Admins" -Members $Username -ErrorAction SilentlyContinue
Set-ADUser -Identity $Username -Department "IT Operations" -Title "IAM Support Engineer"
Get-ADUser $Username | Move-ADObject -TargetPath "OU=IAM_IT,DC=lab,DC=local"
Get-ADUser $Username -Properties Department, Title, MemberOf | Select-Object Name, Department, Title, DistinguishedName, @{N="Groups";E={$_.MemberOf}}

Write-Host "`n=== [4] LEAVER WORKFLOW: Offboarding, Stripping Access & Disabling Account ===" -ForegroundColor Red
Remove-ADGroupMember -Identity "SG_IT_Admins" -Members $Username -Confirm:$false -ErrorAction SilentlyContinue
Disable-ADAccount -Identity $Username
Set-ADUser -Identity $Username -Description "OFFBOARDED LEAVER - Ticket #IAM-2026-104 - $(Get-Date -Format 'yyyy-MM-dd')"
Get-ADUser $Username | Move-ADObject -TargetPath "OU=IAM_Disabled_Leavers,DC=lab,DC=local"
Get-ADUser $Username -Properties Description, MemberOf | Select-Object Name, Enabled, DistinguishedName, Description, @{N="Groups";E={$_.MemberOf}}

Write-Host "`n=== [5] INTERNAL PKI CERTIFICATE PROVISIONING & VERIFICATION ===" -ForegroundColor Cyan
$Cert = New-SelfSignedCertificate -Subject "CN=internal-pki.lab.local" -KeyUsage DigitalSignature, KeyEncipherment -CertStoreLocation "Cert:\LocalMachine\My"
Get-ChildItem "Cert:\LocalMachine\My\$($Cert.Thumbprint)" | Select-Object Subject, Thumbprint, NotAfter
