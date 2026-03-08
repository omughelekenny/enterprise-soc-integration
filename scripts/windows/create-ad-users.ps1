# SOC Lab - Active Directory User Creation Script
# Run as Administrator on Domain Controller

# Create OUs
$OUs = @("IT Department", "HR Department", "Finance Department", "Sales Department")
foreach ($OU in $OUs) {
    New-ADOrganizationalUnit -Name $OU -Path "DC=lab,DC=local" -ErrorAction SilentlyContinue
    Write-Host "Created OU: $OU" -ForegroundColor Green
}

# Create Users
$Users = @{
    "IT Department" = @("john.doe", "jane.smith", "mike.johnson")
    "HR Department" = @("sarah.wilson", "david.brown", "lisa.davis")
    "Finance Department" = @("robert.miller", "amanda.garcia", "chris.martinez")
    "Sales Department" = @("jennifer.taylor", "kevin.anderson", "michelle.thomas")
}

foreach ($Dept in $Users.Keys) {
    foreach ($User in $Users[$Dept]) {
        New-ADUser -Name $User `
            -SamAccountName $User `
            -UserPrincipalName "$User@lab.local" `
            -Path "OU=$Dept,DC=lab,DC=local" `
            -AccountPassword (ConvertTo-SecureString "P@sswOrd123" -AsPlainText -Force) `
            -Enabled $true `
            -ErrorAction SilentlyContinue
        Write-Host "Created user: $User in $Dept" -ForegroundColor Green
    }
}

# Create Security Groups
$Groups = @("IT-Users", "HR-Users", "Finance-Users", "Sales-Users")
$GroupOUs = @("IT Department", "HR Department", "Finance Department", "Sales Department")

for ($i = 0; $i -lt $Groups.Count; $i++) {
    New-ADGroup -Name $Groups[$i] `
        -GroupScope Global `
        -Path "OU=$($GroupOUs[$i]),DC=lab,DC=local" `
        -ErrorAction SilentlyContinue
    Write-Host "Created group: $($Groups[$i])" -ForegroundColor Green
}
