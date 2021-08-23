# Check If Admin Logged in and the script it running as admin, if not relaunch as admin automatically.

if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}

# If you do not need the Microsoft 365 functions comment them out, if you use 2FA then keep these emailed otherwise if you don't comment them out and use the office 365 login below as you won't have to sign in multiple times
Connect-ExchangeOnline
Connect-MsolService
Connect-MicrosoftTeams

# Script Vars
$dc = "DomainController"
$smtpserver = "smtpserver.domain.local"
$homeDir = "\\DomainController\HomeDrive$"

# Script Functions
function Start-Sleep($seconds) {
    $doneDT = (Get-Date).AddSeconds($seconds)
    while($doneDT -gt (Get-Date)) {
        $secondsLeft = $doneDT.Subtract((Get-Date)).TotalSeconds
        $percent = ($seconds - $secondsLeft) / $seconds * 100
        Write-Progress -Activity "Sleeping" -Status "Sleeping..." -SecondsRemaining $secondsLeft -PercentComplete $percent
        [System.Threading.Thread]::Sleep(500)
    }
    Write-Progress -Activity "Sleeping" -Status "Sleeping..." -SecondsRemaining 0 -Completed
}


# Start asking questions

$firstName = Read-Host "Please enter the new starters first name"

$lastName = Read-host "Please enter the new starters last name"

# We use first.last names as the usernames and email addresses
$SAMAccountName = "$firstName.$lastName"

$jobTitle = Read-Host "Please enter their job title"

$l = 1;
while($l -eq 1){
    switch($manager = Read-Host "Who will be the manager"){
        default {
            if($manager = Get-ADUser $manager -Properties * -Server $dc){
                $l = 0;
            }
        }
    }
}

$department = Read-Host "What department are they working in?"

$domainName = Read-Host "Which domain does this user need for their email address"
$l = 1;
while($l -eq 1){
    switch($IsaliasDomain = Read-Host "Does the account need a domain alias (yes/no)"){
        'yes'{
            $aliasDomain = Read-Host "Which domain alias needs to be added"
            if($aliasDomain){
                if($aliasDomain -ne $domainName){
                    $l = 0;
                }
                else{
                    write-host "Alias domain can't be the same as the primary one."
                }
            }
        }
        'no'{
            $l = 0;

        }
        default {
            Write-Host "Please enter yes or no..."
        }
    }
}

$l = 1;
while($l -eq 1){
    switch($office = Read-Host "What Office will they be based in?"){
        'Office1'{
            $webPage = 'www.company.co.uk'
            $streetAddress = 'Company Address here'
            $company = 'Company Co'
            $l = 0;
        }
        'Office2'{
            $webPage = 'www.company.co.uk'
            $streetAddress = 'Company Address here'
            $company = 'Company Co'
            $l = 0;

        }
        default {
            write-host "Please enter Office1 or Office2."
        }
    }
}

$ddi = Read-Host "What is the extension or direct dial phone number?"

$l = 1;
while($l -eq 1){
    switch($isCopyingPermissions = Read-Host "Are we copying from an existing account? (yes/no)"){
        'yes'{
            $n = 1;
            while($n -eq 1){
                switch($copyAccount = Read-Host "Please enter the account name that needs to be copied"){
                    default {
                        if($template = Get-ADUser $copyAccount -Properties * -Server $dc){
                            $n = 0;
                            $l = 0;
                        }
                    }
                }
            }
        }
        'no'{
            $n = 0;
            $l = 0;

        }
        default {
            Write-Host "Please enter yes or no..."
        }
    }
}

# If you don't use 2FA for office uncomment the below so you don't have to login 3 times
#$l = 1;
#while($l -eq 1){
#    $365AdminUserName = Read-Host "Pease enter your office 365 username"
#    $365AdminPassword = Read-Host "Please enter your Office 365 Password" -AsSecureString
#    $office365Login = new-object -typename System.Management.Automation.PSCredential -argumentlist $365AdminUserName, $365AdminPassword
#    Connect-MsolService -Credential $office365Login
#    $test365 = Get-MsolDomain -ErrorAction SilentlyContinue
#    if($test365){
#        $l = 0;
#    }
#}

# Check to see if the account already exists
if($checkAccountExists = Get-Aduser -Identity $SAMAccountName -ErrorAction SilentlyContinue -Server $dc){
    write-host "Account already exists, please delete the account and try again..."
    start-sleep(30);
    exit
}

# Create the account
if($isCopyingPermissions -eq 'yes'){
    $OU = "OU=" + ($template.DistinguishedName -split "=",3)[-1]
}else{
    $OU = "OU=User Staging,OU=Users,DC=domainname,DC=local"
}


#Password generator
$randoms = "!@#$%&*13456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxy".tochararray() 
$newPassword = ($randoms | Get-Random -count 12) -join ''
$SecurePwd = ConvertTo-SecureString $newPassword -AsPlainText -Force

Write-Host "Users password will be $newPassword"

New-ADUser -Name "$firstName $lastName" -DisplayName "$firstName $lastName" -Surname $lastName -GivenName $firstName -SamAccountName $SAMAccountName -UserPrincipalName "$SAMAccountName@$domainName" -Path $OU -HomeDrive "H" -HomeDirectory "$homeDir\$SAMAccountName" -Manager $manager -EmailAddress "$SAMAccountName@$domainName" -ChangePasswordAtLogon $false -AccountPassword $SecurePwd -Company $company -Title $jobTitle -StreetAddress $streetAddress -Department $department -OfficePhone $ddi -Office $office -HomePage $webPage -Server $dc

# Check we can see AD Account Exists now
$l = 1;
while($l -eq 1){
    if($NewAdAccount = Get-ADUser -Identity $SAMAccountName -Properties * -Server $dc){
        $l = 0;
    }
    else{
        start-sleep(10);
    }
}

Enable-ADAccount -Identity $SAMAccountName -Server $dc
Write-Host "Account now enabled"
Set-ADUser $SAMAccountName -Add @{ProxyAddresses="SMTP:$SAMAccountName@$domainName"} -Server $dc
if($aliasDomain){
    Set-ADUser $SAMAccountName -Add @{ProxyAddresses="smtp:$SAMAccountName@$aliasDomain"} -Server $dc
}
Write-Host "User Account Created..."
# Assign 365 license - ours is done by an AD group.
Add-ADGroupMember -Identity "SEC - Office 365 E3" -Members $SAMAccountName
Write-Host "Office 365 License Assigned."


# Copy AD Groups if required
if($isCopyingPermissions -eq 'yes'){
    $template.MemberOf | Where{$NewAdAccount.MemberOf -notcontains $_} |  Add-ADGroupMember -Members $NewAdAccount -Server $dc
    write-host "AD Groups copied..."
}

# Start Syncing to Office 365
Write-Host "Syncing account to Office 365..."
$session = New-PSSession -ComputerName $dc
Invoke-Command -Session $session -ScriptBlock {Import-Module -Name 'ADSync'}
Invoke-Command -Session $session -ScriptBlock {Start-ADSyncSyncCycle}
Remove-PSSession $session

# Wait for Office 365 to be setup if you don't use 2FA uncomment this
#Write-Host "Waiting for syncing to be completed and for Office account to be setup..."
#Import-Module MSOnline
#Connect-MsolService -Credential $office365Login
#Connect-MicrosoftTeams -Credential $office365Login
#$EXSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $office365Login -Authentication Basic -AllowRedirection
#Import-PSSession $EXSession -AllowClobber -DisableNameChecking

# Check if the user has a 365 account and mailbox
$l = 1;
while($l -eq 1){
    $checkMsol = Get-MsolUser -UserPrincipalName $NewAdAccount.UserPrincipalName -ErrorAction SilentlyContinue
    if($checkMsol.ObjectId){
        $l = 0;
    }
    else{
        start-sleep(300);
    }
}

$l = 1;
while($l -eq 1){
    $checkExchange = Get-Mailbox -Identity $NewAdAccount.UserPrincipalName -ErrorAction SilentlyContinue
    if($checkExchange.Guid){
        $l = 0;
    }
    else{
        start-sleep(300);
    }
}

# Copy Office 365 Groups if required
if($isCopyingPermissions -eq 'yes'){
    # Copy Office 365 Groups
    if(Get-MsolUser -UserPrincipalName $NewAdAccount.UserPrincipalName){
        $copyFrom365 = Get-MsolUser -UserPrincipalName $template.UserPrincipalName
        $copyTo365 = Get-MsolUser -UserPrincipalName $NewAdAccount.UserPrincipalName
        foreach ($Group in (Get-MsolGroup -all)) {
            if(Get-MsolGroupMember -all -GroupObjectId $Group.ObjectId | where {$_.Emailaddress -eq $copyFrom365.UserPrincipalName}){
                Add-TeamUser -GroupId $Group.ObjectId -User $copyTo365.UserPrincipalName -ErrorAction SilentlyContinue | Out-Null
                Add-MsolGroupMember -GroupObjectId $Group.ObjectId -GroupMemberType User -GroupMemberObjectId $copyFrom365.ObjectId -ErrorAction SilentlyContinue
                Add-DistributionGroupMember -Identity $Group.DisplayName -Member $copyTo365.UserPrincipalName -ErrorAction SilentlyContinue
                Add-UnifiedGroupLinks -Identity $Group.DisplayName -LinkType Members -Links $copyTo365.UserPrincipalName -ErrorAction SilentlyContinue
            }
        }
        Write-Host "Office 365 Groups Copied..."

        # Copy shared mailbox permissions
        $mailboxes = Get-Mailbox | Get-MailboxPermission -User $template.UserPrincipalName | select Identity,AccessRights
        foreach($mailbox in $mailboxes){
            Add-MailboxPermission -Identity $mailbox.Identity -User $copyTo365.UserPrincipalName -AccessRights $mailbox.AccessRights
        }
        $mailboxesout = $mailboxes.ForEach({[PSCustomObject]$_}) |ConvertTo-Html |Out-String
        
        $mailboxes1 = Get-Mailbox | Get-RecipientPermission | where Trustee -Like $template.UserPrincipalName | select Identity,AccessRights
        foreach($mailbox1 in $mailboxes1){
            Add-RecipientPermission -Identity $mailbox1.Identity -Trustee $copyTo365.UserPrincipalName -AccessRights $mailbox1.AccessRights -Confirm:$false
        }
        $mailboxesout1 = $mailboxes1.ForEach({[PSCustomObject]$_}) |ConvertTo-Html |Out-String

        write-host "Shared mailbox permissions copied..."
    }
}

# We disable OWA, EAS, POP and IMAP, if you don't need to do this then comment the below out
Set-CasMailbox -Identity $NewADAccount.UserPrincipalName -OWAEnabled $false
Write-Host "OWA Access Disabled..."

Set-CasMailbox -Identity $NewADAccount.UserPrincipalName -ActiveSyncEnabled $false
write-host "EAS Disabled..."

Set-CasMailbox -Identity $NewADAccount.UserPrincipalName -PopEnabled $false
write-host "POP Disabled..."

Set-CasMailbox -Identity $NewADAccount.UserPrincipalName -ImapEnabled $false
write-host "IMAP Disabled..."


Remove-PSSession $EXSession

# Generate Emails

# Email Vars
$DisplayName = $NewAdAccount.DisplayName
$emailAddress = $NewAdAccount.EmailAddress
$managerName = $manager.DisplayName

# Generate email to IT
$msg = "New starter account info:<br />"
$msg += "Username: $SAMAccountName<br />"
$msg += "Password: $newPassword<br />"
$msg += "Email Address: $emailAddress<br />"
$msg += "AD Location: $OU<br />"
$msg += "Manager: $managerName<br />"
if($eclipseKey){
    $msg += "Eclipse Key: $eclipseKey<br />"
}
if($isCopyingPermissions){
    $msg += "Shared Mailboxes: $mailboxesout<br />$mailboxesout1<br />"
}
Send-MailMessage -To "itsupport@company.co.uk" -Subject "New Starter Account Info - $displayName" -BodyAsHTML $msg -From "italerts@company.co.uk" -SmtpServer $smtpserver
Write-Host "Email sent to IT..."

# Generate email to manager
$msg = "Hello,<br /><br />"
$msg += "A request to setup a new user account has been completed, please see the login details below:<br />"
$msg += "Username: $SAMAccountName<br />"
$msg += "Password: $newPassword<br />"
$msg += "Email Address: $emailAddress<br />"
$msg += "Kind regards,<br />Internal IT"
Send-MailMessage -To $manager.EmailAddress -Subject "New Starter Account Info - $displayName" -BodyAsHTML $msg -From "italerts@company.co.uk" -SmtpServer $smtpserver
Write-Host "Email sent to Manager..."

# Generate email to new user

$msg = "Welcome $firstName,<br /><br />"
$msg += "Please take a moment to change your password, You can do this by selecting 'Ctrl+Alt+Del' and then 'Change a password'. The password requirements are:"
$msg += "<ul><li>Minimum of 8 characters</li><li>Must include lowercase and uppercase letters, numbers and special characters.</li><li>Must not include your name</li><li>And can't match the last 5 passwords you have used.</li></ul>"
$msg += "<b>As a reminder your current password is: $newPassword </b><br /><br />"


Send-MailMessage -To $NewAdAccount.EmailAddress -Subject "Account Info - $displayName" -BodyAsHTML $msg -From "italerts@company.co.uk" -SmtpServer $smtpserver -Attachments "\\domain.local\fs\IT Getting Started Guide.pdf"
Write-Host "Email sent to New User..."
Write-Host "New Starter $DisplayName completed."

pause
