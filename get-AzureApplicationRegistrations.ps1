function get-datediff {
    param($enddate)
    $date = get-date
    $datediff = (New-TimeSpan -start $date -end $enddate).Days
    return $datediff
}
function Get-AzureApplicationRegistration {
    <#
        .DESCRIPTION
            Gets Azure Application Registrations and the secrets and certificate expiry information
            
            .
        .EXAMPLE
            Get-AzureApllicationRegistration -Verbose
        #>
    [CmdletBinding()]
    param ( )
    try {
        $apps = [System.Collections.Generic.List[PSobject]]@()
        $applications = Get-MgApplication -all
        foreach ($app in $applications) {
            $AppOwners = [System.Collections.Generic.List[psobject]]@()
            $secrets = $app.PasswordCredentials
            $secretscount = $secrets.count
            $certs = $app.KeyCredentials
            $certcount = $certs.count
            $owners = Get-MgApplicationOwner -ApplicationId $app.Id
            foreach ($owner in $owners) {
                write-verbose "getting User information for $($owner.id)"
                $o = (get-mguser -UserId $owner.id).DisplayName
                $AppOwners.Add($o)
            }
            # write-verbose "$($app.DisplayName) Owners are: $newowners" 
            if ($secretscount -ge 1) {
                foreach ($secret in $secrets) {
                    $s = [PSCustomObject]@{
                        Type              = "Secret"
                        DisplayName       = $app.DisplayName
                        AppID             = $app.AppId
                        Id                = $app.Id
                        Owners            = $AppOwners -join ';'
                        SecretDisplayName = $secret.displayname
                        SecretID          = $secret.Keyid
                        StartDateTime     = $secret.$StartDateTime
                        EndDateTime       = $secret.EndDateTime
                        DaystoExpire      = get-datediff $secret.EndDateTime
                    }
                    $apps.Add($s)
                    $s = $null
                }
            }
            if ($certcount -ge 1) {
                foreach ($cert in $certs) {
                    $c = [PSCustomObject]@{
                        Type            = "Cert"
                        DisplayName     = $app.DisplayName
                        AppID           = $app.AppId
                        Id              = $app.Id
                        Owners          = $AppOwners -join ';'
                        CertDisplayName = $cert.DisplayName
                        CertID          = $cert.Keyid
                        StartDateTime   = $cert.StartDateTime
                        EndDateTime     = $cert.EndDateTime
                        DaystoExpire    = get-datediff $cert.EndDateTime
                    }
                    $apps.Add($c)
                    $c = $null
                }
            }
                
        }
        return $apps
    }
    catch {
        $err = $_
        Write-Host $err.Exception.GetType().FullName 
        throw $err
    }
}

$appregistrations = Get-AzureApplicationRegistration
$appswithsecrets = $appregistrations | Where-Object {$_.type -eq 'Secret'}
$appswithcerts = $appregistrations | Where-Object {$_.type -eq 'Cert'}

$secretstoexpire = $appswithSecrets | Where-Object { $_.DaystoExpire -lt 30 -and $_.DaystoExpire -gt 0 }
$certstoexpire = $appswithcerts | Where-Object { $_.DaystoExpire -lt 30 -and $_.DaystoExpire -gt 0 }

if ($secretstoexpire.count -ge 1) {
    foreach ($secret in $secretstoexpire) {
        $emailbody = "
        Your Azure app registration Secret for $($secret.DisplayName) is about to expire.  Please see the details below for additonal information!

        Details:
          Secret ID: $($secret.secretid)
          Display Name: $($Secret.DisplayName)
          Expiration Date: $($secret.EndDateTime)
          Days to Expire: $($secret.DaystoExpire)

        App Registration location: 
        https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Overview/appId/$($secret.AppID)

        Please update your app registration before it expires.  If you need any assistance, please submit a ticket to ioserver@wgu.edu.


        Thank you
        "
        $sendasuser = "svc_azureoperations@wgu.edu"
        $sendMailMessageParam = @{
            Message = @{
                toRecipients = @(
                    @{
                        EmailAddress = @{
                            Address = "brian.simmons@wgu.edu"
                        }
                    }
                )
                Subject      = "$($secret.DisplayName) app registration secret will expire in $($secret.DaystoExpire) days"
                body         = @{
                    ContentType = "Text"
                    Content     = $emailbody
                } 
            }
            
        }
        Send-MgUserMail -UserId $sendasuser -BodyParameter $sendMailMessageParam
    }
}

if ($certstoexpire.count -ge 1) {
    foreach ($cert in $certstoexpire) {
        $emailbody = "
        Your Azure app registration Secret for $($cert.DisplayName) is about to expire.  Please see the details below for additonal information!

        Details:
          Cert ID: $($cert.certtid)
          Display Name: $($cert.DisplayName)
          Expiration Date: $($cert.EndDateTime)
          Days to Expire: $($cert.DaystoExpire)

        App Registration location: 
        https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Overview/appId/$($cert.AppID)

        Please update your app registration before it expires.  If you need any assistance, please submit a ticket to ioserver@wgu.edu.


        Thank you
        "
        $sendasuser = "svc_azureoperations@wgu.edu"
        $sendMailMessageParam = @{
            Message = @{
                toRecipients = @(
                    @{
                    EmailAddress = @{
                        Address = "brian.simmons@wgu.edu"
                    }
                }
                    )
                Subject      = "$($cert.DisplayName) app registration secret will expire in $($cert.DaystoExpire) days"
                body         = @{
                    ContentType = "Text"
                    Content     = $emailbody
                } 
            }
            
        }

    }
}