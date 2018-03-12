#
# This script will update your Azure Application Insights Smart Detection rules email configuration
# You can set whether to send emails to owners, contributers and readers, and add custom email addresses that will get the emails.
# You can read more about it here: https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-diagnostics
#
# Usage examples:
#		.\ProactiveDetectionScript.ps1 -SendMailtoOwnersAndReadersEnabled False -CustomeMails @()
#		.\ProactiveDetectionScript.ps1 -SendMailtoOwnersAndReadersEnabled False -CustomeMails person1@mail.com,person2@mail.com
#

Param(
 
   [ValidateSet("True","False")] 
   [Parameter(Mandatory=$True)]
   [string]$SendMailtoOwnersAndReadersEnabled,
	
   [Parameter(Mandatory=$True, HelpMessage="Set comma seperated email list. For an empty list use: @()")]
   [AllowEmptyCollection()]
   [string[]]$CustomeMails,
   
   [Parameter(Mandatory=$false)]
   [AllowNull()][AllowEmptyString()]
   [string]$TenantId
)

# Login to RmAzure account
function Login
{
    param
    (
        [Parameter(Mandatory = $true)]
        $TenantId
    )
	
    $needLogin = $true
    Try 
    {
        $content = Get-AzureRmContext
        if ($content) 
        {
            $needLogin = ([string]::IsNullOrEmpty($content.Account))
        } 
    } 
    Catch 
    {
        if ($_ -like "*Login-AzureRmAccount to login*") 
        {
            $needLogin = $true
        } 
        else 
        {
            throw
        }
    }

    if ($needLogin)
    {
        if ([string]::IsNullOrEmpty($TenantId))
		{
			Write-Host "Login to default tenant"
			Login-AzureRmAccount 
		}
		else
		{
			Write-Host "Login to tenant:" ($TenantId)
			Login-AzureRmAccount -TenantId $TenantId
		}
    }
}

# create the autoherization token
# taken from: https://blogs.technet.microsoft.com/paulomarques/2016/03/21/working-with-azure-active-directory-graph-api-from-powershell/
function GetAuthToken {
    param
    (
        [Parameter(Mandatory = $true)]
        $TenantId
    )
	
	Write-Host "Acquiring Token"
	
    $adal = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.dll" 
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null 
  
    $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"  
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob" 
    $resourceAppIdURI = "https://management.azure.com/" 
    $authority = "https://login.windows.net/$TenantId" 
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority 
    $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $redirectUri, "Auto")
 
    return $authResult
}

#####################################
# Main
#####################################

Write-Host "Started running with the following params: SendMailToOwnesAndReaders: " ($SendMailtoOwnersAndReadersEnabled) ". Custom Mails: " ($CustomeMails)

# Check if AzureRM is installed. Ream more here : https://docs.microsoft.com/en-us/powershell/azure/install-azurerm-ps?view=azurermps-5.4.0
if ((Get-Module -ListAvailable -Name AzureRM*) -eq $null) 
{
	Write-Host "AzureRM module is missing on this machine. please run from another machine, or install using following documentation: https://docs.microsoft.com/en-us/powershell/azure/install-azurerm-ps?view=azurermps-5.4.0"
	# Install-Module -Name AzureRM -AllowClobber
}

# Login to AzureRmAccount (if not logged in already)
Login -TenantId $TenantId

# Fetch all subscriptions, and prompt user to select relevant subscriptions.
$subscriptions = Get-AzureRmSubscription 
$subscriptionsIndexesArray = @()
$index = 0
foreach ($subscription in $subscriptions) 
{
	$subscriptionsIndexesArray += $index
	$subscription | Add-Member "Index" ($index++)
}

$subscriptions | ft Index, SubscriptionId, Name

$subscriptionsIndexes = Read-Host -Prompt $"Please select affected subscriptions: 1) 'all' or 2) Comma separated subscription indexes [0..$($index-1)]"
if ($subscriptionsIndexes -ne "all")
{
	$subscriptionsIndexesArray = $subscriptionsIndexes.split(",")
}
Write-Host "You selected to update the apps in following subscription: " ($subscriptionsIndexesArray -join ",")
Read-Host "Press any key to proceed"

# Get access token to fetch proactive detection rules.
$token = GetAuthToken -TenantId $subscription.TenantId
$authHeader = @{
	'Authorization' = $token.CreateAuthorizationHeader()
}
 
foreach ($subscription in $subscriptions) 
{
	if ($subscriptionsIndexesArray.contains([string]$subscription.Index) -eq $False)
	{
		continue; #skip this subscription
	}
	
	Write-Host "working on subscription:" $subscription.Name ($subscription.Id)
	Select-AzureRmSubscription $subscription.Id | Out-Null
	
	$applicationInsightsResources = Get-AzureRmApplicationInsights
	Write-Host "Total appinsights reroueces found:" $applicationInsightsResources.count ". Names: " ($applicationInsightsResources.Name -join ",")
	Read-Host "Press any key to proceed"
	
	foreach ($resource in $applicationInsightsResources) 
	{
		$updatedRules = @()
		$listRulesUri = "https://management.azure.com/subscriptions/$($subscription.Id)/resourcegroups/$($resource.ResourceGroupName)/providers/microsoft.insights/components/$($resource.Name)/ProactiveDetectionConfigs?api-version=2015-05-01"
		Write-Host "Current Appinsights resource:" $resource.Name # "; Uri: " $listRulesUri
					
		# Get rule info:
		$rules = Invoke-RestMethod -Uri $listRulesUri -Headers $authHeader -Method Get
		Write-host "received rules count:" $rules.count

		foreach ($rule in $rules)
		{
			if ($rule.ruleDefinitions.SupportsEmailNotifications -eq $false)
			{
				Write-Host "Rule does not support mails. skipping"
				continue;
			}
			
			$updateRuleUri = "https://management.azure.com/subscriptions/$($subscription.Id)/resourcegroups/$($resource.ResourceGroupName)/providers/microsoft.insights/components/$($resource.Name)/ProactiveDetectionConfigs?ConfigurationId=$($rule.name)&api-version=2015-05-01"

			$rule.sendEmailsToSubscriptionOwners = ($SendMailtoOwnersAndReadersEnabled -eq "True")
			$rule.customEmails = $CustomeMails
			
			$ruleJson = $rule | ConvertTo-Json

			# Update rule info:
			$updatedRules += Invoke-RestMethod -Uri $updateRuleUri -Headers $authHeader -Method Put -Body $ruleJson -ContentType "application/json" 
			Write-host "Updated rule succeffully" 
		}
		
		Write-Host "Updated all rules for resource:" $resource.Name
		$updatedRules | ft name, enabled, sendEmailsToSubscriptionOwners, customEmails 
	}
}
