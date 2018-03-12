

#
# This script will update your Azure Application Insights Smart Detection rules email configuration
# You can set whether to send emails to owners, contributers and readers, and add custom email addresses that will get the emails.
# You can read more about it here: https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-diagnostics
#

[CmdletBinding()]
Param(
 
   [ValidateSet("True","False")] 
   [Parameter(Mandatory=$True)]
   [string]$SendMailtoOwnersAndReadersEnabled,
	
   [Parameter(Mandatory=$True, HelpMessage="Set comma seperate demail list")]
   [string[]]$CustomeMails,
   
   [Parameter(Mandatory=$False)]
   [string]$TenantId
)

# create the autoherization token (manual approach)
# taken from: https://blogs.technet.microsoft.com/paulomarques/2016/03/21/working-with-azure-active-directory-graph-api-from-powershell/
# for full automation, the token will need to be retrieved by a non-manual approach
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

Write-Host "Started runnign with following params: SendMailToOwnesAndReaders: " ($SendMailtoOwnersAndReadersEnabled) ". Custom Mails: " ($CustomeMails)

# Install Azure PowerShell: https://docs.microsoft.com/en-us/powershell/azure/install-azurerm-ps?view=azurermps-5.4.0
if ((Get-Module -ListAvailable -Name AzureRM) -eq $null) 
{
	Write-Host "Installing Azure PowerShell"
	Install-Module -Name AzureRM -AllowClobber
}

if ($TenantId -eq $null)
{
	Write-Host "Login to default tenant"
	Login-AzureRmAccount 
}
else
{
	Write-Host "Login to tenant:" ($TenantId)
	Login-AzureRmAccount -TenantId $TenantId
}

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
 
foreach ($subscription in $subscriptions) 
{
	if ($subscriptionsIndexesArray.contains([string]$subscription.Index) -eq $False)
	{
		continue; #skip this subscription
	}
	
	Write-Host "working on subscription:" $subscription.Name ($subscription.Id)
	Select-AzureRmSubscription $subscription.Id | Out-Null
	$selectedSubscription = Select-AzureRmSubscription $subscription.Id
	$token = GetAuthToken -TenantId $subscription.TenantId
	$authHeader = @{
		'Authorization' = $token.CreateAuthorizationHeader()
	}
	
	$applicationInsightsResources = Get-AzureRmApplicationInsights
	Write-Host "Total appinsights reroueces found:" $applicationInsightsResources.count ". Names: " ($applicationInsightsResources.Name -join ",")
	Read-Host "Press any key to proceed"
	
	foreach ($resource in $applicationInsightsResources) 
	{
		$listRulesUri = "https://management.azure.com/subscriptions/$($subscription.Id)/resourcegroups/$($resource.ResourceGroupName)/providers/microsoft.insights/components/$($resource.Name)/ProactiveDetectionConfigs?api-version=2015-05-01"
		Write-Host "Current Appinsights resource:" $resource.Name "; Uri: " $listRulesUri
					
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
			Write-Host "rule json: " $rule
			$rule.sendEmailsToSubscriptionOwners = ($SendMailtoOwnersAndReadersEnabled -eq "True")
			$rule.customEmails = $CustomeMails
			
			$ruleJson = $rule | ConvertTo-Json

			# Update rule info:
			Invoke-RestMethod -Uri $updateRuleUri -Headers $authHeader -Method Put -Body $ruleJson -ContentType "application/json"
			Write-host "Updated rule succeffully" 
		}
	}
}