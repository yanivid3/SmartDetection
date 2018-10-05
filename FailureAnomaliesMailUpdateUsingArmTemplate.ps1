<#
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.We grant You a 
nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the 
Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software product in which the 
Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; 
and(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ 
fees, that arise or result from the use or distribution of the Sample Code.
Please note: None of the conditions outlined in the disclaimer above will supercede the terms and conditions contained within 
the Premier Customer Services Description.
#>

# pass in or update these parameters to suit your needs 
Param(

    [Parameter(Mandatory=$false)]
    [AllowNull()][AllowEmptyString()]
    [string]$TenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47",
 
   [Parameter(Mandatory=$false)]
   [AllowNull()][AllowEmptyString()]
   [string]$SubscriptionId = "ebbc180c-3532-4e79-8750-adfd7757a466",

   [Parameter(Mandatory=$false)]
   [AllowNull()][AllowEmptyString()]
   [string]$ResourceGroupName = "ILDC-PPE",

   [Parameter(Mandatory=$false)]
   [AllowNull()][AllowEmptyString()]
   [string]$ResourceName = "DeepInsights-Ops-INT-inprod",

   [Parameter(Mandatory=$false)]
   [AllowNull()][AllowEmptyString()]
   [string]$ArmTemplatePath = "C:\Users\yanivy\Documents\FailureAnomaliesConf\FailureAnomaliesAlertRule.json",

   [Parameter(Mandatory=$false)]
   [AllowNull()][AllowEmptyString()]
   [bool]$Enabled = $true,

   [Parameter(Mandatory=$false)]
   [AllowNull()][AllowEmptyString()]
   [bool]$SendEmails = $false,

   [Parameter(Mandatory=$false)]
   [AllowNull()][AllowEmptyString()]
   [string[]]$CustomEmails = @("yanivy@microsoft.com","aiedison@microsoft.com"),

   [Parameter(Mandatory=$false)]
   [AllowNull()][AllowEmptyString()]
   [string]$DeploymentName = "SmartDetectionRulesDeployment"
   
)

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
			Write-Output "Login to default tenant"
			Login-AzureRmAccount 
		}
		else
		{
			Write-Output "Login to tenant:" ($TenantId)
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
		
    #$adal = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.dll" 
    #[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null 
  
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


# Check if AzureRM is installed. Ream more here : https://docs.microsoft.com/en-us/powershell/azure/install-azurerm-ps?view=azurermps-5.4.0
if ($null -eq (Get-Module -ListAvailable -Name AzureRM*)) 
{
	Write-Output "AzureRM module is missing on this machine. please run from another machine, or install using following documentation: https://docs.microsoft.com/en-us/powershell/azure/install-azurerm-ps?view=azurermps-5.4.0"
	# Install-Module -Name AzureRM -AllowClobber
}

# Login to AzureRmAccount (if not logged in already)
Login -TenantId $TenantId

# Fetch all subscriptions, and prompt user to select relevant subscriptions.
$subscription = Get-AzureRmSubscription -SubscriptionId $SubscriptionId

Write-Output "Updating the apps in following subscription [resource]:  $($subscription) [$($ResourceName)]" 

# Get access token to fetch proactive detection rules.
$token = GetAuthToken -TenantId $subscription.TenantId

$authHeader = @{
	'Authorization' = $token.CreateAuthorizationHeader()
}
	
Write-Output "working on subscription:" $subscription.Name ($subscription.Id)
Select-AzureRmSubscription $subscription.Id | Out-Null

$listRulesUri = "https://management.azure.com/subscriptions/$($subscription.Id)/resourcegroups/$($ResourceGroupName)/providers/microsoft.insights/alertrules?api-version=2016-03-01"
            
# Get rule info:
$response = Invoke-RestMethod -Uri $listRulesUri -Headers $authHeader -Method Get

$rules = $response.value

Write-Output "received rules count:" $rules.count

$failureAnomalieResourceName = "Failure Anomalies - {0}" -f $ResourceName;

foreach ($rule in $rules)
{
    if ($rule.Name -eq $failureAnomalieResourceName)
    {
        Write-Output "Found Failure Anomalies alert rule - Updating its configuration"  
                
        $metricName = $rule.properties.condition.datasource.metricName
        $params = @{MetricName=$metricName;AIResourceName=$ResourceName;Enabled=$Enabled;SendEmails=$SendEmails;CustomEmails=$CustomEmails}

        New-AzureRmResourceGroupDeployment -Name $DeploymentName -ResourceGroupName $ResourceGroupName -TemplateFile $armTemplatePath -TemplateParameterObject $params
                
        Write-Output "Updated rule succefully: " $rule.Name
        {break}        
    }
}