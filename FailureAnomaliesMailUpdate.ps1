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
    [string]$TenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
 
   [Parameter(Mandatory=$false)]
   [AllowNull()][AllowEmptyString()]
   [string]$SubscriptionId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",

   [Parameter(Mandatory=$false)]
   [AllowNull()][AllowEmptyString()]
   [string]$ResourceGroupName = "resourceGroupName",

   [Parameter(Mandatory=$false)]
   [AllowNull()][AllowEmptyString()]
   [string]$ResourceName = "resourceName"

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



function Select-NonNullProps {
    param
    (
        [Parameter(Mandatory = $true)]
        $object
    )
    # get the root members

        $rootMembers = $object | Get-Member -ErrorAction SilentlyContinue | Where-Object { $_.MemberType -match "Property"} 
       
        # grab the names of the members
        $targetProps = $object.psobject.properties.Name

        # Create the filtered list of those properties whose value is not $null
        $nonNullProps = $targetProps.Where({ $null -ne $object.$_ })
        
        $object = $object | Select-Object $nonNullProps
        
        $excludedTypes = "System.Boolean", "System.String", "System.Int32", "System.Char"

        $rootMembers | ForEach-Object{

            #Base name of property
            $propName = $_.Name

            #Object to process
            $obj = $($object.$propName)
            
            # Make sure it's not null, then recurse, incrementing $Level                        
            
            if($null -ne $obj){
                $isArray = $obj -is [array]

                # Get the type, and only recurse into it if it is not one of our excluded types

                if($isArray){
                    # treat this as an array and iterate through each property of each object type we're tracking 
                    # we're going to assume that the array will always contain the same type
                    # and just grab the type of the first element 
                    if($obj.length -gt 0){
                        $type = ($obj[0].GetType()).ToString()    
                    }
                }
                else{

                    $type = ($obj.GetType()).ToString()            
                }
           
                # Only recurse if it's not of a type in our list
                if (!($excludedTYpes.Contains($type) ) )
                {   
                    if($isArray){
                        $processed = @()
                        foreach($item in $obj){
                            
                            $processed += Select-NonNullProps($obj)
    
                        }
                        
                    }                                                     
                    else{

                        $obj = Select-NonNullProps($obj)
                        if($object.$propName -is [array]){
                            $object.$propName = ,$obj

                        }
                        else {
                            $object.$propName = $obj
                        }
                    }
                        
                }
            }

        }
        
        return $object
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
#Read-Host "Press any key to proceed"

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
    if ($rule.Name.StartsWith($failureAnomalieResourceName))
    {
        Write-Output "Found Failure Anomalies alert rule - disabling."   
        
        $updateRuleUri = "https://management.azure.com/subscriptions/$($subscription.Id)/resourcegroups/$($ResourceGroupName)/providers/microsoft.insights/alertrules/$($rule.Name)?api-version=2016-03-01"

        $rule.properties.isEnabled = $true

        $rule = Select-NonNullProps($rule)

        # Extract the list of non-null properties directly from the input object
        # and convert to JSON.
        $ruleJson = $rule | ConvertTo-Json -Depth 4
 
        # Update rule info:
        $updatedRule = Invoke-RestMethod -Uri $updateRuleUri -Headers $authHeader -Method Put -Body $ruleJson -ContentType "application/json" 
        Write-Output "Updated rule succefully: " $updatedRule.Name 
        {break}
    }
}