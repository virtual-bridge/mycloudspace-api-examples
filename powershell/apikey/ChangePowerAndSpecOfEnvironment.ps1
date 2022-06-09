using namespace System

#Example of driving MyCloudSpace with powershell

#to power off an floor the spec execute with  
#.\script.ps1 -mode off

#to power n and reset desired spec execute with 
#.\script.ps1 -mode on

#NOTE: that you need to set your logpath, vm list, credentials sections below

Param
(
	[ValidateSet("On", "Off", "on", "off")] 
	[String] 
	$mode
)




#------------------- SETUP ---------------------#

#[VIRTUAL MACHINES] -------------------------#

#[LOG FILE] ---------------------#
#log file path you want to output the script log too
$Script:LogPath = 'C:\Temp\PowerSpec.log'

#[SERVER LIST] ------------------#
#object array needs to contain objects with in the following format/example where the poweredOnXXX is the value you wish to configure
#the machine as when it is running. Use the NAME from MyCloudSpace not the guest name/hostname of the machine
# $vmList =
# @(
# 	[pscustomobject]@{name="NIC_Test1";poweredOnCores=1;poweredOnSockets=4;poweredOnMemory=2},
# 	[pscustomobject]@{name="NIC_Test2";poweredOnCores=2;poweredOnSockets=2;poweredOnMemory=4},
# 	[pscustomobject]@{name="NIC_Test3";poweredOnCores=4;poweredOnSockets=1;poweredOnMemory=2}
# )


#[LOGIN/CREDENTIALS] -----------------------#
#it is *not recommended* to store these values as plain text - you should secure them out.
#Depending on where you are executing it from then you can use environment varialbles (local or azure function etc) and access with $env:XXX 
#or encrypt/decrypt the values here for password and PSK
#some reference links below for review and you can decide what to implement

$apiKey = ""
$username  = ""


#SECURE STRING DOCS - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring?view=powershell-6 
#ENCRYPT STRING with machine key https://stackoverflow.com/questions/46400234/encrypt-string-with-the-machine-key-in-powershell
#AZURE FUNCTIONS (the bit in yellow half way down) https://blog.tyang.org/2016/10/08/securing-passwords-in-azure-functions/ 


#[CLIENT ID (Optional)] ---------------------#
#override this to desired clientid if you are a reseller user
#if you are a client user then this will auotmatically fetched
$clientId = 0;

#------------------- END SETUP ---------------------#




#https://gallery.technet.microsoft.com/scriptcenter/Write-Log-PowerShell-999c32d0
function Write-Log 
{ 
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        [Parameter(Mandatory=$false)] 
        [Alias('LogPath')] 
        [string]$Path=$Script:LogPath, 
         
        [Parameter(Mandatory=$false)] 
        [ValidateSet("Error","Warn","Info")] 
        [string]$Level="Info", 
         
        [Parameter(Mandatory=$false)] 
        [switch]$NoClobber 
    ) 
 
    Begin 
    { 
        # Set VerbosePreference to Continue so that verbose messages are displayed. 
        $VerbosePreference = 'Continue' 
    } 
    Process 
    { 
         
        # If the file already exists and NoClobber was specified, do not write to the log. 
        if ((Test-Path $Path) -AND $NoClobber) { 
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name." 
            Return 
            } 
 
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path. 
        elseif (!(Test-Path $Path)) { 
            Write-Verbose "Creating $Path." 
            $NewLogFile = New-Item $Path -Force -ItemType File 
            } 
 
        else { 
            # Nothing to see here yet. 
            } 
 
        # Format Date for our Log File 
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
 
        # Write message to error, warning, or verbose pipeline and specify $LevelText 
        switch ($Level) { 
            'Error' { 
                Write-Error $Message 
                $LevelText = 'ERROR:' 
                } 
            'Warn' { 
                Write-Warning $Message 
                $LevelText = 'WARNING:' 
                } 
            'Info' { 
                Write-Verbose $Message 
                $LevelText = 'INFO:' 
                } 
            } 
         
        # Write log entry to $Path 
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append 
    } 
    End 
    { 
    } 
}


$asciiUri = "https://artii.herokuapp.com/make";
$print = irm "$($asciiUri)?font=big&text=MyCloudSpace API "	
Write-Host $print -ForegroundColor White
Write-Host ""

$print = irm "$($asciiUri)?font=ogre&text=Power and Spec"	
Write-Host $print -ForegroundColor DarkGreen
Write-Host ""


Write-Host $mode
if (!$mode) {
    Write-Log -Message "Please set the mode of the script (param name mode, values on or off)" -Level Error
    exit
}
$mode = $mode.ToLower()

#base url for the api
$baseApi = "https://api.mycloudspace.co.nz/";


#set header value for future calls to API
$headers = @{'Authorization'= 'apiKey ' + $apiKey; 'x-mcs-user' = $username};

#if clientid not set then use this call to grab the clientid from their profile.
if ($clientId -eq 0)
{
	$meResp = Invoke-RestMethod -Uri ($baseApi + 'api/userprofile/me') -ContentType 'application/json' -Method Get -Headers $headers;

	if ($meResp.client -ne 0) {
		$clientId = $meResp.client
	}
}

#check we now have a clientid (set as variable or fetched via profile)
if ($clientId -eq 0)
{
	Write-Log -Message "Client Id could not be found, if you are a reseller you need to set the client id varialble in the script" -Level Error
}



#get list of virtual machines from the platform
$clientVms = Invoke-RestMethod -Uri ($baseApi + 'api/client/virtualresources/' + $clientId) -ContentType 'application/json' -Method Get -Headers $headers;

foreach ($vm in $vmList)
{
	# $($vm.name)

	$asciiUri = "https://artii.herokuapp.com/make";
	$print = irm "$($asciiUri)?font=big&text=$($vm.name)"	
	Write-Host $print -ForegroundColor Cyan
	Write-Host ""
	#find the VM in the VM list returned from the clients so we can get the id etc
	$vmObj = $clientVms | where {$_.name -eq $vm.name}
	
	if ($vmObj.id)
	{
		Write-Log -Message "Found $($vmObj.name)"

		#we matched the vm from the defined list (via the name) to the VM on the client

		#default poweroperation object
		$powerOperationBody = [pscustomobject]@{VirtualResourceId=$vmObj.id;Operation='shutdownGuest'}

		#fetch detailed spec so we can see the state directly from platform
		$vmDetailed = Invoke-RestMethod -Uri ($baseApi + 'api/virtualresource/specification/' + $vmObj.id) -ContentType 'application/json' -Method Get -Headers $headers;

		if ($vmDetailed.powerState)
		{

			$needsSpecReset = $false;
			$needsPowerOperation = $false;

			if ($mode-eq "off" -and $vmDetailed.powerState -eq "Off") {
				Write-Log -Message "$($vmObj.name) is already $($vmDetailed.powerState), no need to shutdown"
				$powerOperationBody.Operation = '';
				#do nothing to this machine. it's already off.

			}

			if ($mode-eq "off" -and $vmDetailed.powerState -eq "On") {

                if ($vmObj.guestHostname -ne "")
                {
                    Write-Log -Message "$($vmObj.name) is $($vmDetailed.powerState), shutting down (guest)"
                    $powerOperationBody.Operation = 'shutdownGuest';
                }
                else {
                    Write-Log -Message "$($vmObj.name) is $($vmDetailed.powerState) and tools appears to be missing shutting down (forced)"
				    $powerOperationBody.Operation = 'off';
                }
				

				$needsPowerOperation = $true; #we need to turn it off

			}

			if ($mode -eq "on" -and $vmDetailed.powerState -eq "On") {
				Write-Log -Message "$($vmObj.name) is already $($vmDetailed.powerState), we will leave the server as it is"
				$powerOperationBody.Operation = '';

				#do nothing to this machine. it's already on... assume spec is correct (or we could check via detailed spec here)
			}

			if ($mode -eq "on" -and $vmDetailed.powerState -eq "Off") {
				Write-Log -Message "$($vmObj.name) is $($vmDetailed.powerState), we will reset specification and power on"
				$powerOperationBody.Operation = 'on';

				$needsPowerOperation = $true;
				$needsSpecReset = $true;

			}


			#do we need to respec (reset to desired running config) 
			if ($needsSpecReset)
			{
				Write-Log "Resetting spec for $($vmObj.name) back to $($vm.poweredOnCores) cores, $($vm.poweredOnSockets) sockets and $($vm.poweredOnMemory) gb memory"


				#default object to full spec
				$specOperationBody = [pscustomobject]@{
					VirtualResourceId=$vmObj.id;
					newMemorySize=$vm.poweredOnMemory;
					newCoreSize=$vm.poweredOnCores;
					newSocketSize=$vm.poweredOnSockets;
					currentCoreSize=$vmDetailed.cores;
					currentSocketSize=$vmDetailed.sockets;
					currentMemorySize=$vmDetailed.memoryGb;
				}


				$specOperation = Invoke-RestMethod -Uri ($baseApi + 'api/virtualresource/changeComputeSpecification') -Body ($specOperationBody | ConvertTo-Json) -ContentType 'application/json' -Method Post -Headers $headers;
				
				Write-Log "Sleeping for 5 seconds"
				
				Start-Sleep 5
			}
			
			
			#do we need to power this on or off?
			if ($needsPowerOperation)
			{
				Write-Log "Performing power $mode operation on $($vmObj.name)"

				$powerOperation = Invoke-RestMethod -Uri ($baseApi + 'api/virtualresource/powerOperation') -Body ($powerOperationBody | ConvertTo-Json) -ContentType 'application/json' -Method Post -Headers $headers;
				
				#we need to power off an wait for it to be off
				if ($mode -eq "off")
				{
					
					Write-Log "Waiting for $($vmObj.name) to be off"

					$powerLoopCount = 0
					
					Do {

						$powerLoopCount++

						if($powerLoopCount -gt 6) {
							Write-Log "We have reached a maximum loop count, forcing a power down."

							$powerOperationBody.Operation = 'off'
							$powerOperation = Invoke-RestMethod -Uri ($baseApi + 'api/virtualresource/powerOperation') -Body ($powerOperationBody | ConvertTo-Json) -ContentType 'application/json' -Method Post -Headers $headers;

							Write-Log "Sleeping for 5 seconds"

							Start-Sleep 5
							break
						}

						Write-Log "$($vmObj.name) is $($vmDetailed.powerState)"
						Write-Log "Refetching $($vmObj.name) details from the platform"
					 
						#fetch the spec so we can check the power
						$vmDetailed = Invoke-RestMethod -Uri ($baseApi + 'api/virtualresource/specification/' + $vmObj.id) -ContentType 'application/json' -Method Get -Headers $headers;


						Write-Log "Sleeping for 15 seconds"
						 
						Start-Sleep 15
					} 
					While ($vmDetailed.powerState -ne "Off" )

					#now its off. floor it.

					Write-Log "Flooring the spec of $($vmObj.name) to 1/1/1"


					#default object to full spec
					$specOperationBody = [pscustomobject]@{
						VirtualResourceId=$vmObj.id;
						newMemorySize=1;
						newCoreSize=1;
						newSocketSize=1;
						currentCoreSize=$vmDetailed.cores;
						currentSocketSize=$vmDetailed.sockets;
						currentMemorySize=$vmDetailed.memoryGb;
					}


					$specOperation = Invoke-RestMethod -Uri ($baseApi + 'api/virtualresource/changeComputeSpecification') -Body ($specOperationBody | ConvertTo-Json) -ContentType 'application/json' -Method Post -Headers $headers;
				
					Write-Log "Sleeping for 5 seconds"
				
					Start-Sleep 5

				}
				 

			}


		}
		else
		{
			Write-Log -Message "Could not retreive detailed specification for $($vm.name)" -Level Error

		}

	}
	else 
	{
		Write-Log -Message "Could not find $($vm.name) on the platform" -Level Error
	}
}

