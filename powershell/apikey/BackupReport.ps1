using namespace System

#Backup Report

#.\BackupReport.ps1

#NOTE: that you need to set your logpath, credentials in the sections below

#------------------- SETUP ---------------------#

#[LOG FILE] ---------------------#
#log file path you want to output the script log too
$Script:LogPath = 'C:\Temp\BackupReport.log'


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
$backupSessions = Invoke-RestMethod -Uri ($baseApi + 'api/backup/backupsessions/' + $clientId) -ContentType 'application/json' -Method Get -Headers $headers;
$backupSessions
foreach ($session in $backupSessions)
{

    Write-Host $([string]::Format("{0} ({1}) ", $session.name, $session.result)) -ForegroundColor Red
    Write-Host ""

    Write-Host $([string]::Format("Started {0:dd MMM yy HH:mm} ", $session.createdOn)) -ForegroundColor DarkGreen
    Write-Host $([string]::Format("Ended {0:dd MMM yy HH:mm} ", $session.endedOn)) -ForegroundColor DarkGreen

    $duration = $session.endedOn - $session.createdOn
    Write-Host $([string]::Format("Backup job took {0} minutes to complete", $duration.Minutes)) -ForegroundColor DarkGreen
    
    Write-Host ""

    if ($session.includes.Length -gt 0)
    {
        Write-Host "Protected virtual machine summary" -ForegroundColor White
        Write-Host ""

        foreach ($include in $session.includes)
        {
            Write-Host $([string]::Format("{0} ({1}) ", $include.name, $include.result)) -ForegroundColor Cyan
            $vmduration = $include.endedOn - $include.createdOn
            Write-Host $([string]::Format("VM took {0} minutes to backup", $vmduration.Minutes)) -ForegroundColor Yellow
            Write-Host ""

        }
    }
    else
    {
            Write-Host "No virtual machines in this job" -ForegroundColor Yellow
    }
    Write-Host ""
    

    Write-Host ""


}




