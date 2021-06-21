using namespace System

#Take a snapshot 

#.\TakeSnapshotOfVirtualMachine.ps1 -vmHostname "WIN-2A4JPC0ITEJ" -snapshotName "This is from the API"

#NOTE: that you need to set your logpath, credentials in the sections below

Param
(
	[Parameter(Mandatory=$true)][String] 
    $vmHostname,
    [Parameter(Mandatory=$true)][String] 
	$snapshotName
)

#------------------- SETUP ---------------------#

#[LOG FILE] ---------------------#
#log file path you want to output the script log too
$Script:LogPath = 'C:\Temp\TakeVMSnapshot.log'


#[LOGIN/CREDENTIALS] -----------------------#
#it is *not recommended* to store these values as plain text - you should secure them out.
#Depending on where you are executing it from then you can use environment varialbles (local or azure function etc) and access with $env:XXX 
#or encrypt/decrypt the values here for password and PSK
#some reference links below for review and you can decide what to implement

$otpPsk = ""
$username = ""
$password = ""

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


$Script:Base32Charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'


#base url for the api
$baseApi = "https://api.mycloudspace.co.nz/";


#https://github.com/HumanEquivalentUnit/PowerShell-Misc/blob/master/GoogleAuthenticator.psm1
function Get-GoogleAuthenticatorPin
{
    [CmdletBinding()]
    Param
    (
        # BASE32 encoded Secret e.g. 5WYYADYB5DK2BIOV
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]
        $Secret,

        # OTP time window in seconds
        $TimeWindow = 30
    )


    # Convert the secret from BASE32 to a byte array
    # via a BigInteger so we can use its bit-shifting support,
    # instead of having to handle byte boundaries in code.
    $bigInteger = [Numerics.BigInteger]::Zero
    foreach ($char in ($secret.ToUpper() -replace '[^A-Z2-7]').GetEnumerator()) {
        $bigInteger = ($bigInteger -shl 5) -bor ($Script:Base32Charset.IndexOf($char))
    }

    [byte[]]$secretAsBytes = $bigInteger.ToByteArray()
    

    # BigInteger sometimes adds a 0 byte to the end,
    # if the positive number could be mistaken as a two's complement negative number.
    # If it happens, we need to remove it.
    if ($secretAsBytes[-1] -eq 0) {
        $secretAsBytes = $secretAsBytes[0..($secretAsBytes.Count - 2)]
    }


    # BigInteger stores bytes in Little-Endian order, 
    # but we need them in Big-Endian order.
    [array]::Reverse($secretAsBytes)
    

    # Unix epoch time in UTC and divide by the window time,
    # so the PIN won't change for that many seconds
    $epochTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    
    # Convert the time to a big-endian byte array
    $timeBytes = [BitConverter]::GetBytes([int64][math]::Floor($epochTime / $TimeWindow))
    if ([BitConverter]::IsLittleEndian) { 
        [array]::Reverse($timeBytes) 
    }

    # Do the HMAC calculation with the default SHA1
    # Google Authenticator app does support other hash algorithms, this code doesn't
    $hmacGen = [Security.Cryptography.HMACSHA1]::new($secretAsBytes)
    $hash = $hmacGen.ComputeHash($timeBytes)


    # The hash value is SHA1 size but we want a 6 digit PIN
    # the TOTP protocol has a calculation to do that
    #
    # Google Authenticator app may support other PIN lengths, this code doesn't
    
    # take half the last byte
    $offset = $hash[$hash.Length-1] -band 0xF

    # use it as an index into the hash bytes and take 4 bytes from there, #
    # big-endian needed
    $fourBytes = $hash[$offset..($offset+3)]
    if ([BitConverter]::IsLittleEndian) {
        [array]::Reverse($fourBytes)
    }

    # Remove the most significant bit
    $num = [BitConverter]::ToInt32($fourBytes, 0) -band 0x7FFFFFFF
    
    # remainder of dividing by 1M
    # pad to 6 digits with leading zero(s)
    # and put a space for nice readability
    $PIN = ($num % 1000000).ToString().PadLeft(6, '0')


    [PSCustomObject]@{
        'PIN Code' = $PIN
        'Seconds Remaining' = ($TimeWindow - ($epochTime % $TimeWindow))
    }
}




#get latest pincode and login
$otp = Get-GoogleAuthenticatorPin $otpPsk
$loginResp = Invoke-RestMethod -Uri ($baseApi + 'token') -ContentType 'multipart/form-data' -Method Post -Headers @{'X-OTP'=($otp.'PIN Code')} -Body @{'grant_type'='password';'username'=$username;'password'=$password};

#set header value for future calls to API
$headers = @{'Authorization'= 'Bearer ' + $loginResp.access_token};

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

#find the VM by hostname.
$vmObj = $clientVms | where {$_.guestHostname -eq $vmHostName}
	
if ($vmObj.id)
{
    Write-Log -Message "Found $($vmObj.name)"

    #snapshot payload
    $createSnapshotBody = [pscustomobject]@{
        VirtualResourceId=$vmObj.id;
        Name=$snapshotName;
    }

    Write-Log "Creating snapshot on $($vmObj.name)"

    $snapshotOperation = Invoke-RestMethod -Uri ($baseApi + 'api/virtualresource/snapshotcreate') -Body ($createSnapshotBody | ConvertTo-Json) -ContentType 'application/json' -Method Post -Headers $headers;
    
    #sleep before checking snapshot exsits, wait for platform to apply snap
    Write-Log "Sleeping for 5 seconds"	
    Start-Sleep 5

    $snapshotLoopCount = 0;
	$snapshotFound = $false;				
    Do {

        $snapshotLoopCount++

        if($snapshotLoopCount -gt 6) {
            Write-Log "We have reached a maximum loop count, something must be wrong, not trying again." -Level Error
            break
        }

        Write-Log "Fetching $($vmObj.name) snapshots from platform"
        
        $vmSnapshots = Invoke-RestMethod -Uri ($baseApi + 'api/virtualresource/snapshots/' + $vmObj.id) -ContentType 'application/json' -Method Get -Headers $headers;

        foreach ($snap in $vmSnapshots)
        {
            #does a snapshot match what we created?
            if ($snap.name.StartsWith($snapshotName))
            {
                Write-Log "Found snapshot called $($snap.name) that matches, good to go."
                $snapshotFound = $true;
            }
        }

        Write-Log "Sleeping for 5 seconds" 
        Start-Sleep 5
    } 
    While ($snapshotFound -ne $true)


}
else 
{
    Write-Log -Message "Could not find $($vmHostName) on the platform" -Level Error
}


