# ================================================================================================================
# VIEW DATA IN ATTRIBUTES "msDS-groupMSAMembership", "msDS-DelegatedMSAState", "msDS-ManagedAccountPrecededByLink"
# ================================================================================================================
#
# SOURCE....: https://github.com/Semperis/BadSuccessorBlockOnOff
#
# LICENSE...: https://github.com/Semperis/BadSuccessorBlockOnOff?tab=MIT-1-ov-file
#

# The DN Of The dMSA To Target
$dMSADN = "<DN Of The dMSA To Target>"

Invoke-Command -ArgumentList $dMSADN -ScriptBlock {
	Param (
		$dMSADN
	)

	Clear-Host

	$thisADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
	$rwdcPDCFQDN = $thisADDomain.PdcRoleOwner.Name

	Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
	[Timespan]$requestTimeout = (New-Object System.TimeSpan(0,0,120)) # Default: 120 seconds
	$ldapDirectoryID = New-Object -TypeName System.DirectoryServices.Protocols.LdapDirectoryIdentifier -ArgumentList $ldapServerFQDN, $ldapServerPort, $true, $false
	$ldapSearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
	$ldapAuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
	$ldapConnection = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList $ldapDirectoryID, $null, $ldapAuthType
	$ldapConnection.SessionOptions.Sealing = $true
	$ldapConnection.SessionOptions.Signing = $true
	$ldapSearchRequest.DistinguishedName = $dMSADN
	$ldapSearchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
	$securityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
	$sdFlagLdapControl = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($securityMasks)
	[void]($ldapSearchRequest.Controls.Add($sdFlagLdapControl))
	[void]($ldapSearchRequest.Attributes.Add("distinguishedName"))
	[void]($ldapSearchRequest.Attributes.Add("sAMAccountName"))
	[void]($ldapSearchRequest.Attributes.Add("msDS-groupMSAMembership"))
	[void]($ldapSearchRequest.Attributes.Add("msDS-DelegatedMSAState"))
	[void]($ldapSearchRequest.Attributes.Add("msDS-ManagedAccountPrecededByLink"))
	[System.DirectoryServices.Protocols.SearchResponse]$ldapSearchResponse = $ldapConnection.SendRequest($ldapSearchRequest, $requestTimeout)
	Write-Host "Distinguished Name...: $($ldapSearchResponse.Entries.Attributes.'distinguishedname'[0])" -ForegroundColor Yellow
	Write-Host "Sam Account Name.....: $($ldapSearchResponse.Entries.Attributes.'samaccountname'[0])" -ForegroundColor Yellow
	If (-not [string]::IsNullOrEmpty($ldapSearchResponse.Entries.Attributes."msds-groupmsamembership")) {
		$adSecurity = New-Object System.DirectoryServices.ActiveDirectorySecurity
		$adSecurity.SetSecurityDescriptorBinaryForm($ldapSearchResponse.Entries.Attributes.'msds-groupmsamembership'[0])
		$adSecurity.Access.IdentityReference.Value | ForEach-Object {
			Write-Host "Pwd Allowed 2 Get By.: $($_)" -ForegroundColor Yellow
		}
	}
	Write-Host "dMSA State...........: $($ldapSearchResponse.Entries.Attributes.'msds-delegatedmsastate'[0])" -ForegroundColor Yellow
	If (-not [string]::IsNullOrEmpty($ldapSearchResponse.Entries.Attributes."msds-managedaccountprecededbylink")) {
		Write-Host "Linked Account DN....: $($ldapSearchResponse.Entries.Attributes.'msds-managedaccountprecededbylink'[0])" -ForegroundColor Yellow
	}
	Write-Host ""
}