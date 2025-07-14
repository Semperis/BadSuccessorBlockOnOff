# ===========================================================================
# Bad-Successor-VIEW-STATE-OF-BLOCK.ps1
# Viewing Value Of systemOnly For 'CN=ms-DS-Managed-Account-Preceded-By-Link'
# ===========================================================================
#
# SOURCE....: https://github.com/Semperis/BadSuccessorBlockOnOff
#
# LICENSE...: https://github.com/Semperis/BadSuccessorBlockOnOff?tab=MIT-1-ov-file
#
# WARNING: This Code Can ONLY Be Used When The W2K25 AD Schema Has Been Implemented! There IS NO Check To Validate This!
# WARNING: The Actual Schema Master MUST Be Online And It Must Be Recognized As The Schema Master By Other RWDCs (i.e., "Initial synchronization" Must Have Taken Place And NO Recent Events With ID 2092 Exist About The FSMO Role: CN=Schema,CN=Configuration,DC=<FOREST>,DC=<TLD>)
# WARNING: AD Replication MUST BE In A Healthy State
#

Invoke-Command -ScriptBlock {
	Clear-Host
	$thisADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
	$msDSManagedAccountPrecededByLinkDN = "CN=ms-DS-Managed-Account-Preceded-By-Link,$($thisADForest.Schema.Name)"
	Write-Host "Reviewing Configuration Of '$msDSManagedAccountPrecededByLinkDN'" -ForegroundColor Magenta
	$msDSManagedAccountPrecededByLink = [ADSI]"LDAP://$($thisADForest.SchemaRoleOwner.Name)/$msDSManagedAccountPrecededByLinkDN"
	Write-Host " > 'systemOnly'........: $($msDSManagedAccountPrecededByLink.systemOnly)" -ForegroundColor Yellow
	Write-Host ""
}