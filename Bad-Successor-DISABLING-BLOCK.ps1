# ===============================================================================
# Bad-Successor-DISABLING-BLOCK
# Setting systemOnly For 'CN=ms-DS-Managed-Account-Preceded-By-Link' To **FALSE**
# ===============================================================================
#
# SOURCE....: https://github.com/Semperis/BadSuccessorBlockOnOff
#
# LICENSE...: https://github.com/Semperis/BadSuccessorBlockOnOff?tab=MIT-1-ov-file
#
# DISCLAIMER: https://github.com/Semperis/BadSuccessorBlockOnOff?tab=readme-ov-file#disclaimer
#
# WARNING: This Code Can ONLY Be Used When The W2K25 AD Schema Has Been Implemented! There IS NO Check To Validate This!
# WARNING: Membership of Schema Admins Is Required
# WARNING: The Actual Schema Master MUST Be Online And It Must Be Recognized As The Schema Master By Other RWDCs (i.e., "Initial synchronization" Must Have Taken Place And NO Recent Events With ID 2092 Exist About The FSMO Role: CN=Schema,CN=Configuration,DC=<FOREST>,DC=<TLD>)
# WARNING: AD Replication MUST BE In A Healthy State
#

Invoke-Command -ScriptBlock {
	Clear-Host
	$systemOnly = $false
	$thisADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
	$rootDSE = [ADSI]"LDAP://$($thisADForest.SchemaRoleOwner.Name)/RootDSE"
	$rootDSE.Put("schemaUpgradeInProgress", 1)
	$rootDSE.SetInfo()
	$msDSManagedAccountPrecededByLinkDN = "CN=ms-DS-Managed-Account-Preceded-By-Link,$($thisADForest.Schema.Name)"
	Write-Host "Reconfiguring '$msDSManagedAccountPrecededByLinkDN'" -ForegroundColor Magenta
	Write-Host " > Setting 'systemOnly' To '$($systemOnly.ToString().ToUpper())'" -ForegroundColor Yellow
	Write-Host ""
	$msDSManagedAccountPrecededByLink = [ADSI]"LDAP://$($thisADForest.SchemaRoleOwner.Name)/$msDSManagedAccountPrecededByLinkDN"
	$msDSManagedAccountPrecededByLink.Put("systemOnly", $($systemOnly.ToString().ToUpper()))
	$msDSManagedAccountPrecededByLink.SetInfo()
	$rootDSE = [ADSI]"LDAP://$($thisADForest.SchemaRoleOwner.Name)/RootDSE"
	$rootDSE.Put("schemaUpgradeInProgress", 0)
	$rootDSE.SetInfo()
	Write-Host "Reviewing Configuration Of '$msDSManagedAccountPrecededByLinkDN'" -ForegroundColor Magenta
	$msDSManagedAccountPrecededByLink = [ADSI]"LDAP://$($thisADForest.SchemaRoleOwner.Name)/$msDSManagedAccountPrecededByLinkDN"
	Write-Host " > 'systemOnly'........: $($msDSManagedAccountPrecededByLink.systemOnly)" -ForegroundColor Yellow
	Write-Host ""
}