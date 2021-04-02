Function Post($method, $params)
{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

	$uri = "https://$global:FortiManager/jsonrpc"
	$body = @{
		method = $method
		params = $params
		id = $id++
		session = $session
	}
    $response = Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Body (ConvertTo-Json -Compress -Depth 100 $body) -ErrorVariable script:lastError -ErrorAction SilentlyContinue -SkipCertificateCheck
    return $response
}
#
Function Login
{
	<#
	.DESCRIPTION
		Login
	.EXAMPLE
		Login -FortiManager x.x.x.x
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$False)][string]$FortiManager,
		[Parameter(Mandatory=$False)][string]$adom
	)

	# Set FMG IP Address from Parameter
	IF ($FortiManager){$global:FortiManager = $FortiManager}
	# Set FMG IP Address if global variable is empty.
	IF (!($global:FortiManager)){$global:FortiManager = Read-Host "Enter FMG IP Address"}

	# Validated in manifest file.
	Import-Module CredentialManager

	# New-StoredCredential -Target Ansible -UserName Dummy -Password "?" -Comment "FortiManager API User" -Type Generic -Persist Enterprise
	$Auth = Get-StoredCredential -Target Ansible -AsCredentialObject

	$response = post "exec" @( @{
		url = "/sys/login/user"
		data = @{
			user = $Auth.UserName
			passwd = $Auth.Password
		}
	})
    $script:session = $response.session
	return $response
}
#
Function Logout
{
	<#
	.DESCRIPTION
		Logut
	.EXAMPLE
		Logut
	#>

	IF (!($global:FortiManager))
		{$global:FortiManager = Read-Host "Enter FMG IP Address"}

	$response = post "exec" @( @{
		url = "/sys/logout"
	})

	IF ($Token) {Clear-Variable Token}
	$script:session = $null

	return $response
}
#
Function GetDevice
{
	<#
	.DESCRIPTION
		Get device.
	.EXAMPLE
		$Result = GetDevive -adom "root" -device "Dummy"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$device
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "get" @( @{
		url = "/dvmdb/adom/$adom/device/$device"
		#fields = @( "name", "ip", "conn_status" )
		loadsub = 0
    })
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function GetAllDevices
{
	<#
	.DESCRIPTION
		Get all devices.
	.EXAMPLE
		$Result = GetAllDevices -adom "root" -device "Dummy"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "get" @( @{
		url = "/dvmdb/adom/$adom/device"
		fields = @( "name", "ip", "conn_status" )
		loadsub = 0
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function GetScriptLogDevice
{
	<#
	.DESCRIPTION
		Get script execution log.
	.EXAMPLE
		$Result = GetScriptLogDevice -adom "root" -device "Dummy"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$device
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "get" @( @{
		url = "/dvmdb/adom/$adom/script/log/list/device/$device"
		fields = @( "content", "exec_time", "log_id" )
		loadsub = 0
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function ExeScript
{
	<#
	.DESCRIPTION
		Run CLI Script.
	.EXAMPLE
		$Result = ExeScript -adom "root" -device "Dummy" -script "IPSec Reset"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$script,
		[Parameter(Mandatory=$True)][string]$device
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "exec" @( @{
		url = "/dvmdb/adom/$adom/script/execute"
		data = @{
            adom = $adom
            # package = $package
            scope = @{
                        name = $device
                        vdom = $adom
                     }
            script = $script
		}
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function GetPolicyScope
{
	<#
	.DESCRIPTION
		Get policy scope member.
	.EXAMPLE
		$Response = GetPolicyScope -adom "root" -path "Office/Branch [Default]"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$Path
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "get" @( @{
		url = "/pm/pkg/adom/$adom/$Path"
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function SetPolicyScope
{
	<#
	.DESCRIPTION
		Update policy scope member.
	.EXAMPLE
		$Response = UpdatePolicyScope -adom "root" -device "Dummy" -Path "Office/Branch [Default]"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(Mandatory=$True)][string]$Path
	)

	$InitData = @( @{
		url = "/pm/pkg/adom/$adom/$Path"
		data = @{
			"scope member" = @{
				}
			}
	})

	# Get policy scope members.
	$Request = GetPolicyScope -adom $adom -Path $Path
	$Scope = $Request.result.data.'scope member'
	IF ($Scope)
		{
			$Member = [PSCustomObject]@{
				name = $device
				vdom = $adom
			}
			$Scope += $Member
			$InitData.data."scope member" = $Scope
		}

	ELSE {
		$InitData.data."scope member" = @{
			"name" = $device
			"vdom" = $adom
		}}

	$Token = Login
	IF (!$Token) {Break}

	$response = post "set" $InitData

	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function InstallPolicy
{
	<#
	.DESCRIPTION
		Install policy.
	.EXAMPLE
		$Response = InstallPolicy -adom "root" -device "Dummy" -package "Office"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(Mandatory=$True)][string]$package
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "exec" @( @{
		url = "/securityconsole/install/package"
		data = @{
			adom = $adom
			pkg = $package
		}
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function AddDeviceToGroup
{
	<#
	.DESCRIPTION
		Add device to group.
	.EXAMPLE
		$Result = AddDeviceToGroup -adom "root" -group "LAB" -device "Dummy"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$group,
		[Parameter(Mandatory=$True)][string]$device
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "add" @( @{
		url = "/dvmdb/adom/$adom/group/$group/object member"
		data = @{
            name = $device
            vdom = $adom
		}
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function RemoveDeviceFromGroup
{
	<#
	.DESCRIPTION
		Remove device from group.
	.EXAMPLE
		$Result = RemoveDeviceFromGroup -adom "root" -group "LAB" -device "Dummy"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$group,
		[Parameter(Mandatory=$True)][string]$device
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "delete" @( @{
		url = "/dvmdb/adom/$adom/group/$group/object member"
		data = @{
            name = $device
            vdom = $adom
		}
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function GetGroup
{
	<#
	.DESCRIPTION
		Get group members.
	.EXAMPLE
		$Result = GetGroup -adom "root" -group "LAB"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$group
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "get" @( @{
		url = "/dvmdb/adom/$adom/group/$group"
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function GetProvisioning
{
	<#
	.DESCRIPTION
		Get provisioning template.
	.EXAMPLE
		$Result = GetProvisioning -adom "root" -provisioning_template "Main"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$provisioning_template
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "get" @( @{
		url = "/pm/devprof/adom/$adom/$provisioning_template"
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function SetProvisioning
{
	<#
	.DESCRIPTION
		Set provisioning template.
	.EXAMPLE
		$Result = SetProvisioning -adom "root" -provisioning_template "Main"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(Mandatory=$True)][string]$provisioning_template
	)

	$InitData = @( @{
		url = "/pm/devprof/adom/$adom/$provisioning_template"
		data = @{
			"type" = "devprof"
            "scope member" = @{
            }
        }
	})

	# Get provisioning template scope members.
	$Request = GetProvisioning -adom $adom -provisioning_template $provisioning_template
	$Scope = $Request.result.data.'scope member'
	IF ($Scope)
		{
			$Member = [PSCustomObject]@{
				name = $device
			}
			$Scope += $Member
			$InitData.data."scope member" = $Scope
		}

	ELSE {
		$InitData.data."scope member" = @{
			"name" = $device
		}}

	$Token = Login
	IF (!$Token) {Break}

	$response = post "set" $InitData

	# Clear session.
	Logout | Out-Null

	return $response
}
#
