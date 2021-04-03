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
		[Parameter(Mandatory=$False)][string]$adom,
		[Parameter(DontShow)]$HiddenParameter
	)

	# Set FMG IP Address from Parameter
	IF ($FortiManager){$global:FortiManager = $FortiManager}
	# Set FMG IP Address if global variable is empty.
	IF (!($global:FortiManager)){$global:FortiManager = Read-Host "Enter FMG IP Address"}

	# Validated in manifest file.
	Import-Module CredentialManager

	# New-StoredCredential -Target FMG -UserName Dummy -Password "?" -Comment "FortiManager API User" -Type Generic -Persist Enterprise
	$Auth = Get-StoredCredential -Target Dummy -AsCredentialObject

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

	[CmdletBinding()]
	Param (
		[Parameter(DontShow)]$HiddenParameter
	)

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
		$Result = GetDevice -adom "root" -device "Dummy"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(DontShow)]$HiddenParameter
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
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(DontShow)]$HiddenParameter
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
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(DontShow)]$HiddenParameter
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
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(DontShow)]$HiddenParameter
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
		[Parameter(Mandatory=$True)][string]$Path,
		[Parameter(DontShow)]$HiddenParameter
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
		[Parameter(Mandatory=$True)][string]$Path,
		[Parameter(DontShow)]$HiddenParameter
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
		[Parameter(Mandatory=$True)][string]$package,
		[Parameter(DontShow)]$HiddenParameter
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
Function InstallConfig
{
	<#
	.DESCRIPTION
		Install config.
	.EXAMPLE
		$Response = InstallConfig -adom "root" -device "Dummy"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(DontShow)]$HiddenParameter
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "exec" @( @{
		url = "/securityconsole/install/device"
		data = @{
			scope = @{
				name = $device
			}
			adom = $adom
			flags = "none"
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
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(DontShow)]$HiddenParameter
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
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(DontShow)]$HiddenParameter
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
		[Parameter(Mandatory=$True)][string]$group,
		[Parameter(DontShow)]$HiddenParameter
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
		[Parameter(Mandatory=$True)][string]$provisioning_template,
		[Parameter(DontShow)]$HiddenParameter
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
		[Parameter(Mandatory=$True)][string]$provisioning_template,
		[Parameter(DontShow)]$HiddenParameter
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
Function GetMetaFields
{
	<#
	.DESCRIPTION
		Get provisioning template.
	.EXAMPLE
		$Result = GetProvisioning -adom "root" -device "Dummy"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(DontShow)]$HiddenParameter
	)
	
	$Token = Login
	IF (!$Token) {Break}

	$response = post "get" @( @{
		url = "/dvmdb/adom/$adom/device/$device"
		option = "get meta"
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function UpdateHostname
{
	<#
	.DESCRIPTION
		Update hostname.
	.EXAMPLE
		$Result = UpdateHostname -device "Dummy" -hostname "New-Dummy"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(Mandatory=$True)][string]$hostname,
		[Parameter(DontShow)]$HiddenParameter
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "update" @( @{
		url = "pm/config/device/$device/global/system/global"
		data = @{
            hostname = $hostname
            }
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function SetName
{
	<#
	.DESCRIPTION
		Set name.
	.EXAMPLE
		$Result = SetName -adom "root" -device "Dummy" -hostname "New-Dummy"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(Mandatory=$True)][string]$hostname,
		[Parameter(DontShow)]$HiddenParameter
	)

	$Token = Login
	IF (!$Token) {Break}

	$response = post "update" @( @{
		url = "/dvmdb/adom/$adom/device/$device"
		data = @{
            name = $hostname
            }
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function UpdateDevicePassword
{
	<#
	.DESCRIPTION
		Update device password in FortiManager.
	.EXAMPLE
		$Result = UpdateDevicePassword -adom "root" -device "Dummy"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$True)][string]$device,
		[Parameter(DontShow)]$HiddenParameter
	)

	# Validated in manifest file.
	Import-Module CredentialManager

	# New-StoredCredential -Target FortiGate -UserName admin -Password "" -Comment "FortiGate Admin User" -Type Generic -Persist Enterprise
	$Auth = Get-StoredCredential -Target FortiGate -AsCredentialObject

	$Token = Login
	IF (!$Token) {Break}

	$response = post "update" @( @{
		url = "/dvmdb/adom/$adom/device/$device"
		data = @{
			'adm_usr' = $Auth.UserName
			'adm_pass' = $Auth.Password
            }
	})
	# Clear session.
	Logout | Out-Null

	return $response
}
#
Function CreateObject
{
	<#
	.DESCRIPTION
		Create firewall object.
	.EXAMPLE
		$Result = CreateObject -type ipmask -adom "root" -name "Dummy" -subnet 192.168.0.0/255.255.0.0 -color 31
	.EXAMPLE
		$Result = CreateObject -type group -adom "root" -name "Dummy" -color 31 -member "Dummy,Dummy2"
	#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True, Position=0)][ValidateSet("ipmask","group")][string]$type,
		[Parameter(Mandatory=$True, HelpMessage="Object name")][string]$object,
		[Parameter(Mandatory=$True)][string]$adom,
		[Parameter(Mandatory=$False)][int]$color,
		[Parameter(DontShow)]$HiddenParameter
	)
	DynamicParam {
        $paramDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        IF ($type -eq "group")
            {
				$attributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
                $attribute = New-Object System.Management.Automation.ParameterAttribute
                $attribute.Mandatory = $True
                $attributeCollection.Add($attribute)
                $Name = "member"
                $dynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($Name,[string], $attributeCollection)
                $paramDictionary.Add($Name, $dynParam)
			}
		IF ($type -eq "ipmask")
            {
                $attributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
                $attribute = New-Object System.Management.Automation.ParameterAttribute
                $attribute.Mandatory = $True
                $attributeCollection.Add($attribute)
                $Name = "subnet"
                $dynParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($Name,[string], $attributeCollection)
                $paramDictionary.Add($Name, $dynParam)
			}
		$paramDictionary
	}
	End {
		$Token = Login
		IF (!$Token) {Break}

		$InitData = @( @{
			url = "/pm/config/adom/$adom/obj/firewall/address"
			data = @{
				'name' = $object
				'comment' = ""
				'color' = $color
				'visibility' = 1
				'allow-routing' = 0
				'subnet' = $PSBoundParameters.subnet
			}
		})

		#Create group if choosen.
		IF ($Type -eq "group")
			{
				Clear-Variable InitData
				$List = New-Object Collections.Generic.List[String]
				#$VariableCut = $member.Replace(" ","")
				$List = $PSBoundParameters.member.Split(",")

				$InitData = @( @{
					url = "/pm/config/adom/$adom/obj/firewall/addrgrp"
					data = @{
						'name' = $object
						'comment' = ""
						'color' = $color
						'visibility' = 1
						'allow-routing' = 0
						'member' = $List
					}
				})
			}

		$response = post "set" $InitData
		# Clear session.
		Logout | Out-Null

		Return $response
	}
}
