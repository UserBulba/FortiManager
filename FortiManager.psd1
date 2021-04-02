@{
    Author               = 'Piotr'
    CompanyName          = ''
    Copyright            = '(c) 2011 - 2021 Piotr. All rights reserved.'
    Description          = 'Helper module for FortiManager'
    FunctionsToExport    = @()
    CmdletsToExport      = @()
    AliasesToExport      = @()
    GUID                 = '8aca843c-6960-41ef-8d32-bab05a62c285'
    ModuleVersion        = '0.0.10'
    PowerShellVersion    = '7.0'
    PrivateData          = @{
        PSData = @{
            Tags       = 'Windows', 'FortiManager'
            ProjectUri = 'https://github.com/UserBulba/FortiManager'
        }
    }
    RequiredModules      = @{
        ModuleVersion = '2.0'
        ModuleName    = 'CredentialManager'
        GUID          = '7db8ecb9-3b2a-437f-a26c-c3983ec8a845'
    }
    RootModule        = 'FortiManager.psm1'
}