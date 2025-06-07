@description('Name of the Sentinel rule.')
param ruleName string = 'Suspicious-PowerShell-Execution'

@description('Name of the Log Analytics workspace where Microsoft Sentinel is enabled.')
param workspaceName string

@description('Location of the Sentinel workspace.')
param location string = resourceGroup().location

resource sentinelWorkspace 'Microsoft.OperationalInsights/workspaces@2021-06-01' existing = {
  name: workspaceName
}

resource sentinelRule 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2022-12-01-preview' = {
  name: '${sentinelWorkspace.name}/Microsoft.SecurityInsights/${ruleName}'
  location: location
  properties: {
    displayName: 'Suspicious PowerShell Execution'
    description: 'Detects PowerShell scripts that may be related to exploitation tools like Mimikatz.'
    severity: 'Low'
    enabled: true
    query: '''
      SecurityEvent
      | where EventID == 4104
      | where ScriptBlockText has_any("Invoke-Mimikatz", "IEX", "DownloadString", "New-Object Net.WebClient")
    '''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT10M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: [
      'Execution'
    ]
    alertRuleTemplateName: ''
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
          'Host'
        ]
      }
    }
    customDetails: {
      Category: 'SuspiciousPowerShell'
      MITRE: 'T1059.001'
    }
    templateVersion: '1.0.0'
  }
}