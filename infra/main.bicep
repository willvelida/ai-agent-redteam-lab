metadata name = 'AI Agent Red-Team Lab'
metadata description = 'Orchestrates the Biotrackr Health Agent lab twin. Phase 0 deploys no resources; modules are added from Phase 1.'

targetScope = 'resourceGroup'

@description('Lab environment name. Must match the GitHub environment and resource group suffix.')
param environmentName 'vulnerable' | 'hardened'

@description('Azure region for lab resources.')
param location string = resourceGroup().location

@description('Turns on the deliberately vulnerable code paths and identities (A1-A12). Must be false in hardened.bicepparam.')
param isVulnMode bool

@description('Deploys APIM Basic v2 as the AI/MCP gateway. About US$150/month if left running, so deploy only for gateway sessions.')
param shouldDeployGateway bool = false

@description('Tags applied to every lab resource.')
var tags = {
  purpose: 'ai-redteam-lab'
  env: environmentName
  vulnMode: string(isVulnMode)
}

@description('Echoes the effective configuration so each deployment records which mode it ran in.')
output labConfig object = {
  environmentName: environmentName
  location: location
  isVulnMode: isVulnMode
  shouldDeployGateway: shouldDeployGateway
  tags: tags
}
