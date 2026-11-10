using '../main.bicep'

param environmentName = 'hardened'
// Every Vuln:Ax flag stays off in this file. Changing this invalidates the before/after ASR comparison.
param isVulnMode = false
param shouldDeployGateway = false
