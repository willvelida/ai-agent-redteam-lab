metadata name = 'Lab budget'
metadata description = 'Subscription-scope cost budget with email alerts. Deployed by the human-run bootstrap, never by the pipeline.'

targetScope = 'subscription'

@description('Budget name.')
param budgetName string = 'budget-ailab3'

@description('Monthly budget in the subscription billing currency.')
@minValue(1)
param amount int

@description('Email address for budget alerts. Passed at deploy time; never committed.')
param alertEmail string

@description('Actual-spend thresholds, as a percentage of the budget.')
param actualThresholds int[] = [50, 80, 100]

@description('Forecasted-spend thresholds, as a percentage of the budget. Kept to 100% to avoid noisy early alerts.')
param forecastThresholds int[] = [100]

@description('Budget start date. Must be the first day of a month.')
param startDate string = utcNow('yyyy-MM-01')

var actualNotifications = toObject(
  actualThresholds,
  t => 'actual_${t}',
  t => {
    enabled: true
    operator: 'GreaterThanOrEqualTo'
    threshold: t
    thresholdType: 'Actual'
    contactEmails: [alertEmail]
  }
)

var forecastNotifications = toObject(
  forecastThresholds,
  f => 'forecast_${f}',
  f => {
    enabled: true
    operator: 'GreaterThanOrEqualTo'
    threshold: f
    thresholdType: 'Forecasted'
    contactEmails: [alertEmail]
  }
)

var notifications = union(actualNotifications, forecastNotifications)

// Whole subscription, no filter: the spending limit applies to the whole subscription, so the warning should too.
resource budget 'Microsoft.Consumption/budgets@2026-06-01' = {
  name: budgetName
  properties: {
    category: 'Cost'
    amount: amount
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: startDate
    }
    notifications: notifications
  }
}

@description('Budget resource ID.')
output budgetId string = budget.id
