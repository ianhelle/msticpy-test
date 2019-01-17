# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
"""default queries module ."""
from . query_defns import KqlQuery, DataFamily, DataEnvironment

# Module level variable that holds dictionary of queries
# indexed by name
# pylint: disable=C0103
query_definitions = dict()
# pylint: enable=C0103


KNOWN_PARAM_NAMES = ['table', 'query_project', 'start', 'end',
                     'provider_alert_id', 'subscription_filter',
                     'host_filter_eq', 'host_filter_neq',
                     'account_name', 'process_name', 'process_id',
                     'logon_session_id', 'path_separator', 'commandline']


def _add_query(kql_query):
    query_definitions[kql_query.name] = kql_query

# ------------------------------------------------------------------------
# Do Not edit above this line
# ------------------------------------------------------------------------


# Predefined queries
_add_query(KqlQuery(name='list_alerts_counts',
                    query='''
{table}
{query_project}
| where TimeGenerated >= datetime({start})
| where TimeGenerated <= datetime({end})
| summarize alertCount=count(), firstAlert=min(TimeGenerated),
    lastAlert=max(TimeGenerated) by AlertName
| order by alertCount desc
''',
                    description='Retrieves summary of current alerts',
                    data_source='security_alert',
                    data_families=[DataFamily.SecurityAlert],
                    data_environments=[DataEnvironment.LogAnalytics]))

_add_query(KqlQuery(name='list_alerts',
                    query='''
{table}
{query_project}
| where TimeGenerated >= datetime({start})
| where TimeGenerated <= datetime({end})
| extend extendedProps = parse_json(ExtendedProperties)
| extend CompromisedEntity = tostring(extendedProps['Compromised Host'])
| project-away extendedProps
''',
                    description='Retrieves list of current alerts',
                    data_source='security_alert',
                    data_families=[DataFamily.SecurityAlert],
                    data_environments=[DataEnvironment.LogAnalytics]))

_add_query(KqlQuery(name='get_alert',
                    query='''
{table}
{query_project}
| where TimeGenerated >= datetime({start})
| where TimeGenerated <= datetime({end})
| extend extendedProps = parse_json(ExtendedProperties)
| extend CompromisedEntity = tostring(extendedProps['Compromised Host'])
| project-away extendedProps
| where ProviderAlertId == \'{provider_alert_id}\'
''',
                    description='Retrieves an alert by alert Id',
                    data_source='security_alert',
                    data_families=[DataFamily.SecurityAlert],
                    data_environments=[DataEnvironment.LogAnalytics]))

_add_query(KqlQuery(name='list_related_alerts',
                    query='''
{table}
{query_project}
| where {subscription_filter}
| where TimeGenerated >= datetime({start})
| where TimeGenerated <= datetime({end})
| extend extendedProps=parse_json(ExtendedProperties)
| extend CompromisedEntity = tostring(extendedProps['Compromised Host'])
| extend host = extract("\\"HostName\\": \\"([^\\"]+)\\",", 1, Entities)
| extend dom = extract("\\"DnsDomain\\": \\"([^\\"]+)\\",", 1, Entities)
| extend Computer = iif(isempty(dom), host, strcat(host, ".", dom))
| extend accountName = tostring(extendedProps["User Name"])
| extend processName = tostring(extendedProps["Suspicious Process"])
| extend CompromisedEntity = iif(isempty(CompromisedEntity), Computer, CompromisedEntity)
| where {host_filter_eq} or accountName =~ \'{account_name}\' or processName =~ \'{process_name}\'
| extend host_match = ({host_filter_eq})
| extend acct_match = (accountName =~ \'{account_name}\')
| extend proc_match = (processName =~ \'{process_name}\')
                   ''',
                    description='Retrieves list of alerts with a common host, acount or process',
                    data_source='security_alert',
                    data_families=[DataFamily.SecurityAlert],
                    data_environments=[DataEnvironment.LogAnalytics],
                    optional_params=['process_name', 'account_name']))

_add_query(KqlQuery(name='get_process_tree',
                    query='''
let start = datetime({start});
let end = datetime({end});
let sourceProcessId = \'{process_id}\';
let sourceLogonId = \'{logon_session_id}\';
let sourceProcess =
materialize(
    {table}
    {query_project}
    | where {subscription_filter}
    | where {host_filter_eq}
    | where TimeGenerated >= start
    | where TimeGenerated <= end
    | where SubjectLogonId == sourceLogonId
    | where NewProcessId == sourceProcessId
    | where NewProcessName =~ \'{process_name}\'
    | extend NodeRole = 'source', Level = 0
    | top 1 by TimeCreatedUtc desc nulls last);
let sourceTimeCreatedUtc = toscalar(sourceProcess | project TimeCreatedUtc);
let sourceParentProcessId = toscalar(sourceProcess | project ProcessId);
let system_session_id = toscalar(sourceProcess
    | extend sys_session = iff(NewProcessName contains '/', '-1', '0x3e7')
    | project sys_session );
let parentProcess = // Parent Process
materialize(
    {table}
    {query_project}
    | where {subscription_filter}
    | where {host_filter_eq}
    | where TimeGenerated >= start - time(1d)
    | where TimeGenerated <= end
    | where TimeGenerated <= sourceTimeCreatedUtc
    | where (SubjectLogonId == sourceLogonId or TargetLogonId == sourceLogonId)
    | where NewProcessId == sourceParentProcessId
    | extend NodeRole = 'parent', Level = 1
    | top 1 by TimeCreatedUtc desc nulls last);
let parentLogonId = toscalar(sourceProcess | project SubjectLogonId);
let parentTimeCreated = toscalar(sourceProcess | project TimeCreatedUtc);
let childProcesses = // Child Process
materialize(
    {table}
    {query_project}
    | where {subscription_filter}
    | where {host_filter_eq}
    | where TimeGenerated >= start
    | where TimeGenerated <= end
    | where SubjectLogonId == sourceLogonId
    | where ProcessId == sourceProcessId
    | extend NodeRole = 'child', Level = 1);

sourceProcess
| union (parentProcess)
| union (childProcesses)
| union
(
    // GrandParent Process (we ignore this if this is the system logonId)
    {table}
    {query_project}
    | where {subscription_filter}
    | where {host_filter_eq}
    | where TimeGenerated >= start - time(1d)
    | where TimeGenerated <= end
    | where TimeGenerated <= parentTimeCreated
    | where (SubjectLogonId == parentLogonId or TargetLogonId == parentLogonId)
    | extend NodeRole = 'parent', Level = 2
    | join (parentProcess | project ProcessId) on $left.NewProcessId == $right.ProcessId
)
| union
(
    // GrandChild Process (we ignore this if this is the system logonId)
    {table}
    {query_project}
    | where {subscription_filter}
    | where {host_filter_eq}
    | where TimeGenerated >= start
    | where TimeGenerated <= end
    | where SubjectLogonId == sourceLogonId and SubjectLogonId != system_session_id
    | extend NodeRole = 'child', Level = 2
    | join (childProcesses | project NewProcessId) on $left.ProcessId == $right.NewProcessId
)
| union
(
    // Sibling Process
    {table}
    {query_project}
    | where {subscription_filter}
    | where {host_filter_eq}
    | where TimeGenerated >= start
    | where TimeGenerated <= end
    | where SubjectLogonId == sourceLogonId
    | where ProcessId == sourceParentProcessId
    | where NewProcessId != sourceProcessId
    | extend NodeRole = 'sibling', Level = 1
)
''',
                    description='Retrieves process tree for a process.',
                    data_source='process_create',
                    data_families=[DataFamily.WindowsSecurity,
                                   DataFamily.LinuxSecurity],
                    data_environments=[DataEnvironment.LogAnalytics]))

_add_query(KqlQuery(name='list_processes',
                    query='''
let start = datetime({start});
let end = datetime({end});
{table}
{query_project}
| where {subscription_filter}
| where {host_filter_eq}
| where TimeGenerated >= start
| where TimeGenerated <= end
''',
                    description='Retrieves processes for a host.',
                    data_source='process_create',
                    data_families=[DataFamily.WindowsSecurity,
                                   DataFamily.LinuxSecurity],
                    data_environments=[DataEnvironment.LogAnalytics]))

_add_query(KqlQuery(name='get_process_parent',
                    query='''
let start = datetime({start});
let end = datetime({end});
let sourceProcessId = \'{process_id}\';
let sourceLogonId = \'{logon_session_id}\';
let sourceProcess =
materialize(
    {table}
    {query_project}
    | where {subscription_filter}
    | where {host_filter_eq}
    | where TimeGenerated >= start
    | where TimeGenerated <= end
    | where SubjectLogonId == sourceLogonId
    | where NewProcessId == sourceProcessId
    | where NewProcessName =~ \'{process_name}\'
    | extend NodeRole = 'source', Level = 0
    | top 1 by TimeCreatedUtc desc nulls last);
let sourceTimeCreatedUtc = toscalar(sourceProcess | project TimeCreatedUtc );
let sourceParentProcessId = toscalar(sourceProcess | project ProcessId);
// Parent Process
{table}
{query_project}
| where {subscription_filter}
| where {host_filter_eq}
| where TimeGenerated >= start - time(2h)
| where TimeGenerated <= end
| where TimeGenerated <= sourceTimeCreatedUtc
| where (SubjectLogonId == sourceLogonId or TargetLogonId == sourceLogonId)
| where NewProcessId == sourceParentProcessId
| where NewProcessId == sourceParentProcessId
| extend NodeRole = 'parent', Level = 1
| top 1 by TimeCreatedUtc desc nulls last);
''',
                    description='Retrieves the parent process of a process process',
                    data_source='process_create',
                    data_families=[DataFamily.WindowsSecurity,
                                   DataFamily.LinuxSecurity],
                    data_environments=[DataEnvironment.LogAnalytics]))

_add_query(KqlQuery(name='list_hosts_matching_commandline',
                    query='''
{table}
{query_project}
| where {subscription_filter}
| where {host_filter_neq}
| where TimeCreatedUtc >= datetime({start})
| where TimeCreatedUtc <= datetime({end})
| where NewProcessName endswith \'{process_name}\'
| where CommandLine =~ \'{commandline}\'
''',
                    description='Retrieves processes on other hosts with matching commandline',
                    data_source='process_create',
                    data_families=[DataFamily.WindowsSecurity,
                                   DataFamily.LinuxSecurity],
                    data_environments=[DataEnvironment.LogAnalytics]))

_add_query(KqlQuery(name='list_processes_in_session',
                    query='''
{table}
{query_project}
| where {subscription_filter}
| where {host_filter_eq}
| where TimeCreatedUtc >= datetime({start})
| where TimeCreatedUtc <= datetime({end})
| where SubjectLogonId == \'{logon_session_id}\'
| extend processName = tostring(split(NewProcessName, \'{path_separator}\')[-1])
| extend commandlineparts = arraylength(split(CommandLine, ' '))
| extend commandlinelen = strlen(CommandLine)
''',
                    description='Retrieves all processes on the host for a logon session',
                    data_source='process_create',
                    data_families=[DataFamily.WindowsSecurity,
                                   DataFamily.LinuxSecurity],
                    data_environments=[DataEnvironment.LogAnalytics]))

_add_query(KqlQuery(name='get_logon_session',
                    query='''
{table}
{query_project}
| where {subscription_filter}
| where {host_filter_eq}
| where TimeCreatedUtc >= datetime({start}) - time(1d)
| where TimeCreatedUtc <= datetime({end})
| where TargetLogonId == \'{logon_session_id}\'
''',
                    description='Retrieves the logon event for the session id on the host.',
                    data_source='account_logon',
                    data_families=[DataFamily.WindowsSecurity,
                                   DataFamily.LinuxSecurity],
                    data_environments=[DataEnvironment.LogAnalytics]))