# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
"""Module for common display functions."""

import datetime
import textwrap

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
from bokeh.io import output_notebook, show
from bokeh.layouts import Spacer, column, layout, row
from bokeh.models import (BoxAnnotation, ColumnDataSource, DateRangeSlider,
                          DatetimeTickFormatter, HoverTool, Label, LabelSet)
from bokeh.plotting import figure, output_notebook, reset_output, show
from IPython.core.display import HTML, display
from IPython.display import Javascript

from .security_alert import SecurityAlert
from .utility import export

__version__ = '0.1'
__author__ = 'Ian Hellen'


@export
def display_alert(alert=None, show_entities=False):
    """
    Display the alert properties as HTML.

        :param alert: The alert to display
            pd.Series or SecurityAlert
    """
    if alert is None:
        return

    if isinstance(alert, SecurityAlert):
        display(HTML(alert.to_html(show_entities=False)))
        if show_entities:
            for entity in alert.entities:
                print(entity)
        return

    # Display subset of raw properties
    if isinstance(alert, pd.Series):
        entity = (alert['CompromisedEntity']
                  if 'CompromisedEntity' in alert
                  else '')
        title = '''
            <h3>Alert: '{name}'</h3><br>time=<b>{start}</b>, entity=<b>{entity}</b>, id=<b>{id}</b>
            '''.format(start=alert['StartTimeUtc'],
                       name=alert['AlertDisplayName'],
                       entity=entity,
                       id=alert['ProviderAlertId'])
        display(HTML(title))
        display(pd.DataFrame(alert))
    else:
        raise ValueError(
            'Unrecognized alert object type ' + str(type(alert)))


def _print_process(process_row: pd.Series):
    if process_row.NodeRole == 'parent':
        if process_row.Level > 1:
            level = 0
        else:
            level = 1
    elif process_row.NodeRole == 'source':
        level = 2
    elif process_row.NodeRole == 'child':
        level = 3 + process_row.Level
    else:
        level = 2

    spaces = 20 * level * 2
    if process_row.NodeRole == 'source':
        line1 = '<b>[alert:{}] {} {}</b> [PID: {}, SubSess:{}, TargSess:{}]'.format(
            process_row.Level,
            process_row.TimeCreatedUtc,
            process_row.NewProcessName,
            process_row.NewProcessId,
            process_row.SubjectLogonId,
            process_row.TargetLogonId)
    else:
        line1 = '[{}:{}] {} <b>{}</b> [PID: {}, SubSess:{}, TargSess:{}]'.format(
            process_row.NodeRole,
            process_row.Level,
            process_row.TimeCreatedUtc,
            process_row.NewProcessName,
            process_row.NewProcessId,
            process_row.SubjectLogonId,
            process_row.TargetLogonId)

    line2 = '(Cmdline: \'{}\') [Account: \'{}\']'.format(
        process_row.CommandLine, process_row.SubjectUserName)

    display(HTML('<p style="margin-left: {indent}px">{txt}<br>{txt2}</p>'.format(indent=spaces,
                                                                                 txt=line1,
                                                                                 txt2=line2)))


@export
def display_process_tree(process_tree: pd.DataFrame):
    """
    Display process tree data frame.

        :param process_tree
    """
    tree = process_tree[['TimeCreatedUtc', 'NodeRole', 'Level', 'NewProcessName',
                         'CommandLine', 'SubjectUserName', 'NewProcessId', 'ProcessId']]
    tree = tree.sort_values(by=['TimeCreatedUtc'], ascending=False)

    display(HTML("<h3>Alert process tree:</h3>"))
    tree.sort_values(by=['TimeCreatedUtc']).apply(_print_process, 1)


def exec_remaining_cells():
    """Execute all cells below currently selected cell."""
    Javascript("Jupyter.notebook.execute_cells_below()")


@export
def draw_alert_entity_graph(nx_graph: nx.Graph, font_size: int = 12,
                            height: int = 15, width: int = 20,
                            margin: float = 0.3, scale: int = 1):
    """
    "Draw networkX graph with matplotlib.

    Arguments:
        nx_graph {networkx.graph} -- [description]

    Keyword Arguments:
        font_size {int} -- base font size (default: {12})
        height {int} -- Image height (default: {15})
        width {int} -- Image width (default: {20})
        margin {float} -- Image margin (default: {0.3})
        scale {int} -- Position scale (default: {1})
    """
    alert_node = [n for (n, node_type) in
                  nx.get_node_attributes(nx_graph, 'node_type').items()
                  if node_type == 'alert']
    entity_nodes = [n for (n, node_type) in
                    nx.get_node_attributes(nx_graph, 'node_type').items()
                    if node_type == 'entity']

    # now draw them in subsets  using the `nodelist` arg
    plt.rcParams['figure.figsize'] = (width, height)

    plt.margins(x=margin, y=margin)

    pos = nx.kamada_kawai_layout(nx_graph, scale=scale, weight='weight')
    nx.draw_networkx_nodes(nx_graph, pos, nodelist=alert_node,
                           node_color='red', alpha=0.5, node_shape='o')
    nx.draw_networkx_nodes(nx_graph, pos, nodelist=entity_nodes,
                           node_color='green', alpha=0.5, node_shape='s',
                           s=200)
    nlabels = nx.get_node_attributes(nx_graph, 'description')
    nx.relabel_nodes(nx_graph, nlabels)
    nx.draw_networkx_labels(nx_graph, pos, nlabels, font_size=font_size)
    nx.draw_networkx_edges(nx_graph, pos)
    elabels = nx.get_edge_attributes(nx_graph, 'description')
    nx.draw_networkx_edge_labels(nx_graph, pos, edge_labels=elabels,
                                 font_size=font_size * 2 / 3, alpha=0.6)


@export
def display_timeline(data, alert=None, overlay_data=None,
                     time_column='TimeGenerated',
                     source_columns=None):
    """
    Display a timeline of events.

    Arguments:
        :param data: Input DataFrame
        :param alert=None: Input alert (optional)
        :param overlay_data=None: Second event stream (DataFrame)
            to display as overlay
        :param time_column='TimeGenerated': The name of the time
            property used in the Dataframe(s)
        :param source_columns=None: List of source columns to use in
            tooltips
    """
    reset_output()
    output_notebook()

    WRAP = 50
    WRAP_CMDL = 'WrapCmdl'
    y_max = 1

    if not source_columns:
        source_columns = ['NewProcessName', 'EventID', 'CommandLine']
    if time_column not in source_columns:
        source_columns.append(time_column)

    if 'CommandLine' in source_columns:
        graph_df = data[source_columns].copy()
        graph_df[WRAP_CMDL] = graph_df.apply(lambda x:
                                             _wrap_text(x.CommandLine, WRAP),
                                             axis=1)
    else:
        graph_df = data[source_columns].copy()

    # if we have an overlay - add this data and shift the y co-ordinates to
    # show on two separate lines
    if overlay_data is not None:
        overlay_colums = source_columns
        if time_column not in overlay_colums:
            overlay_colums.append(time_column)
        if 'CommandLine' in overlay_colums:
            overlay_df = overlay_data[overlay_colums].copy()
            overlay_df[WRAP_CMDL] = overlay_df.apply(lambda x:
                                                     _wrap_text(
                                                         x.CommandLine, WRAP),
                                                     axis=1)
        else:
            overlay_df = overlay_data[overlay_colums].copy()
        graph_df['y_index'] = 2
        overlay_df['y_index'] = 1
        y_max = 2
    else:
        graph_df['y_index'] = 1

    source = ColumnDataSource(graph_df)

    # build the tool tips from columns (excluding these)
    excl_cols = [time_column, 'CommandLine']
    tool_tip_items = [(f'{col}', f'@{col}')
                      for col in source_columns if col not in excl_cols]
    if WRAP_CMDL in graph_df:
        tool_tip_items.append(('CommandLine', f'@{WRAP_CMDL}'))
    hover = HoverTool(
        tooltips=tool_tip_items,
        formatters={'Tooltip': 'printf'}
        # display a tooltip whenever the cursor is vertically in line with a glyph
        # ,mode='vline'
    )

    # tools = 'pan, box_zoom, wheel_zoom, reset, undo, redo, save, hover'
    plot = figure(min_border_left=50, plot_height=300, plot_width=1000,
                  x_axis_label='Event Time', x_axis_type='datetime', x_minor_ticks=10,
                  tools=[hover, 'pan', 'xwheel_zoom', 'box_zoom', 'reset'],
                  title='Event Timeline (hover over item to see details)')
    plot.yaxis.visible = False

    # Tick formatting for different zoom levels
    # '%H:%M:%S.%3Nms
    tick_format = DatetimeTickFormatter()
    tick_format.days = ['%d %H:%M']
    tick_format.hours = ['%H:%M:%S']
    tick_format.minutes = ['%H:%M:%S']
    tick_format.seconds = ['%H:%M:%S']
    tick_format.milliseconds = ['%H:%M:%S.%3N']

    plot.xaxis[0].formatter = tick_format
    plot.circle(x=time_column, y='y_index', color='navy',
                alpha=0.5, size=10, source=source)

    if overlay_data is not None:
        overlay_source = ColumnDataSource(overlay_df)
        plot.circle(x=time_column, y='y_index', color='green',
                    alpha=0.5, size=10, source=overlay_source)

    # Adding data labels stops everything working!
    # labels = LabelSet(x=time_column, y='y_index', y_offset=5, 
    #                   text='NewProcessName', source=source,
    #                   angle='90deg', text_font_size='8pt')
    # p.add_layout(labels)

    # if we have an alert, plot the time as a line
    if alert is not None:
        x_alert_label = pd.Timestamp(alert['StartTimeUtc'])
        plot.line(x=[x_alert_label, x_alert_label], y=[0, y_max + 1])
        alert_label = Label(x=x_alert_label, y=0, y_offset=10, x_units='data', y_units='data',
                            text='< Alert time', render_mode='css',
                            border_line_color='red', border_line_alpha=1.0,
                            background_fill_color='white', background_fill_alpha=1.0)

        plot.add_layout(alert_label)

        print('Alert start time = ', alert['StartTimeUtc'])

    show(plot)


def _wrap_text(source_string, wrap_len):
    if len(source_string) <= wrap_len:
        return source_string
    out_string = ''
    input_parts = source_string.split()
    out_line = ''
    for part in input_parts:
        if len(part) > wrap_len:
            if len(out_line) > 0:
                out_string += out_line + '\n'
                out_line = ''
            out_line = part[0:wrap_len] + '...'
        else:
            if len(out_line) > 0:
                out_line += ' ' + part
            else:
                out_line = part
            if len(out_line) > wrap_len:
                out_string += out_line + '\n'
                out_line = ''

    return out_string
