# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

__version__ = '0.1'
__author__ = 'Ian Hellen'

import IPython.display
from bs4 import BeautifulSoup

_CSS = '''
body {
    margin:50px;
    font-family:'Arial', sans-serif;
}
*{margin:0;padding: 0;}

h1 {
    color:#FA9A39;
}

p { padding-bottom:50px;}

.content {
    width:500px;
    margin:auto;
}
.tree ul {
    margin-left: 20px;
}

.tree li {
    list-style-type: none;
    margin:10px;
    position: relative;
}

.tree li::before {
    content: "";
    position: absolute;
    top:-7px;
    left:-20px;
    border-left: 1px solid #ccc;
    border-bottom:1px solid #ccc;
    border-radius:0 0 0 0px;
    width:20px;
    height:15px;
}

.tree li::after {
    position:absolute;
    content:"";
    top:8px;
    left:-20px;
    border-left: 1px solid #ccc;
    border-top:1px solid #ccc;
    border-radius:0px 0 0 0;
    width:20px;
    height:100%;
}

.tree li:last-child::after  {
    display:none;
}

.tree li:last-child:before{
    border-radius: 0 0 0 5px;
}

ul.tree>li:first-child::before {
    display:none;
}

ul.tree>li:first-child::after {
    border-radius:5px 0 0 0;
}

.tree li a {
    border: 1px #ccc solid;
    border-radius: 5px;
    padding:2px 5px;
}

.tree li a:hover, .tree li a:hover+ul li a,
.tree li a:focus, .tree li a:focus+ul li a {
    background: #ccc; color: #000; border: 1px solid #000;
}

.tree li a:hover+ul li::after, .tree li a:focus+ul li::after,
.tree li a:hover+ul li::before, .tree li a:focus+ul li::before 
.tree li a:hover+ul::before, .tree li a:focus+ul::before 
.tree li a:hover+ul ul::before, .tree li a:focus+ul ul::before{
    border-color:  #000; /*connector color on hover*/
}
'''

_HTML_DOC = '''
<head>
    <title>Pure CSS Tree</title>
    <style/>    
</head>
<body>
    <div class="content">
        <ul class="tree">
        </ul>
    </div>
</body>'''

class TreeNode:

    def __init__(self, name, **kwargs):
        self._name = name
        self._attributes = kwargs
        self.children = []
        self.parent = None

    def add_child(self, node):
        node.parent = self
        self.children.append(node)

    def add_children(self, nodes):
        for n in nodes:
            n.parent = self
            self.add_child(node=n)

    @property
    def html(self):
        node_html = '<li>' + self._name
        if self.has_children:
            node_html = node_html + '<ul>' + '\n'.join([n.html for n in self.children]) + '</ul>\n'
        node_html + '</li>\n'
        return node_html

    @property
    def has_children(self):
        return len(self.children) > 0

        

# class ProcessTreeView:

#     def __init__(self, root_node):
#         html_doc = BeautifulSoup(_HTML_DOC, 'html.parser')
#         html_doc.head.style

#         self.html = html_doc

#     def html(self):
        


if __name__ == '__main__':
    attribs = {'attr1' : 'time', 'attr2' : 'hash'}
    root = TreeNode('rootnode', **attribs)
    for i in range(1, 20):
        child1_node = TreeNode('node' + str(i), **attribs)
        root.add_child(child1_node)
        if i % 3:
            child2_node = TreeNode('node' + str(i) + '-1', **attribs)
            child1_node.add_child(child2_node)
            for j in range(1,6):
                if j % 2:
                    gchild_node = TreeNode('node' + str(i) + '-' + str(j) + '-1', **attribs)
                    child2_node.add_child(gchild_node)

    # view = ProcessTreeView(root)

    # html_txt = root.html
