"""
This module contains node objects
"""

from random import *
from math import *

class node(object):
    """
    Create basic node object.
    """
    def __init__(self, name):
        self.name = name
        #Set connections        
        self.con = []
        #Store lower layer info     
        self.child = None
        #Store a list of parent nodes
        self.parent = None
        #Set default value of start/end
        self.isStart = False
        self.isEnd = False
        self.subnet = []
        self.vul = None

    #Set the node as normal/start/end
    def setStart(self):
        self.isStart = True
    def setNormal(self):
        self.isStart = False
        self.isEnd = False
    def setEnd(self):        
        self.isEnd = True
    #Check whether the node is leaf or not
    def isLeaf(self):
        return (len(self.con) is 1)
    
class iot(node):
    """
    Create IoT device object. 
    """
    def __init__(self, name):
        super(iot, self).__init__(name)
        self.type = None
        
    def checkNodeInCons(self, node1, node2):
        """
        Check whether the node1 is in the connections of node2.
        """
        for temp in node2.con:
            if node1.name == temp.name:
                return 1
        
        return 0
    
    def checkNodeInList(self, list):
        """
        Check whether the node is in the list or not.
        """
        for temp in list:
            if self.name == temp.name:
                return True 
            
        return False


class computer(node):
    """
    Create computer object.
    Could be used for the attacker node.
    """
    def __init__(self, name):
        super(computer, self).__init__(name)
        self.type = None
            
    