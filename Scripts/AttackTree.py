"""
This module constructs attack tree.
"""

from Node import *
from Network import *
from Vulnerability import *


class tNode(node):
    """
    Create attack tree node object.
    """
    def __init__(self, name):
        super(tNode, self).__init__(name)
        self.n = None
        self.t = "node"
        self.val = 0
    
    def __str__(self):
        return self.name

class tVulNode(vulNode):
    """
    Create attack tree vulnerability object.
    """
    def __init__(self, name):
        super(tVulNode, self).__init__(name)
        self.n = None
        self.t = "node"
        self.val = 0
        self.command = 0
        
    def __str__(self):
        return self.name
      
class andGate(node):
    def __init__(self):
        super(andGate, self).__init__("andGate")
        self.t = "andGate"

class orGate(node):
    def __init__(self):
        super(orGate, self).__init__("orGate")
        self.t = "orGate"

     
class at(object):
    """
    Create attack tree.
    """
    def __init__(self, network, val, *arg):
        self.nodes = []
        self.topGate = None
        self.construct(network, val, *arg)
        self.isAG = 0
    
    #Preprocess for the construction
    def preprocess(self, network, nodes, val, *arg):  
        for u in [network.s, network.e] + network.nodes:
            if u is not None:
                #For vulnerability
                if type(u) is vulNode:
                    tn = tVulNode('at_'+str(u.name))
                    tn.privilege = u.privilege  
                    tn.val = u.val
                    tn.vulname = u.name
                #For node
                else:
                    tn = tNode('at_'+str(u.name))
                    
                    #Assign default value to attacker node
                    if u.isStart == True:
                        tn.val = -1
                    else:
                        tn.val = val
                    
                tn.n = u
                
                #Assign default value to start and end in vulnerability network
                if u in [network.s, network.e]:
                    tn.val = 0
                    tn.command = 1
                    
                nodes.append(tn)   
        
        #Initialize connections for attack tree node                         
        for u in nodes:
            for v in u.n.con:
                #For upper layer
                if len(arg) is 0:
                    for t in nodes:
                        if t.n is v:
                            u.con.append(t)
                #For lower layer
                else:
                    # Privilege value is used here to decide what vulnerabilities an attacker can use for attack paths 
                    if v.privilege is not None and arg[0] >= v.privilege:
                        for t in nodes:
                            if t.n is v:
                                u.con.append(t)      
        return None
    
    #Construct the attack tree
    def construct(self, network, val, *arg):        
        nodes = []
        history = []
        self.topGate = orGate() 
        self.preprocess(network, nodes, val, *arg)

        #For one vulnerability
        if len(nodes) < 4:
            a_gate = andGate()
            for node in nodes:
                a_gate.con.append(node)
                
            self.topGate.con.append(a_gate)
        #For more than one vulnerability
        else:    
            for u in nodes:
                if u.n is network.e:
                    e = u
                if u.n is network.s:
                    self.topGate.con.append(u)  
            
            self.simplify(self.topGate, history, e)
            self.targetOut(self.topGate, e)
            self.foldgate(self.topGate)

    #Simplify the method
    def simplify(self, gate, history, target):
        tGate = []
        tGate.extend(gate.con)
        value = 1
        if len(tGate) == 0:
            value = 0
           
        for item in tGate:    
            if (item is not target) and (item.t is "node"):
                a_gate = andGate()                                
                gate.con.append(a_gate)
                gate.con.remove(item)                                                   
                                          
                a_gate.con.append(item)                
                o_gate = orGate()                                      
                a_gate.con.append(o_gate)            
                
                for u in item.con:
                    if u not in history:
                        o_gate.con.append(u)
                       
                history.append(item)
                value = self.simplify(o_gate, history, target)
                history.pop()
                if len(o_gate.con) < 1:
                    a_gate.con.remove(o_gate)
                    if len(a_gate.con) == 1 and value == 0:
                        gate.con.append(item)
                        gate.con.remove(a_gate)
                
                value = value * item.val
    
        return value
    
    def targetOut(self, rootGate, target):
        self.targetOutRecursive(rootGate, target)
        for gate in rootGate.con:
            gate.con.append(target)
        self.deleteEmptyGates(rootGate)        
        
    def deleteEmptyGates(self, gate):
        removedGates = []
        for node in gate.con:
            if node.t in ['andGate', 'orGate']:
                if (len(node.con) is 1) and (node.con[0] is "removed"):
                    removedGates.append(node)
                else:
                    self.deleteEmptyGates(node)
                                
        for node in removedGates:
            gate.con.remove(node)    
                
    def targetOutRecursive(self, gate, target):
        toChange = []
        for node in gate.con:
            if node is target:
                if len(gate.con) is 1:
                    del gate.con[:]
                    gate.con.append("removed")
                    break
                else:                    
                    toChange.append(node)                    
                    
            elif node.t in ['andGate', 'orGate']:
                self.targetOutRecursive(node, target)
        for node in toChange:
            gate.con.remove(node)
            nothing = tNode('at-.')
            nothing.val = 1            
            gate.con.append(nothing)
            
    #Fold gate with one child                
    def foldgate(self, gate):
        removedGates = []
        for node in gate.con:
            if node.t in ['andGate', 'orGate']:
                self.foldgate(node)
                if len(node.con) == 1:
                    gate.con.extend(node.con)
                    removedGates.append(node)                
        for node in removedGates:
            gate.con.remove(node)
            
    def tPrintRecursive(self, gate):
        print(gate.name, '->',)
        for u in gate.con:
            print(u.name,)
        print
        for u in gate.con:
            if u.t in ['andGate', 'orGate']:
                self.tPrintRecursive(u)
    
    #Print tree
    def treePrint(self):
        self.tPrintRecursive(self.topGate)


    #---------------------------------------------------------------------------------------------------------------------------
    #Security analysis part: including attack impact, attack cost, return-on-attack, risk and attack success probability


    #---------------------------------------------------------------------------------------------------------------------------  
    #AT is upper layer
    #Assign child value to node value recursively
    def getImpactValueRecursive(self, gate):
        for u in gate.con:
            if u.t is "node": 
                if u.child is not None:                
                    u.val = u.child.calcImpact()
            else:
                self.getImpactValueRecursive(u)
      
    def getImpactValue(self):
        self.getImpactValueRecursive(self.topGate)


    def getCostValueRecursive(self, gate):
        for u in gate.con:
            if u.t is "node": 
                if u.child is not None:                
                    u.val = u.child.calcCost()
            else:
                self.getCostValueRecursive(u)
    
    def getCostValue(self):
        self.getCostValueRecursive(self.topGate)

    def getProValueRecursive(self, gate):
        for u in gate.con:
            if u.t is "node": 
                if u.child is not None:                
                    u.val = u.child.calcPro()
            else:
                self.getProValueRecursive(u)
    
    def getProValue(self):
        self.getProValueRecursive(self.topGate)


    #----------------------------------------------------------------------------------------------    
    #AT is lower layer
   
    #Calculate the impact value for each node in the attack tree
    def calcImpactRecursive(self, s):    
        if s.t is "andGate":
            val = 0
            for u in s.con:                
                val += self.calcImpactRecursive(u) 
                print ('and: ', val)
        elif s.t is "orGate":
            val = 0
            for u in s.con:
                tval = self.calcImpactRecursive(u)
                if tval >= val:
                    val = tval 
                    print('or:', val)
        elif s.t is "node":
            val = s.val
            print('node value: ', val, s.name)
        else:
            val = 0
        return val
    
    #Get the impact value of each node in the attack tree
    def calcImpact(self):
        return self.calcImpactRecursive(self.topGate)

   
    #Calculate the attack cost value for each node in the attack tree
    def calcCostRecursive(self, s):    
        if s.t is "andGate":
            val = 0
            for u in s.con:                
                val += self.calcCostRecursive(u) 
        elif s.t is "orGate":
            val = 0
            tval = []
            for u in s.con:
                tval.append(self.calcCostRecursive(u))
            #choose the minimum cost value
            val = min(tval)
        elif s.t is "node":
            val = s.val
        else:
            val = 0
        return val
    
    #Get the attack cost value of each node in the attack tree
    def calcCost(self):
        return self.calcCostRecursive(self.topGate)


    #Calculate the probability value for each node in the attack tree
    def calcProRecursive(self, s):      
        if s.t is "andGate":
            val = 1.0
            for u in s.con:                
                val *= self.calcProRecursive(u) #probability
                #print('and: ', val)
        elif s.t is "orGate":
            val = 1.0
            for u in s.con:
                tval = self.calcProRecursive(u)
                #print('tval: ', tval)
                if tval > 0:
                    val *= (1.0-self.calcProRecursive(u)) #probability
            val = 1.0-val
            #print('or: ', val)
        elif s.t is "node" and s.val > 0:
            val = s.val
            #print('node: ', val, s.name)
        else:
            val = 1.0
        return val

    #Get the probability value of each node in the attack tree
    def calcPro(self):
        print('==============================================')
        return self.calcProRecursive(self.topGate)


    #Calculate the risk value for each node in the attack tree
    def calcRiskRecursive(self, s):    
        if s.t is "andGate":
            val = 0
            for u in s.con:                
                val += self.calcRiskRecursive(u) 
                #print ('and:', val)
        elif s.t is "orGate":
            val = 0
            for u in s.con:
                tval = self.calcRiskRecursive(u)
                if tval >= val:
                    val = tval 
        elif s.t is "node":
            val = s.val
        else:
            val = 0
        return val
    
    #Get the risk value of each node in the attack tree
    def calcRisk(self):
        return self.calcRiskRecursive(self.topGate)


    #Calculate the return on attack path value for each node in the attack tree
    def calcReturnOnAttackRecursive(self, s):    
        if s.t is "andGate":
            val = 0
            for u in s.con:                
                val += self.calcReturnOnAttackRecursive(u) 
                #print ('and:', val)
        elif s.t is "orGate":
            val = 0
            for u in s.con:
                tval = self.calcReturnOnAttackRecursive(u)
                if tval >= val:
                    val = tval 
        elif s.t is "node":
            val = s.val
        else:
            val = 0
        return val
    
    #Get the return on attack path value of each node in the attack tree
    def calcReturnOnAttack(self):
        return self.calcReturnOnAttackRecursive(self.topGate)

    #When only one node is in the attack tree, calculate the value for the node
    def getNodeValue(self, s):    
        if s.t is "andGate":
            val = 0
            for u in s.con:                
                val = self.getNodeValue(u) 
        elif s.t is "orGate":
            val = 0
            for u in s.con:
                val = self.getNodeValue(u)
        elif s.t is "node":
            val = s.val
        else:
            val = 0
        return val

    #For MTTC
    #Get value recursively
    def getValueRecursive(self, gate, elements):
        for u in gate.con:
            if u.t is "node": 
                if u.val > 0:
                    elements.append((u.name, u.val))
                #print (elements)
            else:
                self.getValueRecursive(u, elements)
        return None

    #Get gate type recursively
    def getGateRecursive(self, gate, orn, andn):
        for u in gate.con:
            if u.t is 'orGate': 
                orn = orn + 1
                #print (u.name, orn)
                orn, andn = self.getGateRecursive(u, orn, andn)
            elif u.t is 'andGate':
                andn = andn + 1
                #print (u.name, andn)
                orn, andn = self.getGateRecursive(u, orn, andn)
        return (orn, andn)
