"""
This module conducts security analysis and generates SHARPE code from HARM as text file.
"""

from AttackGraph import *
from AttackTree import *
from Harm import *
import os
import math
import csv
from random import shuffle, uniform, expovariate
import numpy as np
from tempfile import NamedTemporaryFile
import shutil
from plotResult import *
import time
from time import sleep
#-------------------------------------------------------
#Compute maximum risk
#-------------------------------------------------------
def computeRisk(harm):
    """
    Compute risk for HARM using attack graph as upper layer and attack tree as lower layer.
    """
    risk = []

    harm.model.calcRisk()
    #No vf() function

    for path in harm.model.allpath:
        pathRisk = 0
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0:
                    print(node.name, node.type, node.val)
                    pathRisk += node.val


        risk.append(pathRisk)

    value = max(risk)
    return value

def riskAnalysis(net, pri):

    h = harm()
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, pri)
    if len(h.model.allpath) != 0:
        r = computeRisk(h)
    else:
        return 0

    return r


#-------------------------------------------------------
#Compute maximum return on attack
#-------------------------------------------------------
def computeReturnOnAttack(harm):
    """
    Compute risk for HARM using attack graph as upper layer and attack tree as lower layer.
    """
    attackReturn = []

    harm.model.calcReturnOnAttack()

    for path in harm.model.allpath:
        pathReturn = 0
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0:
                    #print(node.name, node.type, node.val)
                    pathReturn += node.val
        #print(pathReturn)
        attackReturn.append(pathReturn)

    value = max(attackReturn)

    return value


def returnOnAttackAnalysis(net, pri):

    h = harm()
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, pri)
    if len(h.model.allpath) != 0:
        r = computeReturnOnAttack(h)
    else:
        return 0

    return r


#-------------------------------------------------------
#Compute maximum attack impact
#-------------------------------------------------------
def update_attackImpactAnalysis_file(filename, max_impact):
    tempfile = NamedTemporaryFile(mode='w', delete=False)

    fields = ['From', 'To', 'Weight', 'x', 'y', 'Highlight']
    with open(filename, 'r') as csvfile:
        reader = csv.DictReader(csvfile, fieldnames=fields)
        term_max_impact = 0
        index = 0
        for row in reader:
            if(index):
                if (index > 2 and row['From'] == "attacker"):
                    break
                print("Weight")
                print(float(row['Weight']))
                print(row['From'])
                term_max_impact = term_max_impact + float(row['Weight'])
            index = index + 1

    print("Max Impact")
    print(max_impact)
    print("term_max_impact")
    print(term_max_impact)
    with open(filename, 'r') as csvfile, tempfile:
        reader = csv.DictReader(csvfile, fieldnames=fields)
        writer = csv.DictWriter(tempfile, fieldnames=fields)
        index_term = 0
        if(term_max_impact < max_impact):
            for row in reader:
                if (index_term and index_term < index):
                    row['Highlight'] = 0
                index_term = index_term+1
                row = {'From': row['From'], 'To': row['To'], 'Weight': row['Weight'],
                       'x': row['x'],
                       'y': row['y'],
                       'Highlight': row['Highlight'],
                       }
                writer.writerow(row)
        else:
            for row in reader:
                row = {'From': row['From'], 'To': row['To'], 'Weight': row['Weight'],
                       'x': row['x'],
                       'y': row['y'],
                       'Highlight': row['Highlight'],
                       }
                writer.writerow(row)
    shutil.move(tempfile.name, filename)


def computeAttackImpact(harm, file_prefix):
    """
    Compute attack impact for HARM using attack graph as upper layer and attack tree as lower layer.
    """
    impact = []
    create_Graph = []
    nodeval_array = []
    sum_nodeval_array = 0
    highlight = []
    flag_path_0 =  True
    flag_update = True
    index = 0
    number_paths = 0
    file_name = file_prefix+'attackImpactAnalysis.csv'

    with open(file_name, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["From", "To", "Weight", "x", "y", "Highlight"])

    harm.model.calcImpact()
    print("=================================================")
    print("Print attack paths: \n")
    for path in harm.model.allpath:
        pathImpact = 0
        create_Graph.clear()
        nodeval_array.clear()
        print(path)
        number_paths = number_paths + 1
        for node in path:
            print(node.name, end =' ')
            create_Graph.append(str(node.name)[3:])
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0:
                    print('(', node.val, ')', end = ' ')
                    pathImpact += node.val
                    nodeval_array.append(node.val)
                else:
                    nodeval_array.append(0)
            if flag_path_0:
                index = index + 1
        flag_path_0 = False


        if sum_nodeval_array < sum(nodeval_array):
            sum_nodeval_array = sum(nodeval_array)
            highlight[:] = [1] * (len(nodeval_array))
            if flag_update:
                r = csv.reader(open(file_name))
                lines = list(r)
                for i in range(index-2):
                    print(i)
                    #lines[i][5] = '0'
                writer = csv.writer(open(file_name, 'w'))
                writer.writerows(lines)
                flag_update = False
        else:
            highlight[:] = [0] * (len(nodeval_array))

        with open(file_name, 'a', newline='') as file:
            writer = csv.writer(file)
            for i in range(2, len(create_Graph)-1):
                if i == 2:
                    x = 0
                    y = 0

                elif i == len(create_Graph)-2:
                    x = 6
                    y = 6

                else:
                    x = 3
                    y = 3

                writer.writerow([create_Graph[i-1], create_Graph[i], nodeval_array[i-1], x, y, highlight[i-1]])

        print("\n")
        impact.append(pathImpact)

    value = max(impact)

    print("Maximum attack impact is: ", value)
    #update_attackImpactAnalysis_file(file_name, value)
    #sleep(1)  # Time in seconds
    plotResult(file_name, file_name.replace(".csv",".html"))

    return value, number_paths


def attackImpactAnalysis(net, pri, file_prefix):

    h = harm()
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, pri)
    h.model.printPath()
    h.model.printAG()

    if len(h.model.allpath) != 0:
        ai = computeAttackImpact(h, file_prefix)
    else:
        return 0

    return ai

#---------------------------------------------------------
#Compute minimum attack cost
#---------------------------------------------------------

def computeAttackCost(harm):
    """
    Compute attack cost for HARM using attack graph as upper layer and attack tree as lower layer.
    """
    cost = []

    harm.model.calcCost()

    for path in harm.model.allpath:
        pathCost = 0
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0:
                    pathCost += node.val

        cost.append(pathCost)


    value = min(cost)
    print("Attack Cost:")
    print(value)

    return value

def attackCostAnalysis(net, pri):

    h = harm()
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, pri)
    if len(h.model.allpath) != 0:
        ac = computeAttackCost(h)
    else:
        return 0

    return ac

#---------------------------------------------------------------
#Compute maximum attack success probability
#---------------------------------------------------------------

def computeAttackPro(harm):
    """
    Compute attack success probability for HARM using attack graph as upper layer and attack tree as lower layer.
    """
    pro = []
    rare_paths = 0 # number of rare paths
    unlikely_paths = 0 #number of unlikely paths
    possible_paths = 0 #number of possible paths
    likely_paths = 0 #number of likely paths
    certain_paths = 0 #number of certain_paths
    harm.model.calcPro()
    print("=================================================")
    print("Print attack paths: \n")
    for path in harm.model.allpath:
        pathPro = 1
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                print(node.name, end =' ')
                #Exclude the attacker
                if node.val > 0:
                    print('(', node.val, ')', end = ' ')
                    pathPro *= node.val
        if pathPro > 0 and pathPro <= 0.19:
            rare_paths = rare_paths + 1
        elif pathPro >= 0.2 and pathPro <= 0.39:
            unlikely_paths = unlikely_paths + 1
        elif pathPro >= 0.4 and pathPro <= 0.59:
            possible_paths = possible_paths + 1
        elif pathPro >= 0.6 and pathPro <= 0.79:
            likely_paths = likely_paths + 1
        else:
            certain_paths = certain_paths + 1
        print('\n')
        pro.append(pathPro)

    value = max(pro)
    print("Maximum attack success probability is: ", value)
    return value, rare_paths, unlikely_paths, possible_paths, likely_paths, certain_paths

def attackProAnalysis(net, pri):

    h = harm()
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, pri)
    h.model.printPath()
    h.model.printAG()
    
    if len(h.model.allpath) != 0:
        pro = computeAttackPro(h)
    else:
        return 0
    
    return pro


#------------------------------------
#Compute the number of paths
#------------------------------------
def NP_metric(harm):
    
    value = len(harm.model.allpath)
    return value

#------------------------------------------
#Compute the mean of path lengths
#------------------------------------------
def MPL_metric(harm):

    sum_path_length = 0
    for path in harm.model.allpath:
        sum_path_length += int(len(path)-3)

    value = float(sum_path_length/len(harm.model.allpath))

    return value

#----------------------------------------
#Compute the mode of path lengths
#----------------------------------------
def MoPL_metric(harm):
    
    NP = []
    for path in harm.model.allpath:
        NP.append(int(len(path)-3))

    value = max(NP, key=NP.count)
    return value

#----------------------------------------------------------
#Compute the standard deviation of path lengths
#----------------------------------------------------------
def SDPL_metric(harm):

    sumation_DPL = 0
    MPL = MPL_metric(harm)
    for path in harm.model.allpath:    
        sumation_DPL += float(len(path) - 3 - MPL)**2

    value = math.sqrt(float(sumation_DPL / len(harm.model.allpath)))

    return value

#--------------------------------------
#Compute the shortest attack path
#--------------------------------------
def SP_metric(harm):

    SP=[]
    for path in harm.model.allpath:
        SP.append(int(len(path)-3))
    value = min(SP)
    return value

