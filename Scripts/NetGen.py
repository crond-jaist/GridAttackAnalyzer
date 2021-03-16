"""
This module generates example IoT networks based on topology type and vulnerabilities.
Modified by LE Duy Tan 1st March 2021
"""

from Network import *
from Harm import *
from SecurityEvaluator import *
import math
import random
import os
import sys
import json
from collections import OrderedDict
import csv
from shutil import copyfile
from datetime import datetime
import shutil
import os.path
from os import path
"""
-------------------------------------------------------------------------
Create network with vulnerabilities for the example IoT network.
-------------------------------------------------------------------------
"""

tv_name = []
cam_name = []
thermostat_name = []
cleaner_name = []
light_name = []
meter_name = []
gateway_name = []
concentrator_name = []
local_terminal_name = []
substation_rtu_name = []
pmu_name = []
plc_name = []
fep_name = []
application_server_name = []
active_directory_server_name = []
historian_server_name = []
communication_server_name = []
hmi_name = []
work_station_name = []
iccp_server_name = []
ems_drp_server_name = []

def find_cve_values(cve):
    find =['','',0,0,0]
    flag = False
    with open(source_file_name) as f:
        for l, i in enumerate(f):
            data = i.split(",")
            if data[0] == cve:
                flag = True
                find.clear()
                find = data
                break
    return find, flag



def createWiFi(street_list, house_list, entry, target):

    # Create a Wi-Fi network
    net = network()
    #print(find_cve_values('CVE-2019-9871'))

    #create central concentrator
    central_concentrator_name = 'central_concentrator'
    central_concentrator = iot(central_concentrator_name)
    central_concentrator.subnet.append('zb') #another type
    v_central_concentrator = vulNode(find_cve_values("central_concentrator")[0][1])
    # createVuls(self, node, metricValue, pri)
    """
            Create vulnerability network for the node.
            :param node: node in the network which has vulnerabilities
            :param metricValue: assign a metric value to vulnerability 
            (e.g. attack probability)
            => metricValue = Exploitability Subscore/10
            :param pri: assign privilege value to vulnerability 
            (1: user; 2: admin; 3: root)
            root higher privilege vulnerability 

            :returns: none
    """
    v_central_concentrator.createVuls(central_concentrator, float(find_cve_values("central_concentrator")[0][4]) / 10,
                                      1)  # Change 1 => 3, pri after exploiting vuls
    v_central_concentrator.thresholdPri(central_concentrator, 1)  # change 1 => 0, pri before exploitation of attackers
    v_central_concentrator.terminalPri(central_concentrator,
                                       1)  # change 1 => 3, pri after expoitation #line 49 == line 51

    # create FEP
    fep_name = 'fep'
    fep = iot(fep_name)
    fep.subnet.append('zb')  # another type
    v_fep = vulNode(find_cve_values("fep")[0][1])
    v_fep.createVuls(fep, float(find_cve_values("fep")[0][4]) / 10, 1)  # Change 1 => 3, pri after exploiting vuls
    v_fep.thresholdPri(fep, 1)  # change 1 => 0, pri before exploitation of attackers
    v_fep.terminalPri(fep, 1)  # change 1 => 3, pri after expoitation #line 49 == line 51

    # create application_server
    application_server_name = 'application_server'
    application_server = iot(application_server_name)
    application_server.subnet.append('zb')  # another type
    v_application_server = vulNode(find_cve_values("application_server")[0][1])
    v_application_server.createVuls(application_server, float(find_cve_values("application_server")[0][4]) / 10, 1)  # Change 1 => 3, pri after exploiting vuls
    v_application_server.thresholdPri(application_server, 1)  # change 1 => 0, pri before exploitation of attackers
    v_application_server.terminalPri(application_server, 1)  # change 1 => 3, pri after expoitation #line 49 == line 51

    # create active_directory_server
    active_directory_server_name = 'active_directory_server'
    active_directory_server = iot(active_directory_server_name)
    active_directory_server.subnet.append('zb')  # another type
    v_active_directory_server = vulNode(find_cve_values("active_directory_server")[0][1])
    v_active_directory_server.createVuls(active_directory_server, float(find_cve_values("active_directory_server")[0][4]) / 10, 1)  # Change 1 => 3, pri after exploiting vuls
    v_active_directory_server.thresholdPri(active_directory_server, 1)  # change 1 => 0, pri before exploitation of attackers
    v_active_directory_server.terminalPri(active_directory_server, 1)  # change 1 => 3, pri after expoitation #line 49 == line 51

    # create historian_server
    historian_server_name = 'historian_server'
    historian_server = iot(historian_server_name)
    historian_server.subnet.append('zb')  # another type
    v_historian_server = vulNode(find_cve_values("historian_server")[0][1])
    v_historian_server.createVuls(historian_server,
                                         float(find_cve_values("historian_server")[0][4]) / 10,
                                         1)  # Change 1 => 3, pri after exploiting vuls
    v_historian_server.thresholdPri(historian_server,
                                           1)  # change 1 => 0, pri before exploitation of attackers
    v_historian_server.terminalPri(historian_server,
                                          1)  # change 1 => 3, pri after expoitation #line 49 == line 51

    # create communication_server
    communication_server_name = 'communication_server'
    communication_server = iot(communication_server_name)
    communication_server.subnet.append('zb')  # another type
    v_communication_server = vulNode(find_cve_values("communication_server")[0][1])
    v_communication_server.createVuls(communication_server,
                                  float(find_cve_values("communication_server")[0][4]) / 10,
                                  1)  # Change 1 => 3, pri after exploiting vuls
    v_communication_server.thresholdPri(communication_server,
                                    1)  # change 1 => 0, pri before exploitation of attackers
    v_communication_server.terminalPri(communication_server,
                                   1)  # change 1 => 3, pri after expoitation #line 49 == line 51

    # create hmi
    hmi_name = 'hmi'
    hmi = iot(hmi_name)
    hmi.subnet.append('zb')  # another type
    v_hmi = vulNode(find_cve_values("hmi")[0][1])
    v_hmi.createVuls(hmi, float(find_cve_values("hmi")[0][4]) / 10, 1)  # Change 1 => 3, pri after exploiting vuls
    v_hmi.thresholdPri(hmi, 1)  # change 1 => 0, pri before exploitation of attackers
    v_hmi.terminalPri(hmi, 1)  # change 1 => 3, pri after expoitation #line 49 == line 51

    # create work_station
    work_station_name = 'work_station'
    work_station = iot(work_station_name)
    work_station.subnet.append('zb')  # another type
    v_work_station = vulNode(find_cve_values("work_station")[0][1])
    v_work_station.createVuls(work_station, float(find_cve_values("work_station")[0][4]) / 10, 1)  # Change 1 => 3, pri after exploiting vuls
    v_work_station.thresholdPri(work_station, 1)  # change 1 => 0, pri before exploitation of attackers
    v_work_station.terminalPri(work_station, 1)  # change 1 => 3, pri after expoitation #line 49 == line 51

    # create iccp_server
    iccp_server_name = 'iccp_server'
    iccp_server = iot(iccp_server_name)
    iccp_server.subnet.append('zb')  # another type
    v_iccp_server= vulNode(find_cve_values("iccp_server")[0][1])
    v_iccp_server.createVuls(iccp_server, float(find_cve_values("iccp_server")[0][4]) / 10, 1)  # Change 1 => 3, pri after exploiting vuls
    v_iccp_server.thresholdPri(iccp_server, 1)  # change 1 => 0, pri before exploitation of attackers
    v_iccp_server.terminalPri(iccp_server, 1)  # change 1 => 3, pri after expoitation #line 49 == line 51

    # create ems_drp_server
    ems_drp_server_name = 'ems_drp_server'
    ems_drp_server = iot(ems_drp_server_name)
    ems_drp_server.subnet.append('zb')  # another type
    v_ems_drp_server = vulNode(find_cve_values("ems_drp_server")[0][1])
    v_ems_drp_server.createVuls(ems_drp_server, float(find_cve_values("ems_drp_server")[0][4]) / 10,
                             1)  # Change 1 => 3, pri after exploiting vuls
    v_ems_drp_server.thresholdPri(ems_drp_server, 1)  # change 1 => 0, pri before exploitation of attackers
    v_ems_drp_server.terminalPri(ems_drp_server, 1)  # change 1 => 3, pri after expoitation #line 49 == line 51






    for i in range(len(street_list)):
        for j in range(len(house_list)):

            #Concentrator
            if j == 0:

                # concentrator
                concentrator_name.append('concentrator_' + street_list[i][0])
                concentrator = iot(concentrator_name[i])
                concentrator.subnet.append('zb')
                v_concentrator = vulNode(find_cve_values(concentrator_name[i])[0][1])
                v_concentrator.createVuls(concentrator, float(find_cve_values(concentrator_name[i])[0][4])/10, 1)
                v_concentrator.thresholdPri(concentrator, 1)
                v_concentrator.terminalPri(concentrator, 1)

                #local_terminal
                local_terminal_name.append('local_terminal_' + street_list[i][0])
                local_terminal = iot(local_terminal_name[i])
                local_terminal.subnet.append('zb')
                v_local_terminal = vulNode(find_cve_values(local_terminal_name[i])[0][1])
                v_local_terminal.createVuls(local_terminal, float(find_cve_values(local_terminal_name[i])[0][4]) / 10, 1)
                v_local_terminal.thresholdPri(local_terminal, 1)
                v_local_terminal.terminalPri(local_terminal, 1)

                # pmu
                pmu_name.append('pmu_' + street_list[i][0])
                pmu = iot(pmu_name[i])
                pmu.subnet.append('zb')
                v_pmu = vulNode(find_cve_values(pmu_name[i])[0][1])
                v_pmu.createVuls(pmu, float(find_cve_values(pmu_name[i])[0][4]) / 10,
                                            1)
                v_pmu.thresholdPri(pmu, 1)
                v_pmu.terminalPri(pmu, 1)

                # substation_rtu
                substation_rtu_name.append('substation_rtu_' + street_list[i][0])
                substation_rtu = iot(substation_rtu_name[i])
                substation_rtu.subnet.append('zb')
                v_substation_rtu = vulNode(find_cve_values(substation_rtu_name[i])[0][1])
                v_substation_rtu.createVuls(substation_rtu, float(find_cve_values(substation_rtu_name[i])[0][4]) / 10,
                                 1)
                v_substation_rtu.thresholdPri(substation_rtu, 1)
                v_substation_rtu.terminalPri(substation_rtu, 1)

                # plc
                plc_name.append('plc_' + street_list[i][0])
                plc = iot(plc_name[i])
                plc.subnet.append('zb')
                v_plc = vulNode(find_cve_values(plc_name[i])[0][1])
                v_plc.createVuls(plc, float(find_cve_values(plc_name[i])[0][4]) / 10,
                                            1)
                v_plc.thresholdPri(plc, 1)
                v_plc.terminalPri(plc, 1)

            #TV
            #tv_A_0
            tv_name.append('smart_tv_' + street_list[i][0]+'_'+ str(j))
            tv = iot(tv_name[-1]) # tv_name[-1] is the last value of tv_name array
            print(tv_name[-1])
            # tv = iot('tv_A_0')
            tv.subnet.append('wifi')  # bluetooth
            v_tv = vulNode(find_cve_values(tv_name[-1])[0][1])  # vulNode(object)
            v_tv.createVuls(tv, float(find_cve_values(tv_name[-1])[0][4])/10, 1)  # CVSS base score: 10.0 #
            v_tv.thresholdPri(tv, 1)
            v_tv.terminalPri(tv, 1)


            #Camera
            cam_name.append('ip_camera_' + street_list[i][0] + '_' + str(j))
            cam = iot(cam_name[-1])
            print(cam_name[-1])
            cam.subnet.append('wifi')
            v_cam = vulNode(find_cve_values(cam_name[-1])[0][1])
            v_cam.createVuls(cam, float(find_cve_values(cam_name[-1])[0][4])/10, 1)  # CVSS base score: 10.0
            v_cam.thresholdPri(cam, 1)
            v_cam.terminalPri(cam, 1)


            #Thermostat
            thermostat_name.append('smart_thermostat_' + street_list[i][0] + '_' + str(j))
            thermostat = iot(thermostat_name[-1])
            print(thermostat_name[-1])
            thermostat.subnet.append('wifi')
            v_thermostat = vulNode(find_cve_values(thermostat_name[-1])[0][1])
            v_thermostat.createVuls(thermostat, float(find_cve_values(thermostat_name[-1])[0][4])/10, 1)  # CVSS base score: 10.0
            v_thermostat.thresholdPri(thermostat, 1)
            v_thermostat.terminalPri(thermostat, 1)

            #Cleaner
            cleaner_name.append('cleaner_' + street_list[i][0] + '_' + str(j))
            cleaner = iot(cleaner_name[-1])
            print(cleaner_name[-1])
            cleaner.subnet.append('wifi')
            v_cleaner = vulNode(find_cve_values(cleaner_name[-1])[0][1])
            v_cleaner.createVuls(cleaner, float(find_cve_values(cleaner_name[-1])[0][4])/10, 1)  # CVSS base score: 10.0
            v_cleaner.thresholdPri(cleaner, 1)
            v_cleaner.terminalPri(cleaner, 1)

            #Light
            light_name.append('light_' + street_list[i][0] + '_' + str(j))
            light = iot(light_name[-1])
            print(light_name[-1])
            light.subnet.append('wifi')
            v_light = vulNode(find_cve_values(light_name[-1])[0][1])
            v_light.createVuls(light, float(find_cve_values(light_name[-1])[0][4])/10, 1)  # CVSS base score: 10.0
            v_light.thresholdPri(light, 1)
            v_light.terminalPri(light, 1)

            #Gateway
            gateway_name.append('gateway_' + street_list[i][0] + '_' + str(j))
            gateway = iot(gateway_name[-1])
            print(gateway_name[-1])
            gateway.subnet.append('wifi')
            v_gateway = vulNode(find_cve_values(gateway_name[-1])[0][1])
            v_gateway.createVuls(gateway, float(find_cve_values(gateway_name[-1])[0][4])/10, 1)
            v_gateway.thresholdPri(gateway, 1) # Start Point #Must Remove if we have 2 vuls
            v_gateway.terminalPri(gateway, 1)

            #Meter
            meter_name.append('smart_meter_' + street_list[i][0] + '_' + str(j))
            meter = iot(meter_name[-1])
            print(meter_name[-1])
            meter.subnet.append('wifi')
            v_meter = vulNode(find_cve_values(meter_name[-1])[0][1])
            v_meter.createVuls(meter, float(find_cve_values(meter_name[-1])[0][4])/10, 1)  # 1.0 initial value with no meaning
            v_meter.thresholdPri(meter, 1)
            v_meter.terminalPri(meter, 1)


            net.connectOneWay(meter, concentrator)
            net.connectOneWay(local_terminal, substation_rtu)
            net.connectOneWay(pmu, substation_rtu)
            net.connectOneWay(substation_rtu, fep)
            net.connectOneWay(concentrator, fep)
            net.connectOneWay(plc, fep)
            #net.connectOneWay(concentrator, central_concentrator)
            net.connectOneWay(fep, application_server)
            net.connectOneWay(fep, active_directory_server)
            net.connectOneWay(fep, historian_server)
            net.connectOneWay(fep, communication_server)

            net.connectOneWay(work_station, application_server)
            net.connectOneWay(work_station, active_directory_server)
            net.connectOneWay(work_station, historian_server)
            net.connectOneWay(work_station, communication_server)

            net.connectOneWay(hmi, application_server)
            net.connectOneWay(hmi, active_directory_server)
            net.connectOneWay(hmi, historian_server)
            net.connectOneWay(hmi, communication_server)

            net.connectOneWay(application_server, iccp_server)
            net.connectOneWay(active_directory_server, iccp_server)
            net.connectOneWay(historian_server, iccp_server)
            net.connectOneWay(communication_server, iccp_server)

            net.connectOneWay(iccp_server, ems_drp_server)






            if find_cve_values(tv_name[-1])[1]:
                net.nodes.append(tv)
            if find_cve_values(cam_name[-1])[1]:
                net.nodes.append(cam)
            if find_cve_values(thermostat_name[-1])[1]:
                net.nodes.append(thermostat)
            if find_cve_values(cleaner_name[-1])[1]:
                net.nodes.append(cleaner)
            if find_cve_values(light_name[-1])[1]:
                net.nodes.append(light)
            if find_cve_values(gateway_name[-1])[1]:
                net.connectOneWay(tv, gateway)
                net.connectOneWay(cam, gateway)
                net.connectOneWay(thermostat, gateway)
                net.connectOneWay(cleaner, gateway)
                net.connectOneWay(light, gateway)
                net.connectOneWay(gateway, meter)

                net.nodes.append(gateway)
            else:
                net.connectOneWay(tv, meter)
                net.connectOneWay(cam, meter)
                net.connectOneWay(thermostat, meter)
                net.connectOneWay(cleaner, meter)
                net.connectOneWay(light, meter)

            if find_cve_values(meter_name[-1])[1]:
                net.nodes.append(meter)
            if j == 0:
                if find_cve_values(concentrator_name[i])[1]:
                    net.nodes.append(concentrator)
                if find_cve_values(local_terminal_name[i])[1]:
                    net.nodes.append(local_terminal)
                if find_cve_values(substation_rtu_name[i])[1]:
                    net.nodes.append(substation_rtu)
                if find_cve_values(pmu_name[i])[1]:
                    net.nodes.append(pmu)
                if find_cve_values(plc_name[i])[1]:
                    net.nodes.append(plc)



    if find_cve_values("central_concentrator")[1]:
        net.nodes.append(central_concentrator)
    if find_cve_values("fep")[1]:
        net.nodes.append(fep)
    if find_cve_values("application_server")[1]:
        net.nodes.append(application_server)
    if find_cve_values("active_directory_server")[1]:
        net.nodes.append(active_directory_server)
    if find_cve_values("historian_server")[1]:
        net.nodes.append(historian_server)
    if find_cve_values("hmi")[1]:
        net.nodes.append(hmi)
    if find_cve_values("work_station")[1]:
        net.nodes.append(work_station)
    if find_cve_values("iccp_server")[1]:
        net.nodes.append(iccp_server)
    if find_cve_values("ems_drp_server")[1]:
        net.nodes.append(ems_drp_server)


    # Set the attacker as the start
    A = computer('attacker')
    A.setStart()  # ag_S- Staring point
    # Link the attacker with TV and camera
    entry_list = []
    name_list = {'smart_tv':'tv_name',
                 'cleaner': 'cleaner_name',
                 'light': 'light_name',
                 'ip_camera': 'cam_name',
                 'smart_thermostat': 'thermostat_name',
                 'smart_meter': 'meter_name',
                 'concentrator': 'concentrator_name',
                 'gateway': 'gateway_name',
                 'central_concentrator': 'central_concentrator_name',
                 "fep": "fep_name",
                 "application_server": "application_server_name",
                 "active_directory_server": "active_directory_server_name",
                 "historian_server": "historian_server_name",
                 "communication_server": "communication_server_name",
                 "hmi": "hmi_name",
                 "work_station": "work_station_name",
                 "iccp_server": "iccp_server_name",
                 "ems_drp_server": "ems_drp_server_name",
                 "local_terminal": "local_terminal_name",
                 "substation_rtu": "substation_rtu_name",
                 "pmu": "pmu_name",
                 "plc": "plc_name"
                 }
    for i in range(len(entry)-1):
        if(entry[i][-1].isnumeric()):
            entry_list.append(entry[i])

        else:
            for key, value in name_list.items():
                if key == entry[i]:
                    entry_list.extend(globals()[value])





    target_list = []
    if "smart_tv" == target[0]:
        target_list.extend(tv_name)
    elif "cleaner" == target[0]:
        target_list.extend(cleaner_name)
    elif  "light" == target[0]:
        target_list.extend(light_name)
    elif "ip_camera" == target[0]:
        target_list.extend(cam_name)
    elif  "smart_meter" == target[0]:
        target_list.extend(meter_name)
    elif  "gateway" == target[0]:
        target_list.extend(gateway_name)
    elif  "concentrator" == target[0]:
        target_list.extend(concentrator_name)
    elif  "central_concentrator" == target[0]:
        target_list.extend(['central_concentrator'])
    elif  "local_terminal" == target[0]:
        target_list.extend(['local_terminal'])
    elif  "substation_rtu" == target[0]:
        target_list.extend(['substation_rtu'])
    elif  "pmu" == target[0]:
        target_list.extend(['pmu'])
    elif  "plc" == target[0]:
        target_list.extend(['plc'])
    elif  "fep" == target[0]:
        target_list.extend(['fep'])
    elif  "application_server" == target[0]:
        target_list.extend(['application_server'])
    elif  "active_directory_server" == target[0]:
        target_list.extend(['active_directory_server'])
    elif  "historian_server" == target[0]:
        target_list.extend(['historian_server'])
    elif  "communication_server" == target[0]:
        target_list.extend(['communication_server'])
    elif  "hmi" == target[0]:
        target_list.extend(['hmi'])
    elif "work_station" == target[0]:
        target_list.extend(['work_station'])
    elif "iccp_server" == target[0]:
        target_list.extend(['iccp_server'])
    elif "ems_drp_server" == target[0]:
        target_list.extend(['ems_drp_server'])
    elif   "smart_thermostat" == target[0]:
        target_list.extend(thermostat_name)
    else:
        target_list.append(target[0])
    #if entry_list in
    for node in net.nodes:
        if node.name in entry_list:
            A.con.append(node)
        elif node.name in target_list:
            node.setEnd()  # central_concentrator ag_E- End point

    net.nodes.append(A)
    net.constructSE()
    net.printNetWithVul()  # Network Model

    return net





def assignNewMetricValue(net, metric):
    for node in net.nodes:
        if node.name in tv_name + cam_name + thermostat_name \
                + cleaner_name + light_name \
                + concentrator_name + ['central_concentrator']\
                + meter_name + gateway_name + local_terminal_name + \
                substation_rtu_name +  pmu_name + plc_name + fep_name + \
                application_server_name + active_directory_server_name + \
                historian_server_name + communication_server_name + hmi_name + \
                work_station_name + iccp_server_name + ems_drp_server_name: #tv_A_0 tv_A_1 #tv_B_0
            for vul in node.vul.nodes:
                if metric == "risk":
                    vul.assignRisk(float(find_cve_values(node.name)[0][4])/10, float(find_cve_values(node.name)[0][3]))
                    # asp, attack impact
                elif metric == "asp":
                    vul.val = float(find_cve_values(node.name)[0][4])/10
                    # attack success probability = exploitability/10
                elif metric == "impact":
                    vul.val = float(find_cve_values(node.name)[0][3])
                    # impact from the CVE version 2




    net.printNetWithVul()
    return None




if __name__ == '__main__':
    #

    street_list = sys.argv[1].split(':')[:-1] # Street List
    house_list = sys.argv[2].split(':')[:-1] # Number of houses in each street

    entry_list = sys.argv[3].split(':') # Entry
    target_list = sys.argv[4].split(':') # Target
    strategy_name = sys.argv[5].replace(":","_") #name
    current_time = sys.argv[6] #current_time
    num_devices = float(sys.argv[7]) #Total Number of devices
    global source_file_name

    source_file_name = "Results/"+strategy_name+"_source.csv"

    copyfile("Results/source.csv", source_file_name)
    file_prefix = "Results/"+strategy_name+"_"


    net = createWiFi(street_list, house_list, entry_list, target_list)

    # Create HARM and compute attack paths

    #h = harm()
    #h.constructHarm(net, "attackgraph", 1, "attacktree", 1, 3)
    #constructHarm(self, net, up, valueUp, lo, valueLow, pri)
    """
            Construct HARM.

            :param net: network
            :param up: upper layer type
            :param vu: assign a default value to val parameter for node, no real meaning when initializing, changed and used in security analysis
            :param lo: lower layer type
            :param vl: assign a default value to val parameter for vulnerability, no real meaning when initializing, changed and used in security analysis
            :param pri: assign a privilege value in construction of lower layer vulnerability connections
            :returns: HARM: contains two layers, when using AGAT, \
                            the upper layer is attack graph listing nodes and attack paths \
                            each node has a lower layer which stored in child parameter, containing vulnerability tree
    """

    # h.model.printPath()
    # h.model.printAG()
    # h.model.printNetWithVul()
    # h.model.treePrint()

    assignNewMetricValue(net, "asp")
    attackProAnalysis_array = attackProAnalysis(net, 1) # 1 because we just have 1 vul for everything
    # change 1 => 3 which is the pri after the exploitation
    attack_success_probability = attackProAnalysis_array[0]

    #Compute Attack Risk
    assignNewMetricValue(net, "risk")
    attack_risk = riskAnalysis(net, 1) # 1 because we just have 1 vul for everything

    
    assignNewMetricValue(net, "impact") #risk #asp #impact
    analysis_array = attackImpactAnalysis(net, 1, file_prefix) # 1 because we just have 1 vul for everything
    
    attack_cost = attackCostAnalysis(net, 1)
    # change 1 => 3 which is the pri after the exploitation

    # read header automatically
    with open('Results/Results.csv', "r") as f:
        reader = csv.reader(f)
        for header in reader:
            break

    with open(r'Results/Results.csv', 'a+', newline='') as file:
        writer = csv.writer(file)
        print(current_time)
        print(str(strategy_name).replace("_"," "))
        print(str(street_list))
        print(str(house_list))
        print(attack_success_probability)
        print(attack_cost)
        print(analysis_array[0])
        print(analysis_array[1])
        writer.writerow([current_time,
                         str(strategy_name).replace("_"," "),
                         str(street_list)+"\n"+str(house_list),
                         attack_success_probability,
                         attack_cost,
                         analysis_array[0],
                         float(attack_success_probability*analysis_array[0]),
                         num_devices,
                         float(attack_cost/num_devices),
                         float(analysis_array[0] / num_devices),
                         analysis_array[1],
                        attackProAnalysis_array[1],
                        attackProAnalysis_array[2],
                        attackProAnalysis_array[3],
                        attackProAnalysis_array[4],
                        attackProAnalysis_array[5],
                         ]

                        )
        file.close()



