from tkinter import *
from tkinter.ttk import *
from tkinter import ttk
import tkinter as tk

import json

from tkinter import messagebox

import datetime

from tkinter.filedialog import askopenfile
from graphviz import Source  #pip install graphviz # to install graphviz
from collections import OrderedDict
from tkinter import StringVar
import csv
import os
import os.path
from os import path
from tkinter import simpledialog


from datetime import datetime
import random
from tempfile import NamedTemporaryFile
import shutil


filter = "JSON file (*.json)|*.json|All Files (*.*)|*.*||"
with open('database.json', 'r') as f:
    distros_dict = json.load(f, object_pairs_hook=OrderedDict)

path = "Scripts/"

#Sets up a frame

class MyApplication(Frame):

    #When a class is initialized, this is called as per any class
    def __init__(self, root):

        #Similar to saying MyFrame = Frame(master)
        Frame.__init__(self, root)

        self.text_file = tk.StringVar()
        self.text_file.set("")
        #Puts the frame on a grid. If you had two frames on one window, you would do the row, column keywords (or not...)
        
        self.grid()




        #Function to put the widgets on the frame. Can have any name!
        self.create_widgets(root)

    def updtcblist(self, list1, list2):

        combo_target.config(values=list1)
        combo_target.current(1)
        combo_to_edit_device.config(values=list2)
        combo_to_edit_device.current(1)

        for i in list1:
            lstbox_target.insert(END,str(i))

    def generate_tree(self):
        n_street_list = ''
        n_house_list = ''
        n_devices_list = ''
        n_cve_list = ''
        n_entry_list = ''
        current_time = datetime.now().strftime("%H:%M:%S")
        n_strategy_name = (str(combo_smartgrid_model.get()) + " " + current_time)

        strategy_name = simpledialog.askstring("Just one more step", "Do you want to set a case study name?\n" +
                                        "Otherwise '" +
                                        n_strategy_name +
                                        "' will be used",
                                        parent=window)
        if str(strategy_name).strip():
            n_strategy_name = strategy_name




        entry = [lstbox_target.get(idx) for idx in lstbox_target.curselection()]
        for i in range(len(street_list)):
            n_street_list = n_street_list + str(street_list[i]) + ":"
        for i in range(len(house_list)):
            n_house_list = n_house_list + str(house_list[i]) + ":"
        for i in range(len(devices_list)):
            n_devices_list = n_devices_list + str(devices_list[i]) + ":"
        for i in range(len(cve_list)):
            n_cve_list = n_cve_list + str(cve_list[i]) + ":"
        for i in range(len(entry)):
            n_entry_list = n_entry_list + str(entry[i]) + ":"



        #Count Number of Devices
        num_devices = 1
        file = open("Results/source.csv")
        reader = csv.reader(file)
        num_devices = len(list(reader))

        self.text_file.set("File was generated at" + str(os.getcwd()) + "/" + "Results/"+(str(n_strategy_name).replace(" ","_")).replace(":","_")+"_source.csv")

        os.system('python3 '+ path +'NetGen.py '+
                  n_street_list +
                  ' ' +
                  n_house_list +
                  ' ' +
                  n_entry_list +
                  ' ' +
                  combo_target.get() +
                  ' ' +
                  str(n_strategy_name).replace(" ","_") +
                  ' ' +
                  current_time +
                  ' ' +
                  str(num_devices)
                  )









    def open_csv_file(self):
        #ubuntu only

        if(self.text_file.get()):
            os.system('libreoffice -o Results/'+str(self.text_file.get().split("/")[-1]))
        else:
            os.system('libreoffice -o Results/source.csv')

    def open_security_csv_file(self):
        #ubuntu only
        os.system('libreoffice -o Results/Results.csv')
    def open_graph_source_file(self):
        os.system('libreoffice -o Results/' +str(self.text_file.get().split("/")[-1]).replace('source.csv','attackImpactAnalysis.csv'))
    def open_attack_graph(self):
        os.system('firefox Results/' + str(self.text_file.get().split("/")[-1]).replace('source.csv','attackImpactAnalysis.html'))


    def find_cve_values(self, cve):
        base_score = 0
        impact_score = 0
        exploitability_score = 0
        description = ''
        for key in range(len(distros_dict['object'][2]['CVE_list'])):
            if distros_dict['object'][2]['CVE_list'][key]["CVE"] in cve:
                base_score = distros_dict['object'][2]['CVE_list'][key]["CVSS_Base_Score_2.0"]
                impact_score = distros_dict['object'][2]['CVE_list'][key]["Impact_Subscore"]
                exploitability_score = distros_dict['object'][2]['CVE_list'][key]["Exploitability_Subscore"]
                description = distros_dict['object'][2]['CVE_list'][key]["description"]
        return base_score, impact_score, exploitability_score, description

    def OnButtonClick(self, key):
        cve = globals()["CVE_list" + str(key)].get()

        messagebox.showinfo("CVE Information",
                            cve+"\n- Description: " + str(self.find_cve_values(cve)[3]) +
                            "\n\n- CVSS Base Score v2.0: " + str(self.find_cve_values(cve)[0]) +
                            "\n\n- Impact Subscore: " + str(self.find_cve_values(cve)[1]) +
                            "\n\n- Exploitability Subscore: " + str(self.find_cve_values(cve)[2])
                            )

    def getRandomCVEVals(self, device_name):
        print(devices_and_cve_list.get(device_name))
        return str(random.choice(devices_and_cve_list.get(device_name)))


    def generate_file(self):
        global street_list
        global house_list
        global devices_list
        global cve_list
        street_list = []
        house_list = []
        devices_list =[]
        cve_list =[]
        street_list.clear()
        house_list.clear()
        devices_list.clear()
        cve_list.clear()
        entry_target = []
        entry_target.clear()
        global n_strategy_name


        for key_1 in range(len(distros_dict['object'][0]['model_list'])):
            if (distros_dict['object'][0]['model_list'][key_1]['list_name'] in combo_smartgrid_model.get() ):
                dict = distros_dict['object'][0]['model_list'][key_1]["streets_and_houses"]
                street_list = [k for k,v in dict[0].items()]
                house_list = [v for k,v in dict[0].items()]
        devices_list = []
        cve_list = []
        for key in range(number_device_list + 1):
            try:
                if globals()["devices_list" + str(key)].state()[0] in ['selected']:
                    # print(globals()["devices_list" + str(key)].cget("text"))
                    devices_list.append(globals()["devices_list" + str(key)].cget("text").lower().replace(" ", "_"))
                    cve_list.append(globals()["CVE_list" + str(key)].get())
            except Exception as e:
                print("Something was wrong!")
        entry_target.extend(devices_list)

        global source_file_name
        source_file_name = 'Results/source.csv'

        if (combo_cve_vals_selection.get() == "Manually"):
            with open(source_file_name, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Device", "CVE", "CVSS Base Score 2.0", "Impact Subcore", "Exploitability Subscore"])

                #SCADA Devices
                try:
                    index_central_concentrator = devices_list.index("central_concentrator")
                    if index_central_concentrator >= 0:
                        writer.writerow(["central_concentrator", cve_list[index_central_concentrator],
                                         self.find_cve_values(cve_list[index_central_concentrator])[0],
                                         self.find_cve_values(cve_list[index_central_concentrator])[1],
                                         self.find_cve_values(cve_list[index_central_concentrator])[2]])
                except ValueError:
                    print("List does not contain value")
                try:
                    index_fep = devices_list.index("fep")
                    if index_fep >= 0:
                        writer.writerow(["fep", cve_list[index_fep],
                                         self.find_cve_values(cve_list[index_fep])[0],
                                         self.find_cve_values(cve_list[index_fep])[1],
                                         self.find_cve_values(cve_list[index_fep])[2]])
                except ValueError:
                    print("No fep")
                try:
                    index_application_server = devices_list.index("application_server")
                    if index_application_server >= 0:
                        writer.writerow(["application_server", cve_list[index_application_server],
                                         self.find_cve_values(cve_list[index_application_server])[0],
                                         self.find_cve_values(cve_list[index_application_server])[1],
                                         self.find_cve_values(cve_list[index_application_server])[2]])
                except ValueError:
                    print("No application server")
                try:
                    index_active_directory_server = devices_list.index("active_directory_server")
                    if index_active_directory_server >= 0:
                        writer.writerow(["active_directory_server", cve_list[index_active_directory_server],
                                         self.find_cve_values(cve_list[index_active_directory_server])[0],
                                         self.find_cve_values(cve_list[index_active_directory_server])[1],
                                         self.find_cve_values(cve_list[index_active_directory_server])[2]])
                except ValueError:
                    print("No active directory server")
                try:
                    index_historian_server = devices_list.index("historian_server")
                    if index_historian_server >= 0:
                        writer.writerow(["historian_server", cve_list[index_historian_server],
                                         self.find_cve_values(cve_list[index_historian_server])[0],
                                         self.find_cve_values(cve_list[index_historian_server])[1],
                                         self.find_cve_values(cve_list[index_historian_server])[2]])
                except ValueError:
                    print("No historian server")
                try:
                    index_communication_server = devices_list.index("communication_server")
                    if index_communication_server >= 0:
                        writer.writerow(["communication_server", cve_list[index_communication_server],
                                         self.find_cve_values(cve_list[index_communication_server])[0],
                                         self.find_cve_values(cve_list[index_communication_server])[1],
                                         self.find_cve_values(cve_list[index_communication_server])[2]])
                except ValueError:
                    print("No communication server")
                try:
                    index_hmi = devices_list.index("hmi")
                    if index_hmi >= 0:
                        writer.writerow(["hmi", cve_list[index_hmi],
                                         self.find_cve_values(cve_list[index_hmi])[0],
                                         self.find_cve_values(cve_list[index_hmi])[1],
                                         self.find_cve_values(cve_list[index_hmi])[2]])
                except ValueError:
                    print("No hmi")
                try:
                    index_work_station = devices_list.index("work_station")
                    if index_work_station >= 0:
                        writer.writerow(["work_station", cve_list[index_work_station],
                                         self.find_cve_values(cve_list[index_work_station])[0],
                                         self.find_cve_values(cve_list[index_work_station])[1],
                                         self.find_cve_values(cve_list[index_work_station])[2]])
                except ValueError:
                    print("No work station")
                try:
                    index_iccp_server = devices_list.index("iccp_server")
                    if index_iccp_server >= 0:
                        writer.writerow(["iccp_server", cve_list[index_iccp_server],
                                         self.find_cve_values(cve_list[index_iccp_server])[0],
                                         self.find_cve_values(cve_list[index_iccp_server])[1],
                                         self.find_cve_values(cve_list[index_iccp_server])[2]])
                except ValueError:
                    print("iccp server")
                try:
                    index_ems_drp_server = devices_list.index("ems_drp_server")
                    if index_ems_drp_server >= 0:
                        writer.writerow(["ems_drp_server", cve_list[index_ems_drp_server],
                                         self.find_cve_values(cve_list[index_ems_drp_server])[0],
                                         self.find_cve_values(cve_list[index_ems_drp_server])[1],
                                         self.find_cve_values(cve_list[index_ems_drp_server])[2]])
                except ValueError:
                    print("No ems_drp_server")
                    #End SCADA Devices


                for i in range(len(street_list)):
                    for j in range(len(house_list)):
                        if j == 0:
                            try:
                                index_local_terminal = devices_list.index("local_terminal")
                                if index_local_terminal >= 0:
                                    writer.writerow(["local_terminal_" + street_list[i], cve_list[index_local_terminal],
                                                     self.find_cve_values(cve_list[index_local_terminal])[0],
                                                     self.find_cve_values(cve_list[index_local_terminal])[1],
                                                     self.find_cve_values(cve_list[index_local_terminal])[2]])
                                entry_target.append("local_terminal_" + street_list[i])
                            except Exception as e:
                                print("There is no local_terminal!")
                            try:
                                index_pmu = devices_list.index("pmu")
                                if index_pmu >= 0:
                                    writer.writerow(["pmu_" + street_list[i], cve_list[index_pmu],
                                                     self.find_cve_values(cve_list[index_pmu])[0],
                                                     self.find_cve_values(cve_list[index_pmu])[1],
                                                     self.find_cve_values(cve_list[index_pmu])[2]])
                                entry_target.append("pmu_" + street_list[i])
                            except Exception as e:
                                print("There is no pmu!")
                            try:
                                index_substation_rtu = devices_list.index("substation_rtu")
                                if index_substation_rtu >= 0:
                                    writer.writerow(["substation_rtu_"+street_list[i], cve_list[index_substation_rtu],
                                                     self.find_cve_values(cve_list[index_substation_rtu])[0],
                                                     self.find_cve_values(cve_list[index_substation_rtu])[1],
                                                     self.find_cve_values(cve_list[index_substation_rtu])[2]])
                                entry_target.append("substation_rtu_"+street_list[i])
                            except Exception as e:
                                print("There is no rtu!")
                            try:
                                index_plc = devices_list.index("plc")
                                if index_plc >= 0:
                                    writer.writerow(["plc_" + street_list[i], cve_list[index_plc],
                                                     self.find_cve_values(cve_list[index_plc])[0],
                                                     self.find_cve_values(cve_list[index_plc])[1],
                                                     self.find_cve_values(cve_list[index_plc])[2]])
                                entry_target.append("plc_" + street_list[i])
                            except Exception as e:
                                print("There is no plc!")
                            try:
                                index_concentrator = devices_list.index("concentrator")
                                if index_concentrator >= 0:
                                    writer.writerow(["concentrator_"+street_list[i], cve_list[index_concentrator],
                                                     self.find_cve_values(cve_list[index_concentrator])[0],
                                                     self.find_cve_values(cve_list[index_concentrator])[1],
                                                     self.find_cve_values(cve_list[index_concentrator])[2]])
                                entry_target.append("concentrator_"+street_list[i])
                            except Exception as e:
                                print("There is no Street Device!")
                        for k in range(len(devices_list)):
                            if devices_list[k] not in ["concentrator", "central_concentrator",
                                                        "local_terminal", "pmu", "substation_rtu",
                                                        "plc",
                                                       "fep", "application_server",
                                                       "active_directory_server", "historian_server",
                                                        "communication_server", "hmi",
                                                        "work_station", "iccp_server",
                                                        "ems_drp_server"
                                                       ] :
                                writer.writerow([devices_list[k]+"_"+street_list[i]+"_"+str(j), cve_list[k], self.find_cve_values(cve_list[k])[0], self.find_cve_values(cve_list[k])[1], self.find_cve_values(cve_list[k])[2]])
                                entry_target.append(devices_list[k]+"_"+street_list[i]+"_"+str(j))
        else:
            with open(source_file_name, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Device", "CVE", "CVSS Base Score 2.0", "Impact Subcore", "Exploitability Subscore"])
                try:
                    index_central_concentrator = devices_list.index("central_concentrator")
                    if index_central_concentrator >= 0:
                        term = self.getRandomCVEVals("CENTRAL CONCENTRATOR")
                        writer.writerow(["central_concentrator", term,
                                         self.find_cve_values(term)[0],
                                         self.find_cve_values(term)[1],
                                         self.find_cve_values(term)[2]])
                except Exception as e:
                    print("There is no Central Concentrator!")

                try:
                    index_fep = devices_list.index("fep")
                    if index_fep >= 0:
                        term = self.getRandomCVEVals("fep".upper().replace("_", " "))
                        writer.writerow(["fep", term,
                                         self.find_cve_values(term)[0],
                                         self.find_cve_values(term)[1],
                                         self.find_cve_values(term)[2]])
                except Exception as e:
                    print("There is no FEP")

                try:
                    index_application_server = devices_list.index("application_server")
                    if index_application_server >= 0:
                        term = self.getRandomCVEVals("application_server".upper().replace("_", " "))
                        writer.writerow(["application_server", term,
                                         self.find_cve_values(term)[0],
                                         self.find_cve_values(term)[1],
                                         self.find_cve_values(term)[2]])
                except Exception as e:
                    print("There is no APPLICATION SERVER")

                try:
                    index_active_directory_server = devices_list.index("active_directory_server")
                    if index_active_directory_server >= 0:
                        term = self.getRandomCVEVals("active_directory_server".upper().replace("_", " "))
                        writer.writerow(["active_directory_server", term,
                                         self.find_cve_values(term)[0],
                                         self.find_cve_values(term)[1],
                                         self.find_cve_values(term)[2]])
                except Exception as e:
                    print("There is no active_directory_server")

                try:
                    index_historian_server = devices_list.index("historian_server")
                    if index_historian_server >= 0:
                        term = self.getRandomCVEVals("historian_server".upper().replace("_", " "))
                        writer.writerow(["historian_server", term,
                                         self.find_cve_values(term)[0],
                                         self.find_cve_values(term)[1],
                                         self.find_cve_values(term)[2]])
                except Exception as e:
                    print("There is no historian_server")

                try:
                    index_communication_server = devices_list.index("communication_server")
                    if index_communication_server >= 0:
                        term = self.getRandomCVEVals("communication_server".upper().replace("_", " "))
                        writer.writerow(["communication_server", term,
                                         self.find_cve_values(term)[0],
                                         self.find_cve_values(term)[1],
                                         self.find_cve_values(term)[2]])
                except Exception as e:
                    print("There is no communication_server")

                try:
                    index_hmi = devices_list.index("hmi")
                    if index_hmi >= 0:
                        term = self.getRandomCVEVals("hmi".upper().replace("_", " "))
                        writer.writerow(["hmi", term,
                                         self.find_cve_values(term)[0],
                                         self.find_cve_values(term)[1],
                                         self.find_cve_values(term)[2]])
                except Exception as e:
                    print("There is no hmi")

                try:
                    index_work_station = devices_list.index("work_station")
                    if index_work_station >= 0:
                        term = self.getRandomCVEVals("work_station".upper().replace("_", " "))
                        writer.writerow(["work_station", term,
                                         self.find_cve_values(term)[0],
                                         self.find_cve_values(term)[1],
                                         self.find_cve_values(term)[2]])
                except Exception as e:
                    print("There is no work_station")
                try:
                    index_iccp_server = devices_list.index("iccp_server")
                    if index_iccp_server >= 0:
                        term = self.getRandomCVEVals("iccp_server".upper().replace("_", " "))
                        writer.writerow(["iccp_server", term,
                                         self.find_cve_values(term)[0],
                                         self.find_cve_values(term)[1],
                                         self.find_cve_values(term)[2]])
                except Exception as e:
                    print("There is no iccp_server")
                try:
                    index_ems_drp_server = devices_list.index("ems_drp_server")
                    if index_ems_drp_server >= 0:
                        term = self.getRandomCVEVals("ems_drp_server".upper().replace("_", " "))
                        writer.writerow(["ems_drp_server", term,
                                         self.find_cve_values(term)[0],
                                         self.find_cve_values(term)[1],
                                         self.find_cve_values(term)[2]])
                except Exception as e:
                    print("There is no ems_drp_server")

                for i in range(len(street_list)):
                    for j in range(len(house_list)):
                        if j == 0:
                            try:
                                index_local_terminal = devices_list.index("local_terminal")
                                if index_local_terminal >= 0:
                                    term = self.getRandomCVEVals("local_terminal".upper().replace("_", " "))
                                    writer.writerow(["local_terminal_" + street_list[i], term,
                                                     self.find_cve_values(term)[0],
                                                     self.find_cve_values(term)[1],
                                                     self.find_cve_values(term)[2]]
                                                    )
                                entry_target.append("local_terminal_" + street_list[i])
                            except Exception as e:
                                print("There is no local_terminal!")
                            try:
                                index_pmu = devices_list.index("pmu")
                                if index_pmu >= 0:
                                    term = self.getRandomCVEVals("pmu".upper().replace("_", " "))
                                    writer.writerow(["pmu_" + street_list[i], term,
                                                     self.find_cve_values(term)[0],
                                                     self.find_cve_values(term)[1],
                                                     self.find_cve_values(term)[2]]
                                                    )
                                entry_target.append("pmu_" + street_list[i])
                            except Exception as e:
                                print("There is no pmu!")
                            try:
                                index_substation_rtu = devices_list.index("substation_rtu")
                                if index_substation_rtu >= 0:
                                    term = self.getRandomCVEVals("substation_rtu".upper().replace("_", " "))
                                    writer.writerow(["substation_rtu_" + street_list[i], term,
                                                     self.find_cve_values(term)[0],
                                                     self.find_cve_values(term)[1],
                                                     self.find_cve_values(term)[2]]
                                                    )
                                entry_target.append("substation_rtu_"+street_list[i])
                            except Exception as e:
                                print("There is no rtu!")
                            try:
                                index_plc = devices_list.index("plc")
                                if index_plc >= 0:
                                    term = self.getRandomCVEVals("plc".upper().replace("_", " "))
                                    writer.writerow(["plc_" + street_list[i], term,
                                                     self.find_cve_values(term)[0],
                                                     self.find_cve_values(term)[1],
                                                     self.find_cve_values(term)[2]]
                                                    )
                                entry_target.append("plc_" + street_list[i])
                            except Exception as e:
                                print("There is no plc!")
                            try:
                                index_concentrator = devices_list.index("concentrator")
                                if index_concentrator >= 0:
                                    term = self.getRandomCVEVals("CONCENTRATOR")
                                    writer.writerow(["concentrator_" + street_list[i], term,
                                                     self.find_cve_values(term)[0],
                                                     self.find_cve_values(term)[1],
                                                     self.find_cve_values(term)[2]]
                                                     )
                                entry_target.append("concentrator_" + street_list[i])
                            except Exception as e:
                                print("There is no Concentrator!")
                        for k in range(len(devices_list)):
                            if devices_list[k] not in ["concentrator", "central_concentrator",
                                                        "local_terminal", "pmu", "substation_rtu",
                                                        "plc",
                                                       "fep", "application_server",
                                                       "active_directory_server", "historian_server",
                                                        "communication_server", "hmi",
                                                        "work_station", "iccp_server",
                                                        "ems_drp_server"
                                                       ] :
                                term = self.getRandomCVEVals(devices_list[k].upper().replace("_", " "))
                                writer.writerow([devices_list[k] + "_" + street_list[i] + "_" + str(j), term,
                                                 self.find_cve_values(term)[0],
                                                 self.find_cve_values(term)[1],
                                                 self.find_cve_values(term)[2]]
                                                )
                                entry_target.append(devices_list[k] + "_" + street_list[i] + "_" + str(j))


        self.text_file.set("File was generated\n"+str(os.getcwd())+"/"+source_file_name)
        self.updtcblist(entry_target, list(set(entry_target)-set(devices_list)))












        

    def show_powergrid_model(self):
    	path_1 = "GLM/"+combo_smartgrid_model.get().replace(" ", "_")+'.glm'
    	path_2 = "GLM/"+combo_smartgrid_model.get().replace(" ", "_") +'.dot'
    	os.system('python3 ' + path + 'glmMap.py ' + path_1 + ' ' + path_2)
    	#os.system('ruby glm2dot.rb ' + path_1 + ' ' + path_2+ " GridAttackAnalyer")
    	s = Source.from_file(path_2)
    	s.view()

    def on_edit_device_change(self, index):
        #combo_edit_cve['values'] = combo_to_edit_device.get()
        device_list = combo_to_edit_device.get().split("_")
        device_list = device_list[:len(device_list) - 2]
        device_list_to_find = []
        device_list_to_find.append((' '.join(map(str, device_list))).title())
        cve_list_to_find = []
        for key in range(len(distros_dict['object'][1]['devices_list'])):
            if (distros_dict['object'][1]['devices_list'][key]["device_name"]).upper() == device_list_to_find[0].upper():
                cve_list_to_find.extend(distros_dict['object'][1]['devices_list'][key]["CVE_list"])
                combo_edit_cve['values'] = cve_list_to_find
                combo_edit_cve.current(0)  # set the selected item
                break



    def plotmetrics(self):
        os.system('python3 ' + path + 'plotMetrics.py')

    def on_combo_connection_model_change(self, event):
        for i in range(number_device_list+1):
            if(globals()["devices_list" + str(i)].cget("text")=="Gateway"):
                #print(globals()["devices_list" + str(i)].cget("text"))
                if (combo_connection_model.get() == "Direct Connection"):
                    globals()["devices_list" + str(i)].configure(state='disabled')
                    globals()["CVE_list" + str(i)].configure(state='disabled')
                    globals()["btn_CVE" + str(i)].configure(state='disabled')
                else:
                    globals()["devices_list" + str(i)].configure(state='enable')
                    globals()["CVE_list" + str(i)].configure(state='enable')
                    globals()["btn_CVE" + str(i)].configure(state='enable')
                break


    def on_cve_vals_selection_change(self, event):
        if (combo_cve_vals_selection.get() == "Automatically"):
            for i in range(number_device_list+1):
                globals()["CVE_list" + str(i)].configure(state='disabled')
                globals()["btn_CVE" + str(i)].configure(state='disabled')
        else:
            for i in range(number_device_list+1):
                globals()["CVE_list" + str(i)].configure(state='enable')
                globals()["btn_CVE" + str(i)].configure(state='enable')





    def update_csv_file(self):
        filename = source_file_name
        tempfile = NamedTemporaryFile(mode='w', delete=False)
        cve = str(combo_edit_cve.get())
        devices = str(combo_to_edit_device.get())

        fields = ['Device', 'CVE', 'CVSS Base Score 2.0', 'Impact Subcore', 'Exploitability Subscore']
        with open(filename, 'r') as csvfile, tempfile:
            reader = csv.DictReader(csvfile, fieldnames=fields)
            writer = csv.DictWriter(tempfile, fieldnames=fields)
            for row in reader:
                if row['Device'] == devices:
                    print('updating row', row['Device'])
                    row['CVE'], row['CVSS Base Score 2.0'], row['Impact Subcore'], row['Exploitability Subscore'] = \
                        cve, str(self.find_cve_values(cve)[0]), str(self.find_cve_values(cve)[1]), str(self.find_cve_values(cve)[2])
                row = {'Device': row['Device'], 'CVE': row['CVE'], 'CVSS Base Score 2.0': row['CVSS Base Score 2.0'], 'Impact Subcore': row['Impact Subcore'], 'Exploitability Subscore': row['Exploitability Subscore']}
                writer.writerow(row)

        shutil.move(tempfile.name, filename)
        messagebox.showinfo("Information",
                            "New CVE has been updated!\n" +
                            "- Device: " + devices +
                            "\n- CVE: " + cve +
                            "\n\n- CVSS Base Score v2.0: " + str(self.find_cve_values(cve)[0]) +
                            "\n\n- Impact Subscore: " + str(self.find_cve_values(cve)[1]) +
                            "\n\n- Exploitability Subscore: " + str(self.find_cve_values(cve)[2])
                            )




    def create_widgets(self, root):

        lbl = Label(root, text="Smart Grid Attack Analysis System", font=("Times", 18), background="#D6E2F3", foreground="#000280")
        lbl.grid(row=0, columnspan=5)
        style = ttk.Style()
        style.configure("TButton", foreground="blue", background="orange", font="Times 14", width=18)





        i = 1
        lbl_powergrid_model = Label(root, text="   Smart Grid Model\n", background="#D6E2F3", foreground="#000280")
        # sticky="W" left align
        
        lbl_powergrid_model.grid(row = i, column=0, sticky="W")
        lbl_powergrid_model.config(width=18)

        powergrid =[]


        for key_1 in range(len(distros_dict['object'][0]['model_list'])):
            powergrid.append(distros_dict['object'][0]['model_list'][key_1]['list_name'])
        #for key_2 in distros_dict['object'][0]['model_list'][key_1]["streets_and_houses"][0]:
            #print(key_2)

        global combo_smartgrid_model 
        combo_smartgrid_model = Combobox(root, width=35)
        
        combo_smartgrid_model['values']= (powergrid)
        combo_smartgrid_model.current(0) #set the selected item
        combo_smartgrid_model.grid(row = i, column=1, columnspan=2, sticky="W")


        btn_show_smartgrid_model = Button(root, text='Show', command=self.show_powergrid_model,  style="TButton")
        btn_show_smartgrid_model.grid(row = i, column=3, columnspan=2, sticky="W")


        i = i+1 

        lbl_network_model = Label(root, text="   Smart Meter Connection\n", background="#D6E2F3", foreground="#000280")
        lbl_network_model.grid(row = i, column=0, sticky="W")
        lbl_network_model.config(width=23)


        global combo_connection_model
        combo_connection_model = Combobox(root, width=35)
        combo_connection_model.bind('<<ComboboxSelected>>', self.on_combo_connection_model_change)
        combo_connection_model['values']= ("Via a Gateway", "Direct Connection")
        combo_connection_model.current(0) #set the selected item
        combo_connection_model.grid(row = i, column=1, columnspan=2, sticky="W")
        i = i + 1

        lbl_cve_vals_selection = Label(root, text="   CVE Selection\n", background="#D6E2F3", foreground="#000280")
        lbl_cve_vals_selection.grid(row=i, column=0, sticky="W")
        lbl_cve_vals_selection.config(width=23)
        global combo_cve_vals_selection
        combo_cve_vals_selection = Combobox(root, width=35)
        combo_cve_vals_selection.bind('<<ComboboxSelected>>', self.on_cve_vals_selection_change)
        combo_cve_vals_selection['values'] = ("Manually", "Automatically")
        combo_cve_vals_selection.current(0)  # set the selected item
        combo_cve_vals_selection.grid(row=i, column=1, columnspan=2, sticky="W")


        i = i + 1



        #filename = filedialog.asksaveasfilename(initialdir="/", title="Select file", filetypes=(("jpeg files", "*.jpg"), ("all files", "*.*")))
        #filename.grid(row = i, column=1)

        i = i+1 

        lbl_devices = Label(root, text="   Devices and \n   Vulnerability\n", background="#D6E2F3", foreground="#000280")
        lbl_devices.grid(row = i, column=0, sticky="W", rowspan = len(distros_dict['object'][1]['devices_list']))
        lbl_devices.config(width=18)
        i = i+1

        devices_list = []
        global number_device_list
        global devices_and_cve_list
        devices_and_cve_list = dict()
        j = 0
        for key in range(len(distros_dict['object'][1]['devices_list'])):
            globals() ["devices_list"+str(key)] = Checkbutton(root, width=17, text=distros_dict['object'][1]['devices_list'][key]["device_name"], variable=distros_dict['object'][1]['devices_list'][key]["device_name"])
            
            devices_list.append(distros_dict['object'][1]['devices_list'][key]["device_name"])
            #globals() ["devices_list"+str(key)].config(width=18, font="Times")
            globals() ["CVE_list"+str(key)] = Combobox(root, width=15)
            globals() ["CVE_list"+str(key)] ['values'] = distros_dict['object'][1]['devices_list'][key]["CVE_list"]
            globals() ["CVE_list"+str(key)].current(0)

            devices_and_cve_list.update({str(distros_dict['object'][1]['devices_list'][key]["device_name"]).upper(): distros_dict['object'][1]['devices_list'][key]["CVE_list"]})
            globals() ["btn_CVE"+str(key)] = Button(root, text='Info', command = lambda key=key: self.OnButtonClick(key))
            if j%2 == 0:
                globals()["devices_list" + str(key)].grid(row=i, column=1, sticky="W")
                globals()["CVE_list" + str(key)].grid(row=i, column=2, sticky="W")
                globals() ["btn_CVE"+str(key)].grid(row = i, column = 3, sticky="W")
            else:
                globals()["devices_list" + str(key)].grid(row=i, column=4, sticky="W")
                globals()["CVE_list" + str(key)].grid(row=i, column=5, sticky="W")
                globals()["btn_CVE" + str(key)].grid(row=i, column=6, sticky="W")
                i = i + 1
            j = j + 1



            number_device_list = key

        i = i+2
        lbl_entry = Label(root, text="  \n \n ", background="#D6E2F3", foreground="#000280")        
        lbl_entry.grid(row = i, column=0, sticky="W", rowspan = len(distros_dict['object'][1]['devices_list']))
        lbl_entry.config(width=15)

        i = i+1
        global valores
        valores = StringVar()
        valores.set("")

        i = i+3
        btn_generate_file = Button(root, text='Generate File', command=lambda: self.generate_file())
        btn_generate_file.grid(row=i, column=0)
        i = i + 1
        lbl_generate_file = Label(root, textvariable=self.text_file, background="#D6E2F3", foreground="#000280")
        lbl_generate_file.grid(row=i, column=0, sticky="W", columnspan=4)
        lbl_generate_file.config()
        i = i + 1

        btn_open_file_to_edit = Button(root, text='1 - Manual Edit', command=lambda: self.open_csv_file())
        btn_open_file_to_edit.grid(row=i, column=0)
        i = i+1
        lbl_edit_device = Label(root, text="2 - Edit a Device & CVE", background="#D6E2F3", foreground="#000280")
        lbl_edit_device.grid(row=i, column=0, sticky="W")
        lbl_edit_device.config(width=21)
        global combo_to_edit_device
        #string_edit_device = StringVar()
        #string_edit_device.trace('w', self.on_edit_device_change)

        combo_to_edit_device = Combobox(root, width=35)
        combo_to_edit_device['values'] = [""]
        combo_to_edit_device.bind('<<ComboboxSelected>>', self.on_edit_device_change)
        combo_to_edit_device.current(0)  # set the selected item
        combo_to_edit_device.grid(row=i, column=1, columnspan=2, sticky="W")



        global combo_edit_cve
        combo_edit_cve = Combobox(root, width=35)
        combo_edit_cve['values'] = [""]
        combo_edit_cve.current(0)  # set the selected item
        combo_edit_cve.grid(row=i, column=3, columnspan=2, sticky="W")

        btn_update_cve = Button(root, text='Update', command=self.update_csv_file)
        btn_update_cve.grid(row=i, column=5)




        i = i + 1

        lbl_entry = Label(root, text="  ", background="#D6E2F3", foreground="#000280")
        lbl_entry.grid(row=i, column=0, sticky="W")
        lbl_entry.config(width=15)
        i = i + 3




        lbl_entry = Label(root, text="   Entry Point", background="#D6E2F3", foreground="#000280")
        lbl_entry.grid(row=i, column=0, sticky="W")
        lbl_entry.config(width=15)


        global lstbox_target
        lstbox_target = Listbox(root, listvariable=valores, selectmode=MULTIPLE, width=35, height=5)
        lstbox_target.configure(exportselection=False)
        lstbox_target.grid(column=1, row=i, columnspan=2, sticky="W")

        scrollbar = Scrollbar(root, orient="vertical")

        scrollbar.config(command=lstbox_target.yview)
        scrollbar.grid(column=1, row=i, columnspan=2, sticky="E")
        lstbox_target.config(yscrollcommand=scrollbar.set)

        # combo_entry
        #combo_entry = Combobox(root, width=35)
        #combo_entry['values'] = [""]
        #combo_entry.current(0)  # set the selected item
        #combo_entry.grid(row=i, column=1)

        lbl_target = Label(root, text="   Target", background="#D6E2F3", foreground="#000280")
        lbl_target.grid(row=i, column=3, sticky="E")
        lbl_target.config(width=15)

        global combo_target

        combo_target = Combobox(root, width=35)
        combo_target['values'] = [""]
        combo_target.current(0)  # set the selected item
        combo_target.grid(row=i, column=4, columnspan = 2, sticky="W")
        i = i+1





        i = i + 1


        btn_tree_generate = Button(root, text='Run', command=self.generate_tree)
        btn_tree_generate.grid(row = i, column = 0)
        i = i+1

        label = Label(root, text="\n   Results \n",  background="#D6E2F3", foreground="#000280")
        label.grid(row = i, column = 0, sticky="W")
        i = i+1

        btn_attack_graph = Button(root, text='Attack Graph', command=self.open_attack_graph)
        btn_attack_graph.grid(row = i, column=0)



        btn_attack_paths = Button(root, text='Graph Source File', command=self.open_graph_source_file,  style="TButton")
        btn_attack_paths.grid(row = i, column=1)
        btn_security_metrics = Button(root, text='Security Metrics', command=lambda: self.open_security_csv_file())
        btn_security_metrics.grid(row = i, column=2)

        btn_security_metrics = Button(root, text='Plot Metrics', command=lambda: self.plotmetrics())
        btn_security_metrics.grid(row=i, column=3, columnspan=2)

        i = i+1
        lbl_entry = Label(root, text=" ", background="#D6E2F3", foreground="#000280")        
        lbl_entry.grid(row = i, column=0, sticky="W", rowspan = len(distros_dict['object'][1]['devices_list']))
        lbl_entry.config(width=15)
    
    



    

window = tk.Tk()
window.title("GridAttackAnalysis")
window.option_add( "*font", "Times 14" )
window.geometry()
window.config(bg="#D6E2F3")
app = MyApplication(window)
window.mainloop()