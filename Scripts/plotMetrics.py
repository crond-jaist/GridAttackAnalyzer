import tkinter as tk
from tkinter.ttk import *
from tkinter import ttk
from pandas import DataFrame
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import os
import sys
import matplotlib
import numpy as np
import pandas as pd
from matplotlib import interactive
import matplotlib.ticker as plticker
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib import cm
from matplotlib.colors import ListedColormap
import random
root= tk.Tk()
root.title("Security Metrics I")
lbl = Label(root, text="Security Metrics I", font=("Times", 18), foreground="#000280")
lbl.pack()

windows_paths = tk.Tk()
windows_paths.title("Security Metrics II")
lbl = Label(windows_paths, text="Security Metrics II", font=("Times", 18), foreground="#000280")
lbl.pack()

windows_average = tk.Tk()
windows_average.title("Security Metrics III")
lbl = Label(windows_average, text="Security Metrics III", font=("Times", 18), foreground="#000280")
lbl.pack()



def add_value_labels(ax, spacing=0):
    """Add labels to the end of each bar in a bar chart.

    Arguments:
        ax (matplotlib.axes.Axes): The matplotlib object containing the axes
            of the plot to annotate.
        spacing (int): The distance between the labels and the bars.
    """

    # For each bar: Place a label
    for rect in ax.patches:
        # Get X and Y placement of label from rect.
        y_value = rect.get_height()
        x_value = rect.get_x() + rect.get_width() / 2

        # Number of points between bar and label. Change to your liking.
        space = spacing
        # Vertical alignment for positive values
        va = 'bottom'

        # If value of bar is negative: Place label below bar
        if y_value < 0:
            # Invert space to place label below
            space *= -1
            # Vertically align label at top
            va = 'center'

        # Use Y value as label and format number with one decimal place
        label = "{:.2f}".format(y_value)


        # Create annotation
        ax.annotate(
            label,                      # Use `label` as label
            (x_value, y_value),         # Place label at end of the bar
            xytext=(3, space),          # Vertically shift label by `space`
            textcoords="offset points", # Interpret `xytext` as offset in points
            ha='center',                # Horizontally center label
            va=va)                      # Vertically align label differently for
                                        # positive and negative values.


def plotMetrics(file):
    my_colormap = ['tab:blue', 'tab:orange', 'tab:green', 'tab:red', 'tab:purple', 'tab:brown', 'tab:pink', 'tab:gray', 'tab:olive', 'tab:cyan', 'b', 'g', 'r', 'c', 'm', 'y', 'k']  # red, green, blue, black, etc.

    # Plot Attack Cost, Attack Impact, Attack Risk
    figure = plt.Figure(figsize=(5, 6), dpi=100)
    ax1 = figure.add_subplot(221)
    bar1 = FigureCanvasTkAgg(figure, root)
    bar1.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    figure.subplots_adjust(hspace=0.4, wspace=0.4)
    ax2 = figure.add_subplot(222)
    ax3 = figure.add_subplot(223)
    ax4 = figure.add_subplot(224)

    # Plot Paths
    figure_paths = plt.Figure(figsize=(5, 6), dpi=100)
    ax5 = figure_paths.add_subplot(231)
    bar_paths = FigureCanvasTkAgg(figure_paths, windows_paths)
    bar_paths.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    figure_paths.subplots_adjust(hspace=0.4, wspace=0.4)
    ax6 = figure_paths.add_subplot(232)
    ax7 = figure_paths.add_subplot(233)
    ax8 = figure_paths.add_subplot(234)
    ax9 = figure_paths.add_subplot(235)
    ax10 = figure_paths.add_subplot(236)

    # Plot average

    figure_average = plt.Figure(figsize=(5, 6), dpi=100)
    bar_average = FigureCanvasTkAgg(figure_average, windows_average)
    bar_average.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    figure_average.subplots_adjust(hspace=0.4, wspace=0.4)
    ax11 = figure_average.add_subplot(121)
    ax12 = figure_average.add_subplot(122)





    for i in range(1, len(file) - 1):
        data_loading = pd.read_csv(file, delimiter=',',skiprows=1,
                                   names=["time",
                                          "case_study_name",
                                          "streets_and_houses_vector",
                                          "attack_success_probability",
                                          "attack_cost",
                                          "attack_impact",
                                          "attack_risk",
                                          "number_of_devices",
                                          "average_attack_cost",
                                          "average_attack_impact",
                                          "number_of_paths",
                                          "rare_paths",
                                          "unlilkely_paths",
                                          "possible_paths",
                                          "likely_paths",
                                          "almost_certain_paths"
                                          ])
        data_loading.head(5)
        # print(data_loading)
    ax1.bar("case_study_name", 'attack_success_probability', data=data_loading, color=my_colormap)
    ax1.set_title('Attack Success Probability')
    add_value_labels(ax1)
    plt.setp(ax1.get_xticklabels(), rotation=15, horizontalalignment='right')
    ax1.set_xlabel('Case Study')
    ax1.set_ylabel('Attack Success Probability')
    #Enable to save figure
    #figure.savefig('Attack_Success_Probability.png')


    ax2.bar("case_study_name", 'attack_cost', data=data_loading, color=my_colormap)
    ax2.set_title('Attack Cost')
    add_value_labels(ax2)
    plt.setp(ax2.get_xticklabels(), rotation=15, horizontalalignment='right')
    ax2.set_xlabel('Case Study')
    ax2.set_ylabel('Attack Cost')
    #Enable to save figure
    #figure.savefig('Attack_Cost.png')

    ax3.bar("case_study_name", 'attack_impact', data=data_loading, color=my_colormap)
    ax3.set_title('Attack Impact')
    plt.setp(ax3.get_xticklabels(), rotation=15, horizontalalignment='right')
    ax3.set_xlabel('Case Study')
    ax3.set_ylabel('Attack Impact')
    add_value_labels(ax3)
    #Enable to save figure
    #figure.savefig('Attack_Impact.png')

    ax4.bar("case_study_name", 'attack_risk', data=data_loading, color=my_colormap)
    ax4.set_title('Attack Risk')
    plt.setp(ax4.get_xticklabels(), rotation=15, horizontalalignment='right')
    ax4.set_xlabel('Case Study')
    ax4.set_ylabel('Attack_Risk')
    add_value_labels(ax4)
    #Enable to save figure
    #figure.savefig('Attack_Risk.png')


    # Number of Paths
    ax5.bar("case_study_name", 'number_of_paths', data=data_loading, color=my_colormap)
    ax5.set_title('Number of Paths')
    plt.setp(ax5.get_xticklabels(), rotation=15, horizontalalignment='right')
    ax5.set_xlabel('Case Study')
    ax5.set_ylabel('Number of Paths')
    add_value_labels(ax5)
    #Enable to save figure
    #figure_paths.savefig('Number_of_Paths.png')
    # Rare Paths
    ax6.bar("case_study_name", 'rare_paths', data=data_loading, color=my_colormap)
    ax6.set_title('Rare Paths')
    plt.setp(ax6.get_xticklabels(), rotation=15, horizontalalignment='right')
    ax6.set_xlabel('Case Study')
    ax6.set_ylabel('Rare Paths')
    add_value_labels(ax6)
    #Enable to save figure
    #figure_paths.savefig('Rare_Paths.png')

    # unlilkely_paths
    ax7.bar("case_study_name", 'unlilkely_paths', data=data_loading, color=my_colormap)
    ax7.set_title('Unlilkely Paths')
    plt.setp(ax7.get_xticklabels(), rotation=15, horizontalalignment='right')
    ax7.set_xlabel('Case Study')
    ax7.set_ylabel('Unlilkely Paths')
    add_value_labels(ax7)
    #Enable to save figure
    #figure_paths.savefig('Unlilkely_Paths.png')

    # possible_paths
    ax8.bar("case_study_name", 'possible_paths', data=data_loading, color=my_colormap)
    ax8.set_title('Possible Paths')
    plt.setp(ax8.get_xticklabels(), rotation=15, horizontalalignment='right')
    ax8.set_xlabel('Case Study')
    ax8.set_ylabel('Possible Paths')
    add_value_labels(ax8)
    #Enable to save figure
    #figure_paths.savefig('Possible_Paths.png')

    # likely_paths
    ax9.bar("case_study_name", 'likely_paths', data=data_loading, color=my_colormap)
    ax9.set_title('Likely Paths')
    plt.setp(ax9.get_xticklabels(), rotation=15, horizontalalignment='right')
    ax9.set_xlabel('Case Study')
    ax9.set_ylabel('Likely Paths')
    add_value_labels(ax9)
    #Enable to save figure
    #figure_paths.savefig('Likely_Paths.png')

    # likely_paths
    ax10.bar("case_study_name", 'almost_certain_paths', data=data_loading, color=my_colormap)
    ax10.set_title('Almost Certain Paths')
    plt.setp(ax10.get_xticklabels(), rotation=15, horizontalalignment='right')
    ax10.set_xlabel('Case Study')
    ax10.set_ylabel('Almost Certain Paths')
    add_value_labels(ax10)
    #Enable to save figure
    #figure_paths.savefig('Almost_Certain_Paths.png')


    # Average Attack Cost

    ax11.bar("case_study_name", 'average_attack_cost', data=data_loading, color=my_colormap)
    ax11.set_title('Average Attack Cost')
    plt.setp(ax11.get_xticklabels(), rotation=15, horizontalalignment='right')
    ax11.set_xlabel('Case Study')
    ax11.set_ylabel('Average Attack Cost')
    add_value_labels(ax11)
    #Enable to save figure
    #figure_average.savefig('Average_Attack_Cost.png')

    # average_attack_impact

    ax12.bar("case_study_name", 'average_attack_impact', data=data_loading, color=my_colormap)
    ax12.set_title('Average Attack Impact')
    plt.setp(ax12.get_xticklabels(), rotation=15, horizontalalignment='right')
    ax12.set_xlabel('Case Study')
    ax12.set_ylabel('Average Attack Impact')
    add_value_labels(ax12)
    #Enable to save figure
    #figure_average.savefig('Average_Attack_Impact.png')



if __name__ == '__main__':
    plotMetrics("Results/Results.csv")
    root.mainloop()
    windows_paths.mainloop()
    windows_average.mainloop()
