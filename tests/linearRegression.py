#!/usr/bin/env python
# Used to generate figure 4b) in the paper. This script calculates the increase
# in mean square error when moving from training on floating-point values to
# training on integer values (using floor/ceil on FP)

import sys
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from math import floor, ceil

powerout = []
temperatures = []
beta = []
# use floor/ceil in parse2() function to generate beta_floor and beta_ceil
beta_floor = [-2.1670109895773635, 495.38635720022921]
beta_ceil = [-2.1666992422241833, 498.51607395474775]

def parse2():
    global temperatures, powerout
    df = pd.read_csv('thermal.csv', header=0)

    # use floor/ceil here to convert data to integer
    temperatures = [float(x) for x in df['AT'][1:]]
    powerout = [float(x) for x in df['PE'][1:]]

def parse():
    with open('lpga2008.dat') as fd:
        for line in fd.readlines():
            data = str(line).split()
            try:
                driveDistance.append(float(data[2]))
            except:
                driveDistance.append(float(data[3]))
            winnings.append(float(data[-3]))

def plot():
    x = temperatures
    y = powerout
    fig, ax = plt.subplots()
    ax.scatter(x, y, color='lightblue')
    pred = [beta[0]*_x + beta[1] for _x in x]
    pred_floor = [beta_floor[0]*_x + beta_floor[1] for _x in x]
    pred_ceil = [beta_ceil[0]*_x + beta_ceil[1] for _x in x]
    plt.plot(x, pred_ceil, label='LR integer ceil', color='tomato')
    plt.plot(x, pred, label='LR floating point')
    plt.plot(x, pred_floor, label='LR integer floor', color='purple')
    plt.legend()
    plt.xlabel("Ambient Temperature ($^\circ$ Celsius)")
    plt.ylabel("Powerplant Energy Output (MW)")
    plt.show()

def trainLR():
    """
    Training a univariate linear regression model. Beta = (x'x)^{-1} . (x'y)
    """
    global beta
    _temperatures = [[x, 1] for x in temperatures] # add 1 to the data array. Absorbing \theta (intercept) in \beta
    np_temperatures = np.array(_temperatures)
    np_powerout = np.array(powerout)

    fc = np.linalg.inv(np.dot(np.transpose(np_temperatures),
        np_temperatures)) 
    sc = np.dot(np.transpose(np_temperatures), np_powerout)
    beta = list(np.dot(fc, sc))
    
def calErr():
    """
    Mean square error
    """
    mse = (1.0/len(temperatures))* sum([(beta[0]*_x + beta[1] - y)**2 for (_x, y) in
            zip(temperatures, powerout)])
    mse_floor = (1.0/len(temperatures))* sum([(beta_floor[0]*_x + beta_floor[1] - y)**2 for (_x, y) in
            zip(temperatures, powerout)])
    mse_ceil = (1.0/len(temperatures))* sum([(beta_ceil[0]*_x + beta_ceil[1] - y)**2 for (_x, y) in
            zip(temperatures, powerout)])

    print('MSE:', mse)
    print('MSE_floor:', mse_floor)
    print('MSE_ceil:', mse_ceil)

#parse()
parse2()
trainLR()
calErr()
plot()
