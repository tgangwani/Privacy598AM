#!/usr/bin/env python
# Used to generate figure 4a) in the paper. This script calculates the average
# time to compute the discrete log using Shank's algorithm.  

import random,time,csv
from curveParams import G,order
from utils import init_baby_giant,baby_giant
import numpy as np 
import matplotlib.pyplot as plt

'''
mu, sigma = 2000, 500
sk_list = np.random.normal(mu, sigma, 1000)
'''

start_time=''
end_time=''
output_list=[]

for b in range (1,32):
    print("B=",b)
    B=b
    number_of_users=1000
    init_baby_giant(B*number_of_users)
    times = []
    
    for i in range(0,10):
        user_values= []
        while len(user_values)<=number_of_users:
            user_values.append(random.randint(0,B))
        #user_values=random.sample(range(0, B),number_of_users )
        total_sum=sum(user_values)
        sum_point= total_sum*G
        #print ("starting for B = {} and Sum = {}".format(B,total_sum))
        #print ("running round number = {}".format(i))

        # timed baby-giant
        start_time= time.time()
        baby_giant(sum_point)
        end_time= time.time()

        times.append(end_time-start_time)
        
    output_list.append([B,sum(times)/len(times)])
            
#print(output_list)

def linepoints():
    # get slope from the first two points for extrapolation
    slope = 0.084824538230896 - 0.041491031646728516
    intercept = 0.041491031646728516 - slope
    points = []
    for x in range(1,32):
        points.append(slope*x + intercept)
    return points

#output_list = [[1, 0.041491031646728516], [2, 0.084824538230896], [3, 0.11868526935577392], [4, 0.10256454944610596], [5, 0.14660813808441162], [6, 0.19417026042938232], [7, 0.16503551006317138], [8, 0.23557641506195068], [9, 0.25430119037628174], [10, 0.21648142337799073], [11, 0.22107312679290772], [12, 0.2608185291290283], [13, 0.2734876871109009], [14, 0.3594123601913452], [15, 0.3561329126358032], [16, 0.4481762170791626], [17, 0.31493003368377687], [18, 0.3382137298583984], [19, 0.3742015838623047], [20, 0.4600819110870361], [21, 0.38501439094543455], [22, 0.4163729190826416], [23, 0.41228437423706055], [24, 0.4009517192840576], [25, 0.43203489780426024], [26, 0.35203335285186765], [27, 0.39530167579650877], [28, 0.3545094966888428], [29, 0.44112708568573], [30, 0.4584857702255249], [31, 0.41862528324127196]]


fig= plt.figure()
plt.plot(np.array(output_list)[:,0],np.array(output_list)[:,1], label =
        'Baby-step/Giant-step')
plt.plot(np.array(output_list)[:,0], linepoints(), label = 'Linear Extrapolation')
plt.xlabel('Maximum bound per user (B)', fontsize=16)
plt.ylabel('Time (seconds)', fontsize=16)
plt.legend(loc='upper left')
plt.show()

'''
resultFile = open("output.csv",'a')
wr = csv.writer(resultFile, dialect=',')
wr.writerows(time_lis)
'''
