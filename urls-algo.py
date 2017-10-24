# -*- coding: UTF-8 -*-
import sys
import argparse
import cPickle as pickle
import subprocess
import os
import numpy as np

features_file = 'result/feautres.csv' 

def createParser():
    parser = argparse.ArgumentParser()
    parser.add_argument ('-u','--urls', nargs='?')
 
    return parser

if __name__ == '__main__':
    parser = createParser()
    namespace = parser.parse_args()
    
    filename = namespace.urls

    # run scrapy
    subprocess.call(['scrapy crawl phish -a filename=%s' % filename], shell=True)
    
    # get data from scrapy output
    data_for_test = np.genfromtxt(features_file, delimiter=',', dtype=np.int32)
    os.remove(features_file)

    # load model
    filename = 'tree_model.bin'
    pickle.dump(model, open(filename, 'wb'))

    loaded_model = pickle.load(open(filename, 'rb'))

    print(loaded_model.predict(data_for_test))
