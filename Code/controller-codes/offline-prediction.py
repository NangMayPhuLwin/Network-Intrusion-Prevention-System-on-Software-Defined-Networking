#run "python offline-prediction.py"
import timeit, time #timeit module is used to measure the execution time of python code
import pandas as pd #pandas stand for Python Data Analysis Library
import numpy as np
from sklearn.preprocessing import minmax_scale # inputs values are needed to normalize between 0 and 1
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.metrics import accuracy_score

# import train flow data
X_train = pd.read_csv('path of your training csv file')
y_train = X_train["class"]
del X_train["class"]
X_train.iloc[:] = minmax_scale(X_train.iloc[:])
# import test flow data
X_test = pd.read_csv('path of your testing csv file')

y_test = X_test["class"]
del X_test["class"]
pred = open('predict.txt', "a+")

def testing(i):
    # Training the model
    # timer start  #default_timer() function returns the waiting time along CPU time
    train = timeit.default_timer()
    mlp = MLPClassifier(hidden_layer_sizes=(i), activation="logistic", solver='sgd', beta_1=0.9, beta_2=0.9,
                        learning_rate="constant", learning_rate_init=0.1, momentum=0.9)
    flow = mlp.fit(X_train, y_train.values.ravel())
    print(mlp)
    print(mlp.coefs_)

    train = timeit.default_timer() - train
    print ("training time :", train)
    test = timeit.default_timer()
    predict = mlp.predict(X_test)
    test = timeit.default_timer() - test
    #pred.write(str(predict[:])
    print ("testing time :", )

    # Evaluation
    c = confusion_matrix(y_test, predict)
    print(c)
    a = accuracy_score(y_test, predict) * 100
    print("accuracy is " + str(a) + "%")
    TN = c[0][0]
    FP = c[0][1]
    FN = c[1][0]
    TP = c[1][1]
    DR = float(TP)/(TP + FN) *100	    	#detection rate
    FAR= float(FP)/(TP+FP) *100    		    #false alarm rate
    print(DR, FAR)
    pred.write("\n" + str(TN) + "," + str(FP) + "," + str(FN) + "," + str(TP) + "," + str(a) + ","
               + str(train) + "," + str(test)+ "," + str(DR)+ "," + str(FAR))

    print(classification_report(y_test, predict))

for i in range(3, 8):
        print("with hidden %s" % i)
        testing(i)
        time.sleep(5)
pred.close()

