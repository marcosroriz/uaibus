#!/bin/env python
# import pudb
# pu.db

import click
import numpy as np
import pandas as pd
from sklearn.externals import joblib
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GridSearchCV
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler


@click.command()
@click.option("--outsidecsv", default="outside.csv",  help="Outside signals")
@click.option("--insidecsv",  default="inside.csv",   help="Inside signals")
@click.option("--testcsv",    default="test.out.csv", help="Test signals")
def main(outsidecsv, insidecsv, testcsv):
    # dropcolumns = ["date", "lat", "lng", "mac"]
    dropcolumns = ["date", "lat", "lng", "stopdist", "mac",
                   "totaltravdist", "totaltravtime", "totalfrequence"]

    outdf = pd.read_csv(outsidecsv)
    indf = pd.read_csv(insidecsv)
    testdf = pd.read_csv(testcsv)

    outdf.drop(dropcolumns, axis=1, inplace=True)
    indf.drop(dropcolumns, axis=1, inplace=True)
    testdf.drop(dropcolumns, axis=1, inplace=True)

    singledf = pd.concat([outdf, indf])
    X = singledf.drop('clazz', axis=1)
    y = singledf['clazz']

    scaler = StandardScaler()
    scaler.fit(X)
    Xtrain = scaler.transform(X)
    ytrain = y

    params_grid = [
        {
            'learning_rate': ["constant", "invscaling", "adaptive"],
            'hidden_layer_sizes': [(10, 10), (10, 5),
                                   (20, 10), (20, 5),
                                   (50, 10), (50, 25), (50, 30),
                                   (100, 50), (100, 25), (100, 10)
                                   ],
            'alpha': [0.1, 0.01, 0.001, 0.2, 0.02, 0.002, 0.5, 0.05, 0.005],
            # 'alpha': [0.1],
            'tol': [1e-10],
            'activation': ["logistic", "relu", "tanh"],
            # 'activation': ["relu"],
            'max_iter': [5000000]
        },
        # {
        #   'kernel': ['linear'],
        #   'C': [1, 10, 100, 1000, 10000],
        #   'class_weight': ['balanced', {1: 2}, {1: 3}, {1: 4}, {1: 5},
        #                                {1: 10}, {1: 20}, {1: 50}]
        # },
        # {
        #   'kernel': ['poly'],
        #   'degree': [2, 3, 4],
        #   'C': [1, 10, 100, 1000, 10000, 100000],
        #   'class_weight': ['balanced', {1: 2}, {1: 3}, {1: 4}, {1: 5},
        #                                {1: 10}, {1: 20}, {1: 50}]
        # }
    ]

    nn = GridSearchCV(MLPClassifier(), params_grid, n_jobs=8, verbose=True)
    nn.fit(Xtrain, ytrain)
    print("Best params:")
    print(nn.best_params_)

    print("\n-----------\nTrain Results:")
    ytrainpred = nn.predict(Xtrain)
    print(confusion_matrix(ytrain, ytrainpred))
    print(classification_report(ytrain, ytrainpred))

    y_true = pd.Series(ytrain.tolist())
    y_pred = pd.Series(ytrainpred.tolist())

    print(pd.crosstab(y_true, y_pred, rownames=['True'],
                      colnames=['Predicted'], margins=True))

    print("\n-----------\nTest Results:")
    # svclassifier = SVC(kernel='rbf', tol=1e-15, class_weight={1 : 100},
    #                    verbose=True, C=100000, max_iter=10000000)
    # svclassifier = linear_model.SGDClassifier(loss="hinge", tol=1e-5,
    # class_weight={1:5})
    # svclassifier.fit(Xtrain, ytrain)

    Xtest = testdf.drop('clazz', axis=1)
    Xtest = scaler.transform(Xtest)
    ytest = testdf['clazz']
    ypred = nn.predict(Xtest)

    print(confusion_matrix(ytest, ypred))
    print(classification_report(ytest, ypred))

    # Save Classifier and scaler
    joblib.dump(scaler, "scaler.pkl")
    joblib.dump(nn.best_estimator_, 'svmclassifier.pkl')


if __name__ == "__main__":
    main()
