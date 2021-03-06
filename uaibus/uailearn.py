#!/bin/env python
# import pudb
# pu.db

import click
import pandas as pd
import numpy as np
from sklearn.svm import SVC
from sklearn.externals import joblib
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler


@click.command()
@click.option("--outsidecsv", default="outside.csv",  help="Outside signals")
@click.option("--insidecsv",  default="inside.csv",   help="Inside signals")
@click.option("--testcsv",    default="test.out.csv", help="Test signals")
def main(outsidecsv, insidecsv, testcsv):
    dropcolumns = ["date", "lat", "lng", "stopdist", "mac",
                   "totaltravdist", "totaltravtime", "totalfrequence"]
    # dropcolumns = ["date", "lat", "lng", "mac"]
    outdf = pd.read_csv(outsidecsv)
    indf = pd.read_csv(insidecsv)
    testdf = pd.read_csv(testcsv)

    outdf.drop(dropcolumns, axis=1, inplace=True)
    indf.drop(dropcolumns, axis=1, inplace=True)
    testdf.drop(dropcolumns, axis=1, inplace=True)

    singledf = pd.concat([outdf, indf])
    X = singledf.drop('clazz', axis=1)

    # X['distsq'] = X['travdist'] ** 2
    # X['distth'] = X['travdist'] ** 3
    # X['rssisq'] = X['rssi'] ** 2
    # X['rssith'] = X['rssi'] ** 3
    y = singledf['clazz']

    scaler = StandardScaler()
    scaler.fit(X)
    Xtrain = scaler.transform(X)
    ytrain = y

    params_grid = [
        {
          'kernel': ['rbf'],
          'gamma': [1e-2, 1e-3, 1e-4, 1e-5, 1e-6],
          'C': [10, 100, 1000, 10000],
          'class_weight': ['balanced', {1: 2}, {1: 5}, {1: 10}, {1: 50}]
        },
        # {
        #   'kernel': ['linear'],
        #   'C': [1, 10, 100, 1000, 10000],
        #   'class_weight': ['balanced', {1: 2}, {1: 3}, {1: 4}, {1: 5},
        #                    {1: 10}, {1: 20}, {1: 50}]
        # },
        # {
        #   'kernel': ['poly'],
        #   'degree': [2, 3, 4],
        #   'C': [1, 10, 100, 1000, 10000, 100000],
        #   'class_weight': ['balanced', {1: 2}, {1: 3}, {1: 4}, {1: 5},
        #                                {1: 10}, {1: 20}, {1: 50}]
        # }
    ]

    svclassifier = GridSearchCV(SVC(), params_grid, n_jobs=8, verbose=True)
    svclassifier.fit(Xtrain, ytrain)
    print("Best params:")
    print(svclassifier.best_params_)

    print("\n-----------\nTrain Results:")
    ytrainpred = svclassifier.predict(Xtrain)
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

    # Xtest['distsq'] = Xtest['travdist'] ** 2
    # Xtest['distth'] = Xtest['travdist'] ** 3
    # Xtest['rssisq'] = Xtest['rssi'] ** 2
    # Xtest['rssith'] = Xtest['rssi'] ** 3

    Xtest = scaler.transform(Xtest)
    ytest = testdf['clazz']
    ypred = svclassifier.predict(Xtest)

    print(confusion_matrix(ytest, ypred))
    print(classification_report(ytest, ypred))

    # Save Classifier and scaler
    joblib.dump(scaler, "scaler.pkl")
    joblib.dump(svclassifier.best_estimator_, 'svmclassifier.pkl')


if __name__ == "__main__":
    main()
