import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import MinMaxScaler
import seaborn as sns
import matplotlib.pyplot as plt
#matplotlib inline

train_url = 'monitor-ddos-port-stats-attack-train.csv'
test_url = 'monitor-ddos-port-stats-attack-test.csv'

train = pd.read_csv(train_url, sep=';')
test = pd.read_csv(test_url, sep=';')

print("***** Train_Set *****")
print(train.head())
print("\n")
print("***** Test_Set *****")
print(test.head())

#datapath, port, rx-pkts, rx-bytes, tx-pkts, tx-bytes

train = train.drop(['duration-sec', 'duration-nsec', 'rx-error', 'tx-error'], axis=1)
test = test.drop(['duration-sec', 'duration-nsec', 'rx-error', 'tx-error'], axis=1)

train.info()
X = np.array(train).astype(int)
kmeans = KMeans(algorithm='auto', copy_x=True, init='k-means++', max_iter=300,
    n_clusters=2, n_init=10, n_jobs=1, precompute_distances='auto',
    random_state=None, tol=0.0001, verbose=0) # Attack or not attack
kmeans.fit(X)

plt.scatter(X[:, 0], X[:, 1], s=100, c=kmeans.labels_)
plt.scatter(kmeans.cluster_centers_[:, 0], kmeans.cluster_centers_[:, 1], s=300, c='red', label='Centroids')
plt.title('Clusters and Centroids')
plt.xlabel('SepalLength')
plt.ylabel('SepalWidth')
plt.legend()

plt.show()

