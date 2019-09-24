# MAPL Adapter Installation

## MAPL Adapter
To demonstrate the use of the MAPL Engine, we created a gRPC adapter for Istio's Mixer that uses the MAPL Engine for policy rules written in MAPL.

## Installation

We assume a cluster with Kuberentes, Istio and the bookinfo app are already installed.  
see [Istio Installation](https://github.com/octarinesec/MAPL/tree/master/MAPL_adapter/docs/ISTIO_INSTALLATION.md) document.

### Define the following environment variables
 change according to your setup:
```bash
$ export MIXERLOC=~/go/src/istio.io/istio/mixer
$ export DOCKER_USER=<DOCKER_USER>
```

Copy the folder MAPL_adapter to the istio mixer adapers folder
```bash
$ cp -r MAPL_adapter $MIXERLOC/adapter/
```

### Build the adapter

You can use Octarine's image in [MAPL_adapter_dep.yaml](https://github.com/octarinesec/MAPL/tree/master/MAPL_adapter/deployments/MAPL_adapter_dep.yaml) instead:
```
  - image: octarinesec/mapl_adapter:{mapl_adapter_version}
```
Or do the following in order to create your own docker image.  

##### Compile
```bash
$ cd $MIXERLOC/adapter/MAPL_adapter/
$ go generate ./...
$ cd $MIXERLOC/adapter/MAPL_adapter/adapter_main
$ go build ./...
$ mv $MIXERLOC/adapter/MAPL_adapter/adapter_main/adapter_main $MIXERLOC/adapter/MAPL_adapter/adapter_main/MAPL_adapter
```

##### Build the docker image
```bash
$ cd $MIXERLOC/adapter/MAPL_adapter/adapter_main
$ docker build . -t $DOCKER_USER/mapl_adapter:{ADAPTER_TAG}
```
##### Push to image repository
```bash
$ docker push $DOCKER_USER/mapl_adapter:{ADAPTER_TAG}
```
Edit [MAPL_adapter_dep.yaml](https://github.com/octarinesec/MAPL/tree/master/MAPL_adapter/deployments/MAPL_adapter_dep.yaml) with the location of the adapter's docker image and imagePullSecrets.

##### Create image pull secret
```bash
$ kubectl create secret docker-registry docker-secret -n istio-system --docker-username="<username>" --docker-password="<password>" --docker-email="<docker_email>" --docker-server="https://index.docker.io/v1/"
```
Create the secret in the istio-system namespace.
Make sure [MAPL_adapter_dep.yaml](https://github.com/octarinesec/MAPL/tree/master/MAPL_adapter/deployments/MAPL_adapter_dep.yaml) has an imagePullSecrets section with docker-secret for the docker-registry field, and that the image can be pulled.

### Create configmap for the rules
the configmap contains the file rules.yaml (pay attention that the file name is rules.yaml, the same as in the Dockerfile)
```bash
$ kubectl create configmap mapl-adapter-rules-config-map -n istio-system --from-file $MIXERLOC/adapter/MAPL_adapter/rules/rules.yaml
```

### Update the environment variables 
Update file [MAPL_adapter_dep.yaml](https://github.com/octarinesec/MAPL/tree/master/MAPL_adapter/deployments/MAPL_adapter_dep.yaml) with the following variables
* LOGGING: "true" (output log to "log.txt") or "false"  
* CACHE_TIMEOUT_SECS: number of seconds the Check results are cached for. 
* ISTIO_TO_SERVICE_NAME_CONVENTION: The convention of translating from Istio's attributes to service name used in rules.
  * "IstioUid": Kuberentes pod ID
  * "IstioWorkloadAndNamespace": Concatenation of service workload and service workload namespace 

For example:
```yaml
env:
- name: ADAPTER_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: CACHE_TIMEOUT_SECS
  value: "3"
- name: ISTIO_TO_SERVICE_NAME_CONVENTION
  value: "IstioUid" 
-name: LOGGING
  value: "true"

```

### Deploy the gRPC adpater

```bash
$ kubectl apply -f $MIXERLOC/testdata/config/attributes.yaml
$ kubectl apply -f $MIXERLOC/template/authorization/template.yaml
$ kubectl apply -f $MIXERLOC/adapter/MAPL_adapter/config/mapl-adapter.yaml
$ kubectl apply -f $MIXERLOC/adapter/MAPL_adapter/MAPL_adapter_config.yaml
$ kubectl apply -f $MIXERLOC/adapter/MAPL_adapter/deployments/MAPL_adapter_dep.yaml
$ kubectl apply -f $MIXERLOC/adapter/MAPL_adapter/deployments/MAPL_adapter_svc.yaml
```


## Test 
Test the effect of the policy rules on the bookinfo app.  
Refresh the webpage a few times to view the effects on the different versions of the ratings service.
Also sign in and out of the app.

The current set of rules [rules.yaml](https://github.com/octarinesec/MAPL/tree/master/MAPL_adapter/rules/rules.yaml) have the following effect:

1) Allow ingress
2) Allow specific services communications
3) Block the communication of reviews-v2 and ratings-v1 (black stars ratings is not available)
4) Block the communication of productpage-v1 and details-v1 (the reviews are not available) every other minute
5) Allow login
6) Block logout (the webpage is not available after signing out)

## How to Apply New Rules

Edit the rules.yaml file or copy another file as rules.yaml.
```bash
$ cp $MIXERLOC/adapter/MAPL_adapter/rules/new_rules.yaml $MIXERLOC/adapter/MAPL_adapter/rules/rules.yaml
```
Update the config map
```bash
$ kubectl create configmap mapl-adapter-rules-config-map -n istio-system --from-file $MIXERLOC/adapter/MAPL_adapter/rules/rules.yaml --dry-run -o yaml | kubectl replace -f -
```
Pay attention that the configmap update may take up to a minute.

Delete the adapter pod. It will be automatically reloaded with the new set of rules:
```bash
$ kubectl delete pod -n istio-system $(kubectl get pods -n istio-system | grep mapl-adapter-dep | awk -F" " '{print $1}')
```

It might be necessary to restart also the mixer:
```bash
$ kubectl delete pod -n istio-system $(kubectl get pods -n istio-system | grep istio-policy | awk -F" " '{print $1}')
```

## Debug
* To view the mixer logs:
```bash
$ kubectl logs -n istio-system $(kubectl get pods -n istio-system | grep istio-policy | awk -F" " '{print $1}') mixer
```
If everything is ok then one of the output lines should be:
```bash
<TIMESTAMP>     info    grpcAdapter     Connected to: mapl-adapter-dep.istio-system:7782
```
* To view the adapter logs:
```bash
kubectl logs -n istio-system $(kubectl get pods -n istio-system | grep mapl-adapter-dep | awk -F" " '{print $1}')
```

* To get a bash command line in the mapl-adapter pod:
```
$ kubectl exec -n istio-system -ti $(kubectl get pods -n istio-system | grep mapl-adapter-dep | awk -F" " '{print $1}') /bin/bash
```

* To view the effect of the new rules in the command-line   

Login to the reviews-v1 pod. For example:
```bash
$  kubectl exec reviews-v1-7cffb56b4d-ghpns  -i -t -- bash -il
```
Connect to the ratings service via HTTP: 
```bash
# wget -O temp.txt http://ratings:9080/ratings/0
# cat temp.txt
    {"id":0,"ratings":{"Reviewer1":5,"Reviewer2":4}}
# exit
``` 
Now, login to the reviews-v2 pod. For example:
```bash
$  kubectl exec reviews-v2-869dcbf5c4-z7xhk  -i -t -- bash -il
``` 
But we cannot connect to the ratings services from the reviews-v2 pod as there is a rule that prevents it. 
```bash
# wget -O temp.txt http://ratings:9080/ratings/0
    HTTP request sent, awaiting response... 401 Unauthorized
    Username/Password Authentication Failed. 
```