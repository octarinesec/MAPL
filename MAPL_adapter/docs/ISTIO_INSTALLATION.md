# Istio and Bookinfo Installation

The following instructions install Istio (release 1.0.0) and the bookinfo app on a cluster with an installation of kubernetes 1.10 or higher.  

### Define the following environment variables
Change according to your setup.  
Istio binaries: [https://github.com/istio/istio/releases/tag/1.0.0](https://github.com/istio/istio/releases/tag/1.0.0)
```bash
$ export ISTIOLOC=~/istio-1.0.0
$ export ISTIOCTL=~/istio-1.0.0/bin/istioctl
```
Istio sources: [https://github.com/istio/istio](https://github.com/istio/istio)
```bash
$ export ISTIOSRC=~/go/src/istio.io/istio
```
### Install Istio
See: https://istio.io/docs/setup/kubernetes/helm-install/

```bash
$ kubectl apply -f $ISTIOLOC/install/kubernetes/helm/helm-service-account.yaml
$ helm init --service-account tiller
$ helm install $ISTIOLOC/install/kubernetes/helm/istio --name istio --namespace istio-system
```

### Changing the mixer version
use the following in order to use the latest mixer version 
```bash
$ kubectl set image deployment/istio-policy mixer="gcr.io/istio-release/mixer:master-latest-daily" -n istio-system
```
### Install Bookinfo App
This will add several services to the default namespace.  
see: https://istio.io/docs/examples/bookinfo/
*  Without side-car injector
```bash
$ kubectl apply -f <($ISTIOCTL kube-inject -f $ISTIOLOC/samples/bookinfo/platform/kube/bookinfo.yaml)
```
* With side-car injector

see: https://istio.io/docs/examples/bookinfo/

### Define a Gateway
```bash
$ kubectl apply -f $ISTIOLOC/samples/bookinfo/networking/bookinfo-gateway.yaml
```

# Testing the installation

* __Check the ingress host and port:__  
see: https://istio.io/docs/tasks/traffic-management/ingress/

```bash
$ kubectl get svc istio-ingressgateway -n istio-system -o wide
```
with the output:
```
NAME                   TYPE           CLUSTER-IP      EXTERNAL-IP        PORT(S)
istio-ingressgateway   LoadBalancer   10.233.48.176   <HOST_NAME>        <PORT>:31380/TCP,443:31390/TCP,31400:31400/TCP
```

* __Open the app web page in a browser:__
```
http://<HOST_NAME>:<PORT>/productpage
```
where <HOST_NAME> is the cluster's external ip (make sure that the host accepts inbound HTTP traffic and that you did not forget the "productpage" path at the end of the URL).


* __Test the app:__   
  - Refresh the page a few times to view the effects of the different versions of the reviews service (different colors of the review-stars or no stars at all).
  - Sign in and out of the app (top-right of the web page).
  
# Install MAPL adapter
Install the MAPL_adapter in order to manage access-control policy rules written in MAPL.  
see: [MAPL Adapter Installation](https://github.com/octarinesec/MAPL/tree/master/MAPL_adapter/docs/ADAPTER_INSTALLATION.md). 