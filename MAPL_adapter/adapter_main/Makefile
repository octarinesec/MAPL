NAME   := octarinesec/mapl_adapter
TAG    := $$(git --git-dir /c/myCode/go/src/github.com/octarinesec/MAPL/.git log -1 --pretty=%h)
IMG    := ${NAME}:${TAG}
LATEST := ${NAME}:latest
 
build:
	@docker build -t ${IMG} ./...
	@docker tag ${IMG} ${LATEST}
 
push:
	#@docker push ${NAME}
	docker push ${NAME}:${TAG}
	docker push ${LATEST}

 
login:
	@docker log -u ${DOCKER_USER} -p ${DOCKER_PASS}