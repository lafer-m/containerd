CTL=dacsctl

export host?=amd64
export baseImage=?centos:centos7.9.2009
rc=${host}rc

version=v0.0.1

include ${rc}

IMAGE_FLAGS:=--build-arg baseImage=${baseImage}

image:
	$(CTL) build ${IMAGE_FLAGS} -f Dockerfile -t baseruntime:${version} .











