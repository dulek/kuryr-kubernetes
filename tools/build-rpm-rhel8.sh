#!/bin/bash -x

source_path=_output/SOURCES

mkdir -p ${source_path}

env

# Getting version from last tag in git
version=`git describe --tags --abbrev=0`
version=${version#openshift-kuryr-} # remove prefix
release=${version#*-} # remove prefix
version=${version%-*} # remove date suffix

# NOTE(dulek): rpmbuild requires that inside the tar there will be a
#              ${service}-${version} directory, hence this --transform option.
#              We exclude .git as rpmbuild will do its own `git init`.
#              Excluding .tox is convenient for local builds.
tar -czvf ${source_path}/kuryr-kubernetes.tar.gz --exclude=.git --exclude=.tox --transform "flags=r;s|\.|kuryr-kubernetes-${version}|" .
cp kuryr.logrotate ${source_path}
cp kuryr-controller.service ${source_path}
cp openshift-kuryr.tmpfs ${source_path}
cp kuryr-cni.service ${source_path}

# NOTE(dulek): We use this to get python3-pbr package in here.
curl http://base-openstack-4-6.ocp.svc > /etc/yum.repos.d/base-openstack-4-6.repo

yum install -y python3-pbr python3-devel

rpmbuild -ba -D "_version $OS_RPM_VERSION" -D "_release $OS_RPM_RELEASE" -D "_topdir `pwd`/_output" openshift-kuryr-kubernetes-rhel8.spec
createrepo _output/RPMS/noarch
