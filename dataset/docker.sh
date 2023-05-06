#!/bin/bash
docker load -i ./docker.tar.gz
docker run -it  --cap-add sys_ptrace --privileged cryptompk:revision /bin/bash
