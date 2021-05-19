#!/usr/bin/env python3

# Copyright (c) 2021, Keane Lucas, Mahmood Sharif, Michael K. Reiter, Lujo Bauer, and Saurabh Shintre
# This file is code used in Malware Makeover

import argparse
import os
import re
import subprocess

CPU_BASE_IMAGE="tensorflow/tensorflow:1.15.0"
GPU_BASE_IMAGE="tensorflow/tensorflow:1.15.0-gpu"
GPU_TAG_NAME = "binary-transform/malware-makeover-pydasm-gpu"
CPU_TAG_NAME = "binary-transform/malware-makeover-pydasm-cpu"
REQUIREMENTS = 'requirements.txt'

DOCKER_VERSION_WITH_NATIVE_GPU_SUPPORT = 19.03

def main(args):
    global GPU_BASE_IMAGE, CPU_BASE_IMAGE, GPU_TAG_NAME, CPU_TAG_NAME, REQUIREMENTS
    
    # build the Docker image
    if args.env == "cpu":
        tag_name = CPU_TAG_NAME
        build_args = ["--build-arg", "BASE_IMAGE={}".format(CPU_BASE_IMAGE), "--build-arg", "REQUIREMENTS={}".format(REQUIREMENTS)]
        gpu_args = []
        runtime_args = []
        env_vars = []

    elif args.env == "gpu":

        # check docker version to see if the --gpus param is supported
        version_output = subprocess.check_output(["docker", "--version"]).decode('utf-8')
        docker_version = float(re.match(r"Docker version (\d+\.\d+)", version_output).group(1))
        if docker_version < DOCKER_VERSION_WITH_NATIVE_GPU_SUPPORT:
            # note: running nvidia-smi inside the container will show you all GPUs,
            # but since CUDA_VISIBLE_DEVICES is set you will only use GPUs listed
            # in args.gpus
            gpu_args = []
            runtime_args = ["--runtime", "nvidia"]
            env_vars= ["--env", "CUDA_VISIBLE_DEVICES={}".format(args.gpus)]
        else:
            # Recent versions of Docker support '--gpus' and don't require
            # '--runtime nvidia' nor CUDA_VISIBLE_DEVICES to be set
            #
            # note: running nvidia-smi inside the container will show you
            # only the GPUs listed in args.gpus
            gpu_args = ["--gpus", '"device={}"'.format(args.gpus)]
            runtime_args = []
            env_vars= []
        
        tag_name = GPU_TAG_NAME
        build_args = ["--build-arg", "BASE_IMAGE={}".format(GPU_BASE_IMAGE), "--build-arg", "REQUIREMENTS={}".format(REQUIREMENTS)]

    subprocess.check_call(["docker", "build", "--tag", tag_name] +
                            build_args + ["."])

    src_dir = os.getcwd()

    volume_mappings = []
    volume_mappings.extend(["-v", "{}:{}".format(src_dir, "/binary-transform")])        

    # Run container as current user, not root. This way,
    # generated files will have the correct file permissions
    user_args = []
    try:
        user_args = ["-u", "{}:{}".format(os.getuid(), os.getgid())]
    except:
        print("WARNING: Could not get current user ID. Container will launch as root.")
        
    subprocess.call(["docker", "run", "--rm", "-it", "--name", "binary_transform"] +
                    user_args +
                    gpu_args +
                    volume_mappings +
                    runtime_args +
                    env_vars +
                    ["{}:latest".format(tag_name), "/bin/bash"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy script")
    parser.add_argument("--env",
                        help="Build environment [default: cpu]",
                        choices=["cpu", "gpu"],
                        default="cpu")
    parser.add_argument("--gpus",
                        choices=["0", "1", "2", "3", "0,1", "2,3", "0,1,2,3"],
                        help="Use 1 or more specific GPUs [default: 0]",
                        default="0")
    args = parser.parse_args()
    main(args)
