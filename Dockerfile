ARG BASE_IMAGE
FROM $BASE_IMAGE

# if needed, can install Ubuntu packages here, e.g.:
RUN apt-get update
RUN apt-get update --fix-missing
RUN apt-get install -y git zip vim gawk

RUN mkdir /binary-transform
WORKDIR /binary-transform

# install any needed python packages not already provided by the
# base docker image
ARG REQUIREMENTS
ADD $REQUIREMENTS /binary-transform/
RUN pip install --upgrade pip
RUN pip install -r $REQUIREMENTS
ADD enhanced-binary-randomization /binary-transform/enhanced-binary-randomization
WORKDIR /binary-transform/enhanced-binary-randomization/libdasm-1.5_orp/pydasm
RUN python setup.py install

#return to home directory
WORKDIR /binary-transform
