#!/bin/bash
cd /
git clone https://github.com/spiffe/spire.git
cd /spire
make build
echo 'export PATH="/spire/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc 
